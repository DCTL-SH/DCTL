//! macFUSE's setuid mount helper: how it is called, and how its verdict is read.
//!
//! ## Why a helper at all, rather than `mount(2)`
//!
//! On macOS `mount(2)` is root-only, and macFUSE's argument struct for it is
//! private to macFUSE. There is no supported way for an unprivileged process to
//! call it, which is why macFUSE ships `mount_macfuse` as `-rwsr-xr-x root:wheel`
//! and why **every** macOS FUSE binding goes through it: macFUSE's own libfuse,
//! `hanwen/go-fuse`, and the `cgofuse` layer rclone is built with on this
//! platform. The helper says so itself — "This program is not meant to be called
//! directly. The macFUSE library calls it" — and that is precisely the role DCTL
//! takes. Using it is not a workaround; it is the interface.
//!
//! It also keeps this crate's `#![forbid(unsafe_code)]` intact. A raw `mount(2)`
//! would need a syscall wrapper *and* root; the handshake below needs neither.
//!
//! ## The exchange, measured
//!
//! Against macFUSE 5.3.3 on macOS 27, in order:
//!
//! 1. The helper parses its arguments and checks the mountpoint. **Anything
//!    wrong here is reported before any descriptor is sent** — a mountpoint that
//!    is a regular file gives `mount_macfuse: …: not a directory`, an over-long
//!    `fstypename` gives its own message — so [`handover`](super::handover)
//!    reading end-of-file is a diagnosis rather than a mystery.
//! 2. It opens a free `/dev/macfuseN`, negotiates with the kernel extension, and
//!    sends that descriptor back over [`MOUNT_MACFUSE_ENV_COMMFD`].
//! 3. It waits. `FUSE_INIT` is already queued on the descriptor at this point,
//!    and the helper does not proceed until the filesystem has answered it and
//!    the kernel's opening `statfs`.
//! 4. Only then does it call `mount(2)` and exit with the result.
//!
//! Step 4 is why [`Helper::confirm`] is called *after* the session loop is
//! running and why its exit status — not the descriptor arriving — is what lets
//! `dctl mount` print "mounted". A helper that has exited 0 is a mount that is in
//! the mount table; nothing earlier proves that.
//!
//! ## Split so the shape is testable off macOS
//!
//! [`invocation`] builds the argument vector and the environment and is compiled
//! everywhere; only the spawn and the wait need macOS. Every string in that
//! invocation is one the setuid helper parses, and macFUSE *ignores what it does
//! not recognise*, so a typo would produce a working mount missing a property —
//! which makes the shape exactly the thing worth pinning in a test that runs on
//! the gate machine.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::constants::{
    MOUNT_MACFUSE_COMMFD, MOUNT_MACFUSE_COMMVERS, MOUNT_MACFUSE_ENV_CALL_BY_LIB,
    MOUNT_MACFUSE_ENV_COMMFD, MOUNT_MACFUSE_ENV_COMMVERS, MOUNT_MACFUSE_ENV_DAEMON_PATH,
    MOUNT_MACFUSE_HELPER,
};

/// Everything needed to run the mount helper, as plain data.
///
/// Separate from running it so that the argument and environment shape — the
/// part macFUSE parses and the part that fails quietly when it is wrong — is
/// ordinary code the Linux gates compile and test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The setuid helper itself.
    pub program: PathBuf,
    /// `-o` pairs followed by the mountpoint, in the order the helper reads them.
    pub arguments: Vec<OsString>,
    /// Variables the helper requires, in addition to the caller's environment.
    pub environment: Vec<(&'static str, OsString)>,
}

/// Describe the call that mounts `mountpoint` with `options`.
///
/// `daemon` is the path of the process that will serve the filesystem; macFUSE
/// records it against the mount, so a mount whose daemon path is missing is one
/// an operator cannot trace back to a program.
#[must_use]
pub fn invocation(mountpoint: &Path, options: &[String], daemon: &Path) -> Invocation {
    let mut arguments = Vec::with_capacity(options.len() * 2 + 1);
    for option in options {
        // One `-o` per option rather than one comma-joined argument: the helper
        // accepts the flag repeatedly, and a comma inside a value would end the
        // option and silently discard the rest. See `super::options`.
        arguments.push(OsString::from("-o"));
        arguments.push(OsString::from(option));
    }
    // The mountpoint is positional and last, after every option.
    arguments.push(mountpoint.as_os_str().to_os_string());

    Invocation {
        program: PathBuf::from(MOUNT_MACFUSE_HELPER),
        arguments,
        environment: vec![
            // Presence is the signal; the value is unused and libfuse leaves it
            // empty. Without it the helper refuses to do anything useful.
            (MOUNT_MACFUSE_ENV_CALL_BY_LIB, OsString::new()),
            (
                MOUNT_MACFUSE_ENV_DAEMON_PATH,
                daemon.as_os_str().to_os_string(),
            ),
            (
                MOUNT_MACFUSE_ENV_COMMFD,
                OsString::from(MOUNT_MACFUSE_COMMFD),
            ),
            (
                MOUNT_MACFUSE_ENV_COMMVERS,
                OsString::from(MOUNT_MACFUSE_COMMVERS),
            ),
        ],
    }
}

/// The path of the running program, for [`MOUNT_MACFUSE_ENV_DAEMON_PATH`].
///
/// Falls back to the binary's own name when the executable path cannot be read —
/// a mount is not worth refusing over a label, and macFUSE only uses it for
/// presentation and its own diagnostics.
#[must_use]
pub fn daemon_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from(dctl_meta::BINARY_NAME))
}

#[cfg(target_os = "macos")]
pub use running::Helper;

#[cfg(target_os = "macos")]
mod running {
    use std::io;
    use std::os::fd::OwnedFd;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    use super::Invocation;
    use crate::constants::{MOUNT_MACFUSE_ATTACH_GRACE, MOUNT_MACFUSE_ATTACH_POLL};

    /// A running mount helper, and therefore a mount that has been asked for and
    /// not yet confirmed.
    pub struct Helper {
        child: Child,
        /// This process's end of the comm socket, held for exactly as long as the
        /// helper is running. See [`Helper::start`] — closing it early kills the
        /// helper with `SIGPIPE` and the mount with it.
        channel: OwnedFd,
    }

    impl Helper {
        /// Start the helper, giving it one half of `channel` as its standard
        /// input and keeping the other.
        ///
        /// The socket goes on descriptor zero because putting a descriptor
        /// anywhere else in a child requires `pre_exec`, which is `unsafe`, and
        /// this crate forbids it. The helper reads the number out of the
        /// environment rather than assuming it, so zero is as good as three; it
        /// never reads standard input for anything else, and standard output and
        /// error stay free to carry its diagnostics.
        ///
        /// ## Why the whole channel, and not just the half being given away
        ///
        /// Because the helper writes back over it **after** the descriptor has
        /// been handed across, and there has to be a reader when it does.
        /// Measured on macFUSE 5.3.3: with this process's end closed as soon as
        /// the device arrived, the helper reached its `mount(2)`, the filesystem
        /// answered, and the helper then died of **signal 13** — every mount
        /// failing with "refused the mount without saying why", which is what an
        /// unhandled `SIGPIPE` and two empty pipes look like from outside.
        ///
        /// It had never been noticed because a second defect was hiding it: the
        /// socketpair was created without close-on-exec, so the helper had
        /// inherited a copy of this process's half and its write always had a
        /// reader — itself. The leak was load-bearing. Closing it exposed this,
        /// and taking ownership here is the answer to both: the channel belongs
        /// to the helper, [`Helper::confirm`] is what ends it, and no caller is
        /// in a position to close it early.
        ///
        /// # Errors
        /// Whatever `std::process::Command` reported. On macOS the usual answer
        /// is that macFUSE is not installed, which [`preflight`] has already
        /// checked for by name.
        ///
        /// [`preflight`]: crate::mount::preflight
        pub fn start(
            invocation: &Invocation,
            channel: super::super::handover::Channel,
        ) -> io::Result<Self> {
            let mut command = Command::new(&invocation.program);
            command
                .args(&invocation.arguments)
                .stdin(Stdio::from(channel.helper))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            for (name, value) in &invocation.environment {
                command.env(name, value);
            }
            // The `Command` is dropped at the end of this function, which closes
            // this process's copy of the *helper's* half. That matters: with a
            // copy left open, a helper that exits without sending a descriptor
            // would never reach end-of-file on the other half, and the wait for
            // it would hang instead of reporting the refusal. Our own half is
            // kept, which is the opposite requirement and the paragraph above.
            Ok(Self {
                child: command.spawn()?,
                channel: channel.ours,
            })
        }

        /// The end of the comm socket the device descriptor arrives on.
        ///
        /// Borrowed rather than handed over, because the helper owns it: a caller
        /// given the descriptor could drop it, and dropping it is precisely the
        /// failure [`Helper::start`] documents.
        #[must_use]
        pub fn channel(&self) -> &OwnedFd {
            &self.channel
        }

        /// Wait for the helper to report the outcome of the mount.
        ///
        /// Call this **after** the session loop is running: the helper does not
        /// reach its `mount(2)` until the filesystem has answered `FUSE_INIT` and
        /// the kernel's opening `statfs`, so waiting first would deadlock.
        ///
        /// # Errors
        /// The helper's own message when it refused, or a statement that it never
        /// finished when it outlasted [`MOUNT_MACFUSE_ATTACH_GRACE`]. Both are
        /// failures to *attach*; neither is a mount that half happened.
        pub fn confirm(mut self) -> io::Result<()> {
            let deadline = Instant::now().checked_add(MOUNT_MACFUSE_ATTACH_GRACE);
            loop {
                match self.child.try_wait()? {
                    Some(status) if status.success() => return Ok(()),
                    Some(status) => {
                        return Err(io::Error::other(self.complaint(status)));
                    }
                    // `checked_add` returning `None` means the clock cannot
                    // represent the deadline, which is not a reason to wait for
                    // ever on a process that may never exit.
                    None if deadline.is_none_or(|deadline| Instant::now() >= deadline) => {
                        // Left running deliberately rather than killed: it is
                        // inside `mount(2)` and cannot be interrupted, and the
                        // caller is about to detach the mountpoint anyway.
                        return Err(io::Error::other(format!(
                            "macFUSE's mount helper did not finish within {} seconds",
                            MOUNT_MACFUSE_ATTACH_GRACE.as_secs()
                        )));
                    }
                    None => std::thread::sleep(MOUNT_MACFUSE_ATTACH_POLL),
                }
            }
        }

        /// What the helper said when it refused, or what killed it if it did not
        /// get the chance to say anything.
        ///
        /// Quoted rather than summarised: macFUSE's messages name the actual
        /// objection — a mountpoint that is not a directory, a type name that is
        /// too long — and a paraphrase would be this module guessing at a cause
        /// it was told.
        ///
        /// Both pipes, error first, because macFUSE writes its refusals to
        /// standard error and its occasional notes to standard output, and a
        /// message that quoted only one of them would sometimes quote nothing.
        ///
        /// ## A signal is not a refusal
        ///
        /// The last branch used to say "refused the mount without saying why"
        /// for *every* unsuccessful exit, and that sentence was wrong twice over
        /// on the one case that mattered: a helper killed by `SIGPIPE` after a
        /// successful `mount(2)` had refused nothing, and had said exactly why —
        /// in the wait status nobody read. Diagnosing it took a bisect. The
        /// signal is named here because which one it was *is* the diagnosis: 13
        /// says the comm socket lost its reader, 9 says something killed the
        /// helper, 11 says macFUSE crashed, and those want three different
        /// answers from whoever reads the message.
        fn complaint(&mut self, status: std::process::ExitStatus) -> String {
            let said = [
                drain(self.child.stderr.take()),
                drain(self.child.stdout.take()),
            ]
            .into_iter()
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("; ");
            if !said.is_empty() {
                return said;
            }
            // A helper that fails without a word must still produce something an
            // operator can act on, and the wait status always carries one of the
            // two facts below.
            match std::os::unix::process::ExitStatusExt::signal(&status) {
                Some(signal) => format!(
                    "macFUSE's mount helper was killed by signal {signal} \
                     without reporting anything"
                ),
                None => match status.code() {
                    Some(code) => {
                        format!("macFUSE's mount helper exited {code} without saying why")
                    }
                    None => {
                        "macFUSE's mount helper refused the mount without saying why".to_string()
                    }
                },
            }
        }
    }

    /// Everything left on one of the helper's pipes, trimmed.
    ///
    /// A read failure yields nothing rather than an error: this runs while a
    /// refusal is being reported, and losing the quote is better than replacing
    /// the helper's reason with a complaint about reading it.
    fn drain(pipe: Option<impl io::Read>) -> String {
        let Some(mut pipe) = pipe else {
            return String::new();
        };
        let mut text = String::new();
        let _ = pipe.read_to_string(&mut text);
        text.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// Whether `argument` is the `-o` flag the helper reads options after.
    ///
    /// A predicate rather than a literal at each call site, because the tests
    /// below assert the *pairing* of flags and values and a mismatch between the
    /// two spellings would make them pass over an invocation macFUSE could not
    /// read.
    fn is_option_flag(argument: &OsStr) -> bool {
        argument == OsStr::new("-o")
    }

    fn described(options: &[&str]) -> Invocation {
        let options: Vec<String> = options.iter().map(|option| (*option).to_string()).collect();
        invocation(
            Path::new("/Volumes/vault"),
            &options,
            Path::new("/usr/local/bin/dctl"),
        )
    }

    #[test]
    fn the_helper_is_the_one_macfuse_ships_and_is_named_absolutely() {
        // A relative name would be resolved against `PATH`, which is the user's
        // to change — and this program runs as root.
        let invocation = described(&[]);
        assert!(invocation.program.is_absolute());
        assert_eq!(invocation.program, Path::new(MOUNT_MACFUSE_HELPER));
    }

    #[test]
    fn every_option_gets_its_own_flag_and_the_mountpoint_comes_last() {
        // One `-o` per option, because a comma-joined argument would let a value
        // containing a comma swallow the option after it — and macFUSE discards
        // what it cannot parse without a word.
        let invocation = described(&["ro", "noexec", "fsname=dctl"]);
        assert_eq!(
            invocation.arguments,
            [
                OsStr::new("-o"),
                OsStr::new("ro"),
                OsStr::new("-o"),
                OsStr::new("noexec"),
                OsStr::new("-o"),
                OsStr::new("fsname=dctl"),
                OsStr::new("/Volumes/vault"),
            ]
        );
        // Stated as a property as well as a literal: the flags and values must
        // alternate, and the last argument is the mountpoint rather than an
        // option that lost its flag.
        let (mountpoint, options) = invocation
            .arguments
            .split_last()
            .expect("there is always a mountpoint");
        assert_eq!(mountpoint, OsStr::new("/Volumes/vault"));
        for pair in options.chunks(2) {
            assert!(is_option_flag(&pair[0]), "{pair:?}");
            assert!(!is_option_flag(&pair[1]), "{pair:?}");
        }
    }

    #[test]
    fn a_mount_with_no_options_still_names_its_mountpoint() {
        assert_eq!(described(&[]).arguments, [OsStr::new("/Volumes/vault")]);
    }

    #[test]
    fn the_environment_carries_exactly_what_the_helper_reads() {
        // Every one of these is parsed by the setuid helper, and macFUSE ignores
        // what it does not recognise — so a wrong name here does not fail, it
        // produces a mount that behaves differently from the one asked for.
        let invocation = described(&[]);
        let named = |name: &str| {
            invocation
                .environment
                .iter()
                .find(|(variable, _)| *variable == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(named(MOUNT_MACFUSE_ENV_CALL_BY_LIB), Some(OsString::new()));
        assert_eq!(
            named(MOUNT_MACFUSE_ENV_DAEMON_PATH),
            Some(OsString::from("/usr/local/bin/dctl"))
        );
        assert_eq!(
            named(MOUNT_MACFUSE_ENV_COMMFD),
            Some(OsString::from(MOUNT_MACFUSE_COMMFD))
        );
        assert_eq!(
            named(MOUNT_MACFUSE_ENV_COMMVERS),
            Some(OsString::from(MOUNT_MACFUSE_COMMVERS))
        );
        assert_eq!(
            invocation.environment.len(),
            4,
            "an extra variable reaches a setuid program: {:?}",
            invocation.environment
        );
    }

    #[test]
    fn a_mountpoint_with_a_space_or_a_comma_is_passed_as_one_argument() {
        // The argument vector is never a shell string, so nothing in a path can
        // be read as a separator. Worth pinning: a mountpoint under
        // `/Volumes/My Vault` is ordinary on macOS.
        let invocation = invocation(
            Path::new("/Volumes/My Vault, 2024"),
            &[],
            Path::new("/usr/local/bin/dctl"),
        );
        assert_eq!(
            invocation.arguments,
            [OsStr::new("/Volumes/My Vault, 2024")]
        );
    }

    #[test]
    fn the_daemon_path_is_a_path_and_never_empty() {
        // macFUSE records it against the mount; an empty one leaves an operator
        // with a volume they cannot trace back to a program.
        let daemon = daemon_path();
        assert!(!daemon.as_os_str().is_empty());
    }

    /// A stand-in for macFUSE's helper, reduced to the one behaviour that
    /// decides whether a mount succeeds: it writes to the comm socket **after**
    /// it has handed the descriptor over.
    ///
    /// Not a guess. Measured on macFUSE 5.3.3, with DCTL's end of the channel
    /// closed as soon as the descriptor arrived: the helper reached its
    /// `mount(2)`, the filesystem answered, and then the helper died of
    /// **signal 13, SIGPIPE** — a write to a socket with no reader left. The
    /// mount failed with "macFUSE's mount helper refused the mount without
    /// saying why", which is what an unhandled signal and two empty pipes look
    /// like from the outside.
    #[cfg(target_os = "macos")]
    fn writes_back_after_handover() -> Invocation {
        Invocation {
            program: PathBuf::from("/bin/sh"),
            arguments: vec![
                OsString::from("-c"),
                // The pause is what makes the test meaningful: a helper that
                // wrote instantly might beat the close and pass by luck.
                OsString::from("sleep 0.5; printf x >&0"),
            ],
            environment: Vec::new(),
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn the_channel_outlives_the_helper_that_reports_over_it() {
        // The bug this pins was invisible for as long as a *second* bug hid it.
        //
        // `attach` opened the channel, gave one half to the helper, took the
        // device off the other half and returned — at which point its `Channel`
        // dropped and this process's end closed. That should have killed every
        // mount, and did not, because `socketpair(2)` had been called without
        // close-on-exec and the helper had **inherited a copy of this process's
        // half**. Its own write therefore always had a reader: itself. Fixing the
        // descriptor leak took that reader away and every mount began failing
        // with SIGPIPE — the leak was load-bearing.
        //
        // So the two are one fix, and this is the half that says what the
        // ownership must be: the channel belongs to the helper, and it is
        // `confirm` — the helper having reported — that ends it. Nothing earlier
        // may close it.
        let channel = super::super::handover::channel().expect("a socketpair");
        let helper = Helper::start(&writes_back_after_handover(), channel)
            .expect("/bin/sh starts on every macOS");
        helper
            .confirm()
            .expect("a helper writing back to the channel it was given must not be cut off");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn a_helper_killed_by_a_signal_is_reported_as_killed_and_not_as_silent() {
        // What the bug above actually looked like while it was being hunted:
        //
        //   error: cannot mount at '…': macFUSE's mount helper refused the
        //          mount without saying why
        //
        // The helper had not refused anything. It had been killed by SIGPIPE
        // after a successful `mount(2)`, and every word of that message was
        // wrong — "refused" names a decision that was never made, and "without
        // saying why" describes a silence that was really a signal nobody
        // looked at. It cost an afternoon and a bisect to find out, which is the
        // measure of a bad diagnostic.
        //
        // A signal is not a refusal and must not be dressed as one.
        let channel = super::super::handover::channel().expect("a socketpair");
        let suicide = Invocation {
            program: PathBuf::from("/bin/sh"),
            arguments: vec![OsString::from("-c"), OsString::from("kill -PIPE $$")],
            environment: Vec::new(),
        };
        let error = Helper::start(&suicide, channel)
            .expect("/bin/sh starts on every macOS")
            .confirm()
            .expect_err("a helper that died is not a mount");
        let said = error.to_string();
        assert!(
            said.contains("signal"),
            "a killed helper must be reported as killed: {said}"
        );
        assert!(
            said.contains("13"),
            "and the signal must be named, because which one it was is the \
             whole diagnosis: {said}"
        );
        assert!(
            !said.contains("without saying why"),
            "a process that died of a signal did say why: {said}"
        );
    }
}
