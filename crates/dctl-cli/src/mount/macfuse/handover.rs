//! Receiving the `/dev/macfuseN` descriptor from the mount helper.
//!
//! The helper opens the kernel-extension device and passes it back over a Unix
//! socket as an `SCM_RIGHTS` control message — protocol 2 of macFUSE's handover,
//! which is the only one any current binding uses. That descriptor is the
//! connection to the kernel: everything the filesystem ever reads or writes goes
//! through it, and it is what [`fuser::Session::from_fd`] is given.
//!
//! ## Why `rustix` and not the `nix` used a file away
//!
//! Because of `#![forbid(unsafe_code)]`, and it is worth writing down so nobody
//! "simplifies" the two crates into one. `nix` hands a received descriptor back
//! as a bare `RawFd` — an integer — and the only way to make that own anything is
//! `OwnedFd::from_raw_fd`, which is `unsafe`. Putting an `unsafe` block here to
//! save a dependency would trade the crate's strongest structural guarantee for
//! nothing.
//!
//! `rustix` was designed around exactly this problem: its
//! `RecvAncillaryMessage::ScmRights` yields **`OwnedFd`** values, so the received
//! descriptor arrives already owned and is closed by the type system rather than
//! by remembering to. It is already in the dependency graph, and it is the one
//! part of this handshake where ownership is easy to get wrong — a leaked device
//! descriptor keeps a macFUSE mount instance alive with nothing serving it, which
//! on macOS is a directory nobody can use until the machine reboots.
//!
//! `nix` stays for [`detach`](super::detach), because `rustix`'s mount module is
//! Linux-only and `unmount(2)` on macOS is not in it. Each crate is used for the
//! thing it can do safely.
//!
//! ## Why the failure case is the interesting one
//!
//! The helper checks its options and its mountpoint **before** it opens the
//! device. Measured on macFUSE 5.3.3: a mountpoint that is a regular file, and an
//! over-long `fstypename`, are both refused with a message and an exit before a
//! single byte crosses the socket. So the socket reaching end-of-file with no
//! control message is not a mystery — it means the helper gave up, and its own
//! complaint is waiting on its error pipe. This module reports that state as
//! itself rather than as a read failure, so [`super::attach`] can quote the
//! helper instead of guessing.
//!
//! ## Why the wait cannot be bounded here
//!
//! There is no timeout on the receive, and that is deliberate. The helper is a
//! setuid program that has already been started; if it is going to send a
//! descriptor it does so in milliseconds, and if it is not, it exits and the
//! socket closes — both of which end the wait. A timer here would add a third
//! outcome ("we stopped listening") that leaves a helper running with nobody to
//! answer it, which on macOS is how a mountpoint gets wedged until reboot.

use std::io::{self, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SocketFlags, SocketType,
    recvmsg, socketpair,
};

/// One byte of payload accompanies the descriptor. `SCM_RIGHTS` requires at
/// least one byte of ordinary data, so the buffer exists to satisfy the protocol
/// rather than to carry anything: its content is never read.
const PAYLOAD_BYTES: usize = 1;

/// How many descriptors the control buffer has room for.
///
/// One, because one is what the protocol sends. Sized rather than generous on
/// purpose: a buffer with room for more would silently accept a message this
/// build does not understand, and the descriptors in it would be installed in
/// this process whether or not anything looked at them.
const EXPECTED_DESCRIPTORS: usize = 1;

/// The two halves of the channel the helper hands the device back over.
///
/// [`Channel::helper`] becomes the child's standard input; [`Channel::ours`] is
/// what [`receive`] listens on. Handed out as separate fields because the caller
/// gives one half away and keeps the other.
pub struct Channel {
    /// This process's end.
    pub ours: OwnedFd,
    /// The end given to the helper.
    pub helper: OwnedFd,
}

/// Open the channel.
///
/// `SOCK_STREAM` rather than `SOCK_DGRAM`, because that is what macFUSE's
/// handover protocol 2 expects and because a stream gives end-of-file — the
/// signal that tells a lost descriptor apart from a helper that refused.
///
/// ## Close-on-exec, and why the flag is the whole point
///
/// `socketpair(2)` leaves both halves inheritable unless it is asked otherwise,
/// and asking was missed. The cost was measured rather than reasoned about: seven
/// `mount_macfuse` processes were found still running eighty minutes after the
/// runs that started them, each pinning one of the sixty-four `/dev/macfuseN`
/// nodes, and each holding *this process's* half of the channel alongside its
/// own. A stream reaches end-of-file when the last descriptor for its peer
/// closes, so a helper carrying a copy of [`Channel::ours`] can never observe
/// DCTL going away — not on a clean exit, not on a crash, not on `SIGKILL`. The
/// signal this module is built around simply never arrives.
///
/// It is also a descriptor handed to a **setuid-root** program that has no use
/// for it, which is worth avoiding on its own terms.
///
/// The half that is *meant* to reach the helper still does: it becomes the
/// child's standard input through `Stdio::from`, which `dup2`s it onto descriptor
/// zero — and `dup2` produces a descriptor without the flag whatever the original
/// carried. So close-on-exec costs the helper nothing it needs, and takes away
/// everything it should not have.
///
/// ## Why the flag is set afterwards rather than asked for
///
/// `SOCK_CLOEXEC` is a Linux extension. Darwin's `socketpair(2)` has no flags
/// argument at all — `rustix` reflects this exactly, gating
/// `SocketFlags::CLOEXEC` off Apple platforms — so there is no atomic form of
/// this call to reach for, and `fcntl` is not a shortcut past one. What that
/// costs is a window between the pair existing and the flag being set, in which
/// a *concurrent* `exec` in another thread would still inherit both halves. It
/// is named rather than left implicit because it is the one thing this cannot
/// fix: the mount path runs on one thread and spawns nothing in that window, and
/// the alternative — omitting the flag because it cannot be perfect — is how the
/// seven stuck helpers came to exist.
///
/// # Errors
/// Whatever `socketpair(2)` or `fcntl(2)` reported. There is no ordinary cause;
/// a failure here means the process is out of descriptors.
pub fn channel() -> io::Result<Channel> {
    let (ours, helper) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::empty(),
        None,
    )?;
    // Both halves, and a failure on either is fatal to the mount rather than a
    // warning: an inheritable half is precisely the state that leaves a helper
    // running for ever, and a mount is not worth starting with it.
    for half in [&ours, &helper] {
        rustix::io::fcntl_setfd(half, rustix::io::FdFlags::CLOEXEC)?;
    }
    Ok(Channel { ours, helper })
}

/// What came back over the channel.
#[derive(Debug)]
pub enum Received {
    /// The kernel-extension device, ready to be handed to a session.
    Device(OwnedFd),
    /// The helper closed the channel without sending one, which means it refused
    /// before it ever opened a device. Its own message says why.
    HelperGaveUp,
}

/// Wait for the helper to send the device descriptor.
///
/// # Errors
/// Whatever `recvmsg(2)` reported. A helper that refuses is **not** an error
/// here — it is [`Received::HelperGaveUp`], because the useful message belongs to
/// the helper and this module has nothing to add to it.
pub fn receive(socket: &OwnedFd) -> io::Result<Received> {
    let mut payload = [0_u8; PAYLOAD_BYTES];
    let mut buffers = [IoSliceMut::new(&mut payload)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(EXPECTED_DESCRIPTORS))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);

    recvmsg(socket, &mut buffers, &mut ancillary, RecvFlags::empty())?;

    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(descriptors) = message {
            // Owned already: `rustix` hands these over as `OwnedFd`, so the one
            // that is kept is closed by its own type and any extra — a protocol
            // this build does not know — is closed by being dropped here rather
            // than leaked into the process.
            let mut descriptors = descriptors;
            if let Some(device) = descriptors.next() {
                return Ok(Received::Device(device));
            }
        }
    }

    Ok(Received::HelperGaveUp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{IoSlice, Write};
    use std::os::fd::{AsFd, AsRawFd};

    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

    #[test]
    fn the_channel_is_a_connected_pair() {
        // Both halves exist and are distinct descriptors; the helper's half is
        // the one that becomes a child's standard input.
        let channel = channel().expect("a socketpair on a healthy process");
        assert_ne!(channel.ours.as_raw_fd(), channel.helper.as_raw_fd());
    }

    #[test]
    fn neither_half_of_the_channel_survives_into_a_child_process() {
        // Measured on this machine, and the reason this test exists: seven
        // `mount_macfuse` processes were found still running eighty minutes
        // after the runs that started them, each pinning a `/dev/macfuseN` node
        // that nothing could reclaim. Every one of them held **three** sockets —
        // its own half twice, and *the parent's half*:
        //
        //   0u unix 0x97d2…f9bf ->0xb09a…8f40   the half it was given
        //   3u unix 0xb09a…8f40 ->0x97d2…f9bf   OURS, inherited
        //   4u unix 0x97d2…f9bf ->0xb09a…8f40   its own, dup'd by macFUSE
        //
        // `socketpair(2)` does not set close-on-exec unless it is asked to, and
        // it was not, so both halves reached every child this process spawned —
        // including a setuid-root program that has no business holding either.
        //
        // The consequence is the one that matters: a stream reaches end-of-file
        // when the *last* descriptor for its peer closes, so a helper holding a
        // copy of `ours` can never see DCTL go away, however DCTL goes. The
        // module docs above call end-of-file "the signal that tells a lost
        // descriptor apart from a helper that refused" — a signal that cannot
        // arrive.
        //
        // Written as the symptom rather than as a flag test: `cat` stands in for
        // the helper, reading the half it was handed until end-of-file. With the
        // parent's half closed there is nothing left to keep the stream open, so
        // it must exit. Leaked, it waits for ever — which is exactly what those
        // seven processes were doing.
        let channel = channel().expect("a socketpair on a healthy process");
        let mut child = std::process::Command::new("/bin/cat")
            .stdin(std::process::Stdio::from(channel.helper))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("cat is on every macOS");

        // The only copy of this half left in this process. Dropping it is the
        // whole experiment: after this, nothing *should* be holding the peer.
        drop(channel.ours);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let exited = loop {
            match child.try_wait().expect("a spawned child can be waited on") {
                Some(_) => break true,
                None if std::time::Instant::now() >= deadline => break false,
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };
        if !exited {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert!(
            exited,
            "the child never reached end-of-file: it inherited this process's \
             half of the channel, so closing ours cannot close the stream. A \
             macFUSE helper in that state outlives DCTL and keeps its \
             /dev/macfuseN node until the machine reboots."
        );
    }

    #[test]
    fn both_halves_of_the_channel_are_close_on_exec() {
        // The mechanism behind the test above, pinned directly so a regression
        // names its own cause rather than presenting as a hung child. Both
        // halves, not just the one kept: the half handed to the helper becomes
        // its standard input through `Stdio::from`, which dups it onto
        // descriptor zero — and a dup does not carry the flag, so asking for
        // close-on-exec here costs the child nothing it needs.
        let channel = channel().expect("a socketpair on a healthy process");
        for (name, half) in [("ours", &channel.ours), ("helper", &channel.helper)] {
            let flags = rustix::io::fcntl_getfd(half).expect("a live descriptor has flags");
            assert!(
                flags.contains(rustix::io::FdFlags::CLOEXEC),
                "the {name} half is inheritable: every child this process spawns \
                 gets a copy, including a setuid-root mount helper"
            );
        }
    }

    #[test]
    fn a_peer_that_closes_without_sending_is_a_helper_that_gave_up() {
        // The measured failure path: macFUSE's helper checks its arguments and
        // its mountpoint before it opens a device, so a refusal arrives as
        // end-of-file rather than as a descriptor. Reported as its own outcome so
        // the caller quotes the helper instead of inventing a cause.
        let channel = channel().expect("a socketpair on a healthy process");
        drop(channel.helper);
        assert!(matches!(
            receive(&channel.ours).expect("end-of-file is not a read failure"),
            Received::HelperGaveUp
        ));
    }

    #[test]
    fn a_peer_that_sends_only_data_is_not_mistaken_for_a_descriptor() {
        // A byte with no control message must not be read as a successful
        // handover: that would hand `Session::from_fd` something that is not the
        // kernel device, and the mount would fail somewhere far less obvious.
        let channel = channel().expect("a socketpair on a healthy process");
        let mut peer = std::fs::File::from(channel.helper);
        peer.write_all(b"x").expect("the pair has buffer space");
        drop(peer);
        assert!(matches!(
            receive(&channel.ours).expect("a plain byte is not a read failure"),
            Received::HelperGaveUp
        ));
    }

    #[test]
    fn a_descriptor_sent_over_the_channel_arrives_owned() {
        // The success path, without macFUSE: a descriptor passed as `SCM_RIGHTS`
        // comes back owned — a distinct descriptor in this process, usable, and
        // closed by its own type. It is the shape of the real handover (one
        // descriptor, one byte) with an ordinary file standing in for the device.
        let channel = channel().expect("a socketpair on a healthy process");
        let file = tempfile::tempfile().expect("a temporary file");

        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let descriptors = [file.as_fd()];
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        let payload = [0_u8; PAYLOAD_BYTES];
        sendmsg(
            &channel.helper,
            &[IoSlice::new(&payload)],
            &mut ancillary,
            SendFlags::empty(),
        )
        .expect("a descriptor fits in the pair's buffer");

        match receive(&channel.ours).expect("a descriptor is waiting") {
            Received::Device(device) => {
                assert_ne!(device.as_raw_fd(), file.as_fd().as_raw_fd());
                let metadata = std::fs::File::from(device)
                    .metadata()
                    .expect("the received descriptor is open");
                assert!(metadata.is_file());
            }
            Received::HelperGaveUp => panic!("a descriptor was sent and not received"),
        }
    }
}
