//! One source per remote, per run.
//!
//! `dctl cat` takes any number of arguments and they may name different places:
//! `dctl cat report.pdf archive:notes/today.md archive:notes/yesterday.md` is
//! three arguments, two of them in the same vault. Opening a source for each
//! argument would unlock that vault twice, which means **two password prompts**
//! for one command — and in an unattended job with `--password-command`, two
//! invocations of whatever that command shells out to.
//!
//! So a remote is opened once and remembered. The cache lives for exactly one
//! `run` and is never global: a process-wide cache of unlocked vaults is a place
//! for root keys to outlive the command that needed them (`PLAN.md` §7).
//!
//! It is deliberately not a general-purpose pool. There is no eviction, no
//! reference counting of unlock state and no sharing between commands, because
//! the lifetime that matters here is "this invocation" and anything longer is a
//! liability rather than a feature.
//!
//! ## The key is the container, not the remote's name
//!
//! It used to be the name, and the name is only half an address on a provider
//! shorthand: `b2:one/x.txt` and `b2:two/y.txt` name two *buckets* and would have
//! shared one client. Worse, the name was all that reached the resolver — each
//! argument's path was replaced with the empty string before it was opened — so
//! `dctl cat b2:DCTL001/a.txt` answered *"'b2' needs a bucket name"* about a
//! command line that had given one. Both halves come from
//! [`logical_prefix`](crate::remote::resolve::logical_prefix) and
//! [`container`](crate::remote::resolve::container) now: one resolution decides
//! which source to open **and** what to ask it for.

use std::collections::HashMap;
use std::sync::Arc;

use crate::commands::pipeline::ObjectSpec;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::remote::RemoteSpec;
use crate::source::{self, Source};

/// One argument's remote, resolved: the source to read through and the key that
/// addresses the object inside it.
pub struct Located {
    /// The opened source, shared by every argument in the same container.
    pub source: Arc<dyn Source>,
    /// The object's logical path **inside that source**.
    ///
    /// Not the spec's path, and the difference is a whole provider family:
    /// `b2:DCTL001/a.txt` names the bucket `DCTL001` and the object `a.txt`, so
    /// reading `DCTL001/a.txt` asks the bucket for a key that was never written.
    /// It did not even fail that way — the bucket was thrown away one layer
    /// earlier and `dctl cat b2:DCTL001/a.txt` answered *"'b2' needs a bucket
    /// name"* about a command line that had given one.
    pub key: String,
}

/// The sources this invocation has opened so far.
pub struct Opened<'a> {
    ctx: &'a Ctx,
    /// Keyed by **container** — `archive:` for a configured remote,
    /// `b2:DCTL001` for a provider shorthand — rather than by the remote's name.
    ///
    /// The name alone was right for every named remote and wrong for every
    /// shorthand, where the bucket is carried in the path: two arguments in two
    /// buckets of one provider would have shared one client and read each
    /// other's objects.
    by_container: HashMap<String, Arc<dyn Source>>,
    /// The configuration, read once per invocation.
    ///
    /// Held because deciding *which container an argument addresses* is a
    /// question for the resolver and has to be answered **before** the source is
    /// opened — otherwise the cache is consulted with a key that was guessed.
    /// Read lazily so a command whose arguments are all local paths never touches
    /// the file at all.
    config: Option<crate::config::Config>,
}

impl<'a> Opened<'a> {
    /// An empty cache bound to one command invocation.
    #[must_use]
    pub fn new(ctx: &'a Ctx) -> Self {
        Self {
            ctx,
            by_container: HashMap::new(),
            config: None,
        }
    }

    /// The configuration, loaded on first use.
    ///
    /// # Errors
    /// Whatever reading the configuration file reported.
    fn config(&mut self) -> Result<&crate::config::Config> {
        if self.config.is_none() {
            let path = crate::config::resolve_path(self.ctx.globals.config.as_deref());
            self.config = Some(crate::config::load_or_default(&path)?);
        }
        // `is_none` was just answered, so this cannot be `None`.
        self.config.as_ref().ok_or_else(|| {
            crate::error::CliError::fatal("internal: the configuration was not retained")
        })
    }

    /// Locate `spec`: the source to read it through, and its key inside that
    /// source.
    ///
    /// Held as an [`Arc`] rather than handed out by reference because each
    /// pre-flighted argument keeps its own handle and they outlive the loop that
    /// built them: the arguments are all resolved before any byte is written,
    /// which is the ordering that stops `cat` emitting half a stream and then
    /// failing.
    ///
    /// # Errors
    /// Whatever [`crate::source::open`] reported for that remote, or whatever
    /// resolution reported about the remote's name and settings.
    pub async fn get(&mut self, spec: &ObjectSpec) -> Result<Located> {
        let Some(remote) = spec.remote() else {
            return Err(crate::error::CliError::fatal(
                "internal: a local path has no remote to open",
            ));
        };

        // The **whole** argument, path included. Passing an empty path here is
        // what discarded the bucket: `b2:DCTL001/a.txt` reached the resolver as
        // `b2:` and was refused for naming no bucket.
        let remote_spec = RemoteSpec::Named {
            remote: remote.to_string(),
            path: spec.path().to_string(),
        };

        let key = crate::remote::resolve::logical_prefix(&remote_spec, self.config()?)?;
        let container = crate::remote::resolve::container(&remote_spec, &key);

        if let Some(existing) = self.by_container.get(&container) {
            return Ok(Located {
                source: Arc::clone(existing),
                key,
            });
        }

        let source: Arc<dyn Source> =
            Arc::from(source::open(self.ctx, &remote_spec).await?.into_source());
        self.by_container.insert(container, Arc::clone(&source));
        Ok(Located { source, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx() -> Ctx {
        Ctx::new(Harness::parse_from(["dctl", "--no-ask-password"]).globals)
    }

    fn object(spec: &str) -> ObjectSpec {
        ObjectSpec::parse(spec).expect("a well-formed argument")
    }

    #[tokio::test]
    async fn a_failure_to_open_is_reported_rather_than_cached_as_success() {
        let context = ctx();
        let mut opened = Opened::new(&context);
        let error = opened
            .get(&object("nosuchremote:file.txt"))
            .await
            .err()
            .expect("an unconfigured remote cannot be opened");
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        // Nothing was remembered, so a retry re-reports rather than answering
        // from a cache that never held anything.
        assert!(opened.get(&object("nosuchremote:file.txt")).await.is_err());
    }

    #[tokio::test]
    async fn two_objects_in_one_container_share_a_source_and_two_containers_do_not() {
        // The cache key is the container, not the remote's name. Keyed by name,
        // `b2:one/x` and `b2:two/y` — two buckets on one provider — shared a
        // client and each argument read the other's bucket. The key is asserted
        // directly because opening a bucket needs a credential; what the key
        // *is* decides whether they collide.
        for (left, right, shared) in [
            ("archive:a.txt", "archive:b/c.txt", true),
            ("b2:one/x.txt", "b2:one/sub/y.txt", true),
            ("b2:one/x.txt", "b2:two/y.txt", false),
        ] {
            let key = |written: &str| {
                let spec = object(written);
                let remote_spec = RemoteSpec::Named {
                    remote: spec.remote().expect("a remote").to_string(),
                    path: spec.path().to_string(),
                };
                let prefix = crate::remote::resolve::logical_prefix(&remote_spec, &())
                    .unwrap_or_else(|_| spec.path().to_string());
                crate::remote::resolve::container(&remote_spec, &prefix)
            };
            assert_eq!(
                key(left) == key(right),
                shared,
                "'{left}' and '{right}' disagree about sharing a source"
            );
        }
    }

    #[tokio::test]
    async fn a_shorthands_object_key_is_what_is_left_after_the_bucket() {
        // `dctl cat b2:DCTL001/a.txt` used to answer *"'b2' needs a bucket
        // name"* — a false diagnosis about a command line that had given one —
        // because the argument's path was replaced with the empty string before
        // it reached the resolver. Now the whole argument resolves, and what
        // comes back is the object's key inside the bucket.
        let spec = object("b2:DCTL001/a.txt");
        let remote_spec = RemoteSpec::Named {
            remote: spec.remote().expect("a remote").to_string(),
            path: spec.path().to_string(),
        };
        assert_eq!(
            crate::remote::resolve::logical_prefix(&remote_spec, &())
                .expect("a shorthand resolves"),
            "a.txt"
        );
    }
}
