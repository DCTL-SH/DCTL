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
//! `run`, is keyed by the remote's configured name, and is never global: a
//! process-wide cache of unlocked vaults is a place for root keys to outlive the
//! command that needed them (`PLAN.md` §7).
//!
//! It is deliberately not a general-purpose pool. There is no eviction, no
//! reference counting of unlock state and no sharing between commands, because
//! the lifetime that matters here is "this invocation" and anything longer is a
//! liability rather than a feature.

use std::collections::HashMap;
use std::sync::Arc;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::remote::RemoteSpec;
use crate::source::{self, Source};

/// The sources this invocation has opened so far.
pub struct Opened<'a> {
    ctx: &'a Ctx,
    /// Keyed by the remote's name as the configuration file spells it, which is
    /// also what [`crate::commands::pipeline::ObjectSpec`] hands back — so two
    /// arguments naming the same vault find each other here.
    by_remote: HashMap<String, Arc<dyn Source>>,
}

impl<'a> Opened<'a> {
    /// An empty cache bound to one command invocation.
    #[must_use]
    pub fn new(ctx: &'a Ctx) -> Self {
        Self {
            ctx,
            by_remote: HashMap::new(),
        }
    }

    /// The source for `remote`, opening it if this is the first argument to name
    /// it.
    ///
    /// Held as an [`Arc`] rather than handed out by reference because each
    /// pre-flighted argument keeps its own handle and they outlive the loop that
    /// built them: the arguments are all resolved before any byte is written,
    /// which is the ordering that stops `cat` emitting half a stream and then
    /// failing.
    ///
    /// # Errors
    /// Whatever [`crate::source::open`] reported for that remote.
    pub async fn get(&mut self, remote: &str) -> Result<Arc<dyn Source>> {
        if let Some(existing) = self.by_remote.get(remote) {
            return Ok(Arc::clone(existing));
        }

        // The path portion is empty on purpose: this addresses the *remote*, and
        // each argument supplies its own object path when it reads. Passing one
        // argument's path here would key the cache by object and unlock once per
        // file.
        let spec = RemoteSpec::Named {
            remote: remote.to_string(),
            path: String::new(),
        };
        let source: Arc<dyn Source> = Arc::from(source::open(self.ctx, &spec).await?);
        self.by_remote
            .insert(remote.to_string(), Arc::clone(&source));
        Ok(source)
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

    #[tokio::test]
    async fn a_failure_to_open_is_reported_rather_than_cached_as_success() {
        let context = ctx();
        let mut opened = Opened::new(&context);
        let error = opened
            .get("nosuchremote")
            .await
            .err()
            .expect("an unconfigured remote cannot be opened");
        assert_eq!(error.code(), crate::exit::ExitCode::FatalError);
        // Nothing was remembered, so a retry re-reports rather than answering
        // from a cache that never held anything.
        assert!(opened.get("nosuchremote").await.is_err());
    }
}
