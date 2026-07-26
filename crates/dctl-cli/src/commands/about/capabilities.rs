//! What a provider can do, answered without asking it.
//!
//! Every row here is a property of the **backend implementation** in
//! `dctl-store`, not of the provider's feature list: `range_reads` is claimed
//! because `Backend::get_range` is on the trait and every implementation
//! honours it, and `usage_reporting` is claimed by nobody because no such call
//! exists on the trait at all. That is what makes the answer knowable offline —
//! it is a fact about this binary, and this binary is right here.
//!
//! It is also the limit of the claim, and the module says so out loud through
//! [`crate::constants::ABOUT_CAPABILITIES_NOTICE`]. Whether a particular bucket
//! lets a particular key do these things is a different question, and one DCTL
//! cannot answer until it can talk to the provider.
//!
//! The matrix itself lives in [`crate::constants::BACKEND_CAPABILITIES`] so that
//! this renderer and the documentation generator read the same rows. Listing the
//! providers that *have* each capability, rather than a full grid of booleans,
//! means a provider added later inherits `false` for anything nobody has
//! considered for it — the safe direction to be wrong in, because an
//! understated capability produces a refusal and an overstated one produces a
//! silent wrong answer.

use serde::Serialize;

use crate::constants::{ABOUT_SUPPORTED_NO, ABOUT_SUPPORTED_YES, BACKEND_CAPABILITIES};

/// One capability, as it applies to one provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Capability {
    /// Stable machine name, safe to branch on.
    pub name: &'static str,
    /// Whether the provider's backend has it.
    pub supported: bool,
    /// One sentence on what it means and why DCTL cares.
    pub description: &'static str,
}

impl Capability {
    /// The text rendering of [`Capability::supported`].
    ///
    /// Words rather than glyphs: this column is grepped at least as often as it
    /// is read, and a tick mark is neither typeable nor safe on a console that
    /// cannot render it. The JSON shape carries the boolean and never applies
    /// this.
    #[must_use]
    pub const fn supported_label(self) -> &'static str {
        if self.supported {
            ABOUT_SUPPORTED_YES
        } else {
            ABOUT_SUPPORTED_NO
        }
    }
}

/// Every capability, resolved for one provider type.
///
/// The full list is returned every time, including the unsupported rows. A
/// report that listed only what a provider *can* do would leave a reader unable
/// to tell "this provider cannot" from "this build forgot to ask" — and for
/// `usage_reporting` and `quota_reporting`, which nothing supports yet, that
/// distinction is the entire point of the command.
#[must_use]
pub fn for_provider(provider: &str) -> Vec<Capability> {
    BACKEND_CAPABILITIES
        .iter()
        .map(|&(name, description, providers)| Capability {
            name,
            supported: providers.contains(&provider),
            description,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        CAPABILITY_EMPTY_DIRECTORIES, CAPABILITY_MULTIPART_UPLOAD, CAPABILITY_PAGED_LISTING,
        CAPABILITY_QUOTA_REPORTING, CAPABILITY_RANGE_READS, CAPABILITY_USAGE_REPORTING,
        CAPABILITY_VERIFIED_WRITES, PROVIDER_B2, PROVIDER_LOCAL, PROVIDER_R2, PROVIDER_S3,
        PROVIDER_VAULT, REMOTE_PROVIDER_TYPES,
    };

    fn lookup(provider: &str, capability: &str) -> bool {
        for_provider(provider)
            .into_iter()
            .find(|entry| entry.name == capability)
            .map(|entry| entry.supported)
            .unwrap_or_else(|| panic!("'{capability}' is not in the matrix"))
    }

    #[test]
    fn every_provider_gets_the_whole_matrix_including_the_noes() {
        // A short list would make "cannot" and "was not asked" indistinguishable.
        for (provider, _) in REMOTE_PROVIDER_TYPES {
            assert_eq!(
                for_provider(provider).len(),
                BACKEND_CAPABILITIES.len(),
                "'{provider}' got a truncated matrix"
            );
        }
    }

    #[test]
    fn an_unknown_provider_supports_nothing_rather_than_everything() {
        // The safe direction: a provider nobody has considered must not inherit
        // claims it was never checked against.
        assert!(
            for_provider("gdrive").iter().all(|entry| !entry.supported),
            "an unknown provider was credited with a capability"
        );
    }

    #[test]
    fn the_trait_guaranteed_capabilities_belong_to_every_provider() {
        // These three are on `dctl_store::Backend` itself, so an implementation
        // that lacked one would not compile.
        for (provider, _) in REMOTE_PROVIDER_TYPES {
            for capability in [
                CAPABILITY_RANGE_READS,
                CAPABILITY_VERIFIED_WRITES,
                CAPABILITY_PAGED_LISTING,
            ] {
                assert!(
                    lookup(provider, capability),
                    "{provider} lacks {capability}"
                );
            }
        }
    }

    #[test]
    fn multipart_upload_is_a_cloud_provider_property() {
        assert!(lookup(PROVIDER_B2, CAPABILITY_MULTIPART_UPLOAD));
        assert!(lookup(PROVIDER_S3, CAPABILITY_MULTIPART_UPLOAD));
        assert!(lookup(PROVIDER_R2, CAPABILITY_MULTIPART_UPLOAD));
        // A filesystem write is one write; there is nothing to split.
        assert!(!lookup(PROVIDER_LOCAL, CAPABILITY_MULTIPART_UPLOAD));
    }

    #[test]
    fn only_a_filesystem_can_hold_an_empty_directory() {
        // An object store has no directories at all, only shared key prefixes,
        // which is why `rmdirs` means something different on each.
        assert!(lookup(PROVIDER_LOCAL, CAPABILITY_EMPTY_DIRECTORIES));
        for provider in [PROVIDER_B2, PROVIDER_S3, PROVIDER_R2] {
            assert!(!lookup(provider, CAPABILITY_EMPTY_DIRECTORIES));
        }
    }

    /// Whether any provider at all is credited with a capability.
    fn supported_by_anything(capability: &str) -> bool {
        BACKEND_CAPABILITIES
            .iter()
            .any(|&(name, _, providers)| name == capability && !providers.is_empty())
    }

    #[test]
    fn nothing_in_this_build_reports_usage_or_quota() {
        // The assertion that keeps `dctl about` honest: the moment a backend
        // gains either call, this test fails and whoever added it is sent to
        // remove the `unimplemented` gate in the command.
        assert!(!supported_by_anything(CAPABILITY_USAGE_REPORTING));
        assert!(!supported_by_anything(CAPABILITY_QUOTA_REPORTING));
        // The control: a capability that *is* supported proves the check works.
        assert!(supported_by_anything(CAPABILITY_RANGE_READS));
    }

    #[test]
    fn the_matrix_never_names_a_provider_that_does_not_exist() {
        // A typo in the table would silently create a capability nothing has.
        let known: Vec<&str> = REMOTE_PROVIDER_TYPES
            .iter()
            .map(|(name, _)| *name)
            .collect();
        for (capability, _, providers) in BACKEND_CAPABILITIES {
            for provider in *providers {
                assert!(
                    known.contains(provider),
                    "'{capability}' names unknown provider '{provider}'"
                );
                // A vault remote stores nothing itself; `about` follows the
                // chain to the provider that does.
                assert_ne!(*provider, PROVIDER_VAULT);
            }
        }
    }

    #[test]
    fn capability_names_are_unique_and_machine_safe() {
        // The name is what a script branches on, so it must be stable, unique
        // and free of the shell-hostile characters a JSON key can otherwise hold.
        let names: Vec<&str> = BACKEND_CAPABILITIES
            .iter()
            .map(|(name, ..)| *name)
            .collect();
        for (index, name) in names.iter().enumerate() {
            assert!(!name.is_empty());
            assert!(!names[index + 1..].contains(name), "'{name}' listed twice");
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "'{name}' is not snake_case ascii"
            );
        }
    }

    #[test]
    fn every_capability_explains_itself() {
        // The description column is what makes the table usable by someone who
        // has never read PLAN.md.
        for (name, description, _) in BACKEND_CAPABILITIES {
            assert!(!description.is_empty(), "'{name}' has no description");
            assert!(
                description.ends_with('.'),
                "'{name}' description is not a sentence"
            );
        }
    }

    #[test]
    fn the_supported_labels_are_distinct() {
        let yes = Capability {
            name: CAPABILITY_RANGE_READS,
            supported: true,
            description: "",
        };
        let no = Capability {
            supported: false,
            ..yes
        };
        assert_eq!(yes.supported_label(), ABOUT_SUPPORTED_YES);
        assert_eq!(no.supported_label(), ABOUT_SUPPORTED_NO);
        assert_ne!(yes.supported_label(), no.supported_label());
    }
}
