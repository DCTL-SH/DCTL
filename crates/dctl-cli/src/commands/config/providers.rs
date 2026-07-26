//! `dctl config providers` — the remote types this build can store bytes in.
//!
//! Answers the question `dctl config create NAME TYPE` raises: what may TYPE be?
//! Printing the list beats documenting it, because a build compiled without a
//! provider must not advertise it — the list a user reads has to be the list the
//! binary in front of them actually supports.
//!
//! `vault` is deliberately **not** in the table. It is a legal section type, and
//! [`super::create`] accepts it, but it is a wrapper rather than a destination:
//! it stores nothing itself and cannot be the answer to "where should this go".
//! Offering it in a list of places to put data would be misleading, so it is
//! mentioned on stderr instead, where it informs without being mistaken for a
//! provider.

use serde::Serialize;

use super::emit;
use crate::constants;
use crate::ctx::Ctx;
use crate::error::Result;

/// One supported provider type.
#[derive(Debug, Serialize)]
struct ProviderRow {
    /// Spelling used in a config section's `type` key.
    #[serde(rename = "type")]
    kind: &'static str,
    description: &'static str,
}

/// List the supported remote types.
///
/// # Errors
/// A stdout failure other than a broken pipe.
pub async fn run(ctx: &Ctx) -> Result<()> {
    let rows: Vec<ProviderRow> = constants::REMOTE_PROVIDER_TYPES
        .iter()
        .map(|(kind, description)| ProviderRow { kind, description })
        .collect();

    ctx.out.info(format!(
        "'{}' is also a legal type: it wraps one of these and encrypts on the \
         way through, rather than storing bytes itself",
        constants::PROVIDER_VAULT
    ));

    emit::records(ctx, &rows, || {
        emit::pairs(
            constants::CONFIG_COLUMN_TYPE,
            constants::CONFIG_COLUMN_DESCRIPTION,
            rows.iter()
                .map(|row| (row.kind.to_string(), row.description.to_string()))
                .collect(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalArgs;
    use crate::commands::config::settings;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        globals: GlobalArgs,
    }

    fn ctx(format: &str) -> Ctx {
        Ctx::new(Harness::parse_from(["dctl", "--format", format]).globals)
    }

    #[tokio::test]
    async fn every_format_is_supported() {
        for format in ["text", "json", "json-lines"] {
            assert!(run(&ctx(format)).await.is_ok(), "{format} failed");
        }
    }

    #[tokio::test]
    async fn the_listing_needs_no_configuration_file() {
        // It describes the binary, not the installation, so it must work on a
        // machine that has never run `dctl config touch`.
        assert!(run(&ctx("text")).await.is_ok());
    }

    #[test]
    fn the_list_is_not_empty_and_every_row_is_documented() {
        let rows: Vec<ProviderRow> = constants::REMOTE_PROVIDER_TYPES
            .iter()
            .map(|(kind, description)| ProviderRow { kind, description })
            .collect();
        assert!(!rows.is_empty(), "a build with no providers is useless");
        for row in &rows {
            assert!(!row.kind.is_empty());
            assert!(
                !row.description.is_empty(),
                "'{}' is undocumented",
                row.kind
            );
        }
    }

    #[test]
    fn the_json_field_is_spelled_type() {
        // It is the word that goes into the config file, so it is the word a
        // machine consumer must see.
        let row = ProviderRow {
            kind: "b2",
            description: "Backblaze B2 bucket",
        };
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["type"], "b2");
        assert!(json.get("kind").is_none());
    }

    #[test]
    fn everything_advertised_is_something_create_accepts() {
        // The drift this prevents: offering a type that `dctl config create`
        // then refuses.
        for (kind, _) in constants::REMOTE_PROVIDER_TYPES {
            assert!(
                settings::validate_type(kind).is_ok(),
                "'{kind}' is advertised but `config create` refuses it"
            );
        }
        assert!(settings::validate_type("dropbux").is_err());
    }

    #[test]
    fn the_wrapper_type_is_creatable_but_not_advertised_as_a_destination() {
        // Both halves matter: offering `vault` as a place to put data would be
        // misleading, and refusing to create one would make PLAN.md §14's
        // worked example impossible.
        assert!(settings::validate_type(constants::PROVIDER_VAULT).is_ok());
        assert!(
            !constants::REMOTE_PROVIDER_TYPES
                .iter()
                .any(|(kind, _)| *kind == constants::PROVIDER_VAULT),
            "a wrapper is not a destination"
        );
    }
}
