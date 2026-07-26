//! The wire shape of one listed object.
//!
//! Field names are rclone's, in rclone's capitalisation, because the scripts
//! this tool has to accept were written against `rclone lsjson` and
//! `jq -r '.[].Path'` should keep working after the binary is swapped. The
//! vocabulary is the interoperability surface; the field *values* are DCTL's.
//!
//! ## Paths are relative to the listing root
//!
//! `Path` is what lies below the spec the command was given, exactly as rclone
//! defines it: `dctl lsjson vault:photos` reports `2024/a.jpg`, not
//! `photos/2024/a.jpg`. Re-address an entry by re-joining it to the spec that
//! produced it. The alternative — absolute vault paths — would be more
//! convenient at exactly one call site and would break every ported script.
//!
//! ## What is deliberately absent
//!
//! No object key, no wrapped DEK, no chunk map. A `lsjson` dump is the artefact
//! most likely to be pasted into a ticket or committed to a repository, and the
//! plaintext-path-to-object-key mapping is precisely the metadata the storage
//! design exists to withhold (`PLAN.md` §2). [`Entry`] does not carry them, so
//! this shape cannot leak them by omission of a `skip_serializing`.
//!
//! ## `Hashes` is a map, not a string
//!
//! One algorithm is recorded today ([`LISTING_HASH_ALGORITHM`]). A map means a
//! second one can be added without a consumer that reads `Hashes.blake3` ever
//! noticing, which a bare `Hash: "…"` field would not allow.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::constants::LISTING_HASH_ALGORITHM;

use super::entry::Entry;
use super::time::rfc3339;

/// One entry, as a machine reads it.
///
/// Borrows from the [`Entry`] it describes: `lsjson` over ten million objects
/// serialises one of these per object, and cloning two strings each time would
/// be the whole cost of the command.
#[derive(Debug, Serialize)]
pub struct JsonEntry<'a> {
    /// Path below the listing root.
    #[serde(rename = "Path")]
    pub path: &'a str,
    /// Final path component.
    #[serde(rename = "Name")]
    pub name: &'a str,
    /// Plaintext size in bytes; for a directory, the total beneath it.
    #[serde(rename = "Size")]
    pub size: u64,
    /// Last modification, RFC 3339 in UTC, or `null` when the index recorded
    /// none. Null rather than the epoch: "unknown" and "1970" are different
    /// answers and a consumer must be able to tell them apart.
    #[serde(rename = "ModTime")]
    pub mod_time: Option<String>,
    /// Whether the entry stands for a directory.
    #[serde(rename = "IsDir")]
    pub is_dir: bool,
    /// Plaintext content hashes by algorithm name. Empty for a directory, which
    /// has no content of its own to hash.
    #[serde(rename = "Hashes")]
    pub hashes: BTreeMap<&'static str, &'a str>,
}

impl<'a> JsonEntry<'a> {
    /// Describe `entry`.
    #[must_use]
    pub fn new(entry: &'a Entry) -> Self {
        let mut hashes = BTreeMap::new();
        if let Some(hash) = entry.content_hash() {
            hashes.insert(LISTING_HASH_ALGORITHM, hash);
        }

        Self {
            path: entry.relative(),
            name: entry.name(),
            size: entry.size(),
            mod_time: entry.modified_unix().map(rfc3339),
            is_dir: entry.is_dir(),
            hashes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listing::tests_support::listed;
    use serde_json::{Value, json};

    fn value(entry: &Entry) -> Value {
        serde_json::to_value(JsonEntry::new(entry)).expect("a listing entry always serialises")
    }

    #[test]
    fn an_object_serialises_to_the_documented_shape() {
        let entry = Entry::from_source(listed("photos/2024/a.jpg", 1024, Some(0)), "photos");
        assert_eq!(
            value(&entry),
            json!({
                "Path": "2024/a.jpg",
                "Name": "a.jpg",
                "Size": 1024,
                "ModTime": "1970-01-01T00:00:00Z",
                "IsDir": false,
                "Hashes": { "blake3": "abcd" },
            })
        );
    }

    #[test]
    fn the_field_set_is_exactly_the_published_one() {
        // Adding a field is a compatibility change; this is the tripwire.
        let entry = Entry::from_source(listed("a.txt", 1, None), "");
        let Value::Object(map) = value(&entry) else {
            panic!("an entry serialises as an object");
        };
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["Hashes", "IsDir", "ModTime", "Name", "Path", "Size"]
        );
    }

    #[test]
    fn an_unknown_modification_time_is_null_not_the_epoch() {
        let entry = Entry::from_source(listed("a.txt", 1, None), "");
        assert_eq!(value(&entry)["ModTime"], Value::Null);
    }

    #[test]
    fn a_directory_carries_no_hashes_and_no_time() {
        let dir = Entry::directory("photos/2024".into(), "photos", 4096);
        assert_eq!(
            value(&dir),
            json!({
                "Path": "2024",
                "Name": "2024",
                "Size": 4096,
                "ModTime": Value::Null,
                "IsDir": true,
                "Hashes": {},
            })
        );
    }

    #[test]
    fn no_object_key_or_key_material_can_reach_the_wire() {
        // The record carries both; the shape must not be able to name them.
        let entry = Entry::from_source(listed("a.txt", 1, Some(0)), "");
        let encoded = serde_json::to_string(&JsonEntry::new(&entry)).unwrap();
        assert!(!encoded.contains("object_key"));
        assert!(!encoded.contains("o/a.txt"), "the object key leaked");
        assert!(!encoded.to_lowercase().contains("dek"));
    }

    #[test]
    fn a_record_at_the_listing_root_reports_its_own_name() {
        let entry = Entry::from_source(listed("a.txt", 1, None), "");
        let value = value(&entry);
        assert_eq!(value["Path"], "a.txt");
        assert_eq!(value["Name"], "a.txt");
    }
}
