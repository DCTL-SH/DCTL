//! Minimal parsing of the few S3 XML responses DCTL needs.

use quick_xml::Reader;
use quick_xml::events::Event;
use quick_xml::name::QName;

use crate::error::{Result, StoreError};

/// Local element name (namespace prefix stripped).
fn local_name(name: QName) -> String {
    let full = name.as_ref();
    let local = match full.iter().rposition(|&b| b == b':') {
        Some(i) => &full[i + 1..],
        None => full,
    };
    String::from_utf8_lossy(local).into_owned()
}

/// Parsed `ListObjectsV2` page: `(key, size)` items plus a continuation token.
pub(crate) struct Listing {
    pub items: Vec<(String, u64)>,
    pub next_token: Option<String>,
}

pub(crate) fn parse_list(xml: &str) -> Result<Listing> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut items = Vec::new();
    let mut next_token = None;
    let mut current: Option<String> = None;
    let mut in_contents = false;
    let mut key: Option<String> = None;
    let mut size: Option<u64> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name());
                if name == "Contents" {
                    in_contents = true;
                    key = None;
                    size = None;
                }
                current = Some(name);
            }
            Ok(Event::Text(t)) => {
                if let Some(name) = &current {
                    let text = t.unescape().unwrap_or_default().into_owned();
                    match name.as_str() {
                        "Key" if in_contents => key = Some(text),
                        "Size" if in_contents => size = text.parse().ok(),
                        "NextContinuationToken" => next_token = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                if local_name(e.name()) == "Contents" {
                    in_contents = false;
                    if let (Some(k), Some(s)) = (key.take(), size.take()) {
                        items.push((k, s));
                    }
                }
                current = None;
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(StoreError::Backend(format!("s3 xml parse: {err}"))),
            _ => {}
        }
    }
    Ok(Listing { items, next_token })
}

/// Extract the text of the first `<tag>...</tag>` (used for `UploadId`, error codes).
pub(crate) fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}
