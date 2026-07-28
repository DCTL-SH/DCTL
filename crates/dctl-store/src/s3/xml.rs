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
#[derive(Debug)]
pub(crate) struct Listing {
    pub items: Vec<(String, u64)>,
    pub next_token: Option<String>,
}

/// The root element every `ListObjectsV2` response has, whatever the provider.
///
/// Its presence — opened *and* closed — is what tells a listing apart from a
/// truncated one; see [`parse_list`].
const LIST_ROOT: &str = "ListBucketResult";

/// Parse a `ListObjectsV2` page.
///
/// # Errors
///
/// [`StoreError::Backend`] when the body is not a complete listing.
///
/// That check is the whole reason this function returns a `Result` at all, and it
/// was missing. `quick_xml` reports end-of-input as an ordinary `Eof` event, so a
/// body that stopped half way through — a connection dropped mid-response, a
/// proxy's HTML interstitial served with a 200, a gateway timeout page — parsed
/// as a listing with **no objects in it** and no error anywhere. An empty listing
/// is the worst wrong answer this parser can give: `copy s3:bucket /out` reports
/// `Files: 0 / 0` and exits 0, a nightly `sync` re-uploads a tree the bucket
/// already holds, and `sync --delete` in the other direction removes a
/// destination to match a source it never actually read.
///
/// So the parse now has to see the root element open and close. Nothing else in
/// this workspace would have noticed: `tests/s3_live.rs` has never run.
pub(crate) fn parse_list(xml: &str) -> Result<Listing> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut items = Vec::new();
    let mut next_token = None;
    let mut current: Option<String> = None;
    let mut in_contents = false;
    let mut key: Option<String> = None;
    let mut size: Option<u64> = None;
    let mut root_opened = false;
    let mut root_closed = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name());
                if name == LIST_ROOT {
                    root_opened = true;
                }
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
                let name = local_name(e.name());
                if name == LIST_ROOT {
                    root_closed = true;
                }
                if name == "Contents" {
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

    if !root_opened || !root_closed {
        return Err(StoreError::Backend(format!(
            "s3 listing response is not a complete <{LIST_ROOT}> document ({} bytes read); \
             it was truncated, or the endpoint answered with something else",
            xml.len()
        )));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `ListObjectsV2` body, as AWS documents it — namespaced root,
    /// `CommonPrefixes` beside `Contents`, and fields DCTL does not read mixed in
    /// with the two it does.
    const LIST_RESPONSE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix>photos/</Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
  <Contents>
    <Key>photos/2020/a b.jpg</Key>
    <LastModified>2020-01-01T00:00:00.000Z</LastModified>
    <ETag>&quot;70ee1738b6b21e2c8a43f3a5ab0eee71&quot;</ETag>
    <Size>4096</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>photos/2021/&amp;.raw</Key>
    <LastModified>2021-06-01T12:00:00.000Z</LastModified>
    <Size>0</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <CommonPrefixes>
    <Prefix>photos/2022/</Prefix>
  </CommonPrefixes>
</ListBucketResult>"#;

    /// Nothing else in this workspace exercises the S3 listing parser.
    ///
    /// `tests/s3_live.rs` has never run — no S3 or R2 credentials have existed in
    /// this environment — so until this test, a listing parser that returned an
    /// empty page for every request would have passed every gate DCTL has. An
    /// empty listing is the worst possible wrong answer: `copy` reports zero files
    /// and exit 0, `sync` re-uploads a whole tree it already holds, and `purge`
    /// reports success over objects it never saw.
    #[test]
    fn a_listing_page_yields_every_object_and_its_continuation() {
        let page = parse_list(LIST_RESPONSE).expect("a documented response parses");
        assert_eq!(
            page.items,
            vec![
                ("photos/2020/a b.jpg".to_string(), 4096),
                ("photos/2021/&.raw".to_string(), 0),
            ],
            "both objects, with their sizes, and their names unescaped"
        );
        assert_eq!(
            page.next_token.as_deref(),
            Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM="),
            "a page that stops at the token has stopped mid-bucket"
        );
    }

    #[test]
    fn a_common_prefix_is_not_mistaken_for_an_object() {
        // `CommonPrefixes` carries a `<Prefix>` and no `<Key>`; a parser that
        // took every element it saw would invent a zero-byte object for every
        // directory, and `sync --delete` would then remove them.
        let page = parse_list(LIST_RESPONSE).expect("parses");
        assert!(
            !page.items.iter().any(|(key, _)| key.contains("2022")),
            "got {:?}",
            page.items
        );
    }

    #[test]
    fn a_final_page_reports_no_continuation() {
        // The stopping condition for the whole listing walk. A parser that always
        // produced a token would loop forever; one that never produced a token
        // would silently list only the first thousand objects.
        let last = LIST_RESPONSE
            .replace(
                "<NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>",
                "",
            )
            .replace("<IsTruncated>true</IsTruncated>", "<IsTruncated>false</IsTruncated>");
        let page = parse_list(&last).expect("parses");
        assert_eq!(page.next_token, None);
        assert_eq!(page.items.len(), 2);
    }

    #[test]
    fn an_empty_bucket_is_an_empty_page_rather_than_an_error() {
        let page = parse_list(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <KeyCount>0</KeyCount>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>"#,
        )
        .expect("parses");
        assert!(page.items.is_empty());
        assert_eq!(page.next_token, None);
    }

    /// A body that is not a whole listing must not look like an empty bucket.
    ///
    /// This test failed when it was written, against the parser as shipped: every
    /// case below returned `Ok` with no items. That is the worst wrong answer
    /// available here — `copy` reports `Files: 0 / 0` and exits 0, and
    /// `sync --delete` empties a destination to match a source it never read.
    /// Nothing else could have caught it: `tests/s3_live.rs` has never run.
    #[test]
    fn a_body_that_is_not_a_whole_listing_is_reported_rather_than_read_as_empty() {
        let truncated = [
            // A connection dropped mid-response.
            "<ListBucketResult><Contents><Key>a</Key><Size>1</Size></Contents>",
            // A proxy or gateway answering with a page of its own.
            "<html><body><h1>504 Gateway Time-out</h1></body></html>",
            // Nothing at all, which is what a zero-length 200 looks like.
            "",
            // A different S3 document, correctly formed but not a listing.
            "<Error><Code>AccessDenied</Code></Error>",
        ];
        for body in truncated {
            let error = parse_list(body)
                .map(|listing| listing.items)
                .expect_err(&format!("must not be read as a listing: {body:?}"));
            assert!(matches!(error, StoreError::Backend(_)), "got {error:?}");
        }
    }

    #[test]
    fn a_tag_is_extracted_by_its_exact_name() {
        // `UploadId` is what every part of a multipart upload is addressed by,
        // and an error `Code` is what a failure is classified from.
        let create = r#"<InitiateMultipartUploadResult><Bucket>b</Bucket>\
<Key>k</Key><UploadId>VXBsb2FkIElEIGZvciA2aWWpbmc=</UploadId>\
</InitiateMultipartUploadResult>"#;
        assert_eq!(
            extract_tag(create, "UploadId").as_deref(),
            Some("VXBsb2FkIElEIGZvciA2aWWpbmc=")
        );
        assert_eq!(
            extract_tag("<Error><Code>NoSuchKey</Code></Error>", "Code").as_deref(),
            Some("NoSuchKey")
        );
        assert_eq!(
            extract_tag("<Error><Code>x</Code></Error>", "Message"),
            None
        );
    }
}
