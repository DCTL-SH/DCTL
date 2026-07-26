//! DSF1 self-describing encrypted object (`docs/FORMAT.md` §3–§4).
//!
//! Each object embeds its own root-wrapped DEK + encrypted per-item metadata +
//! chunked, seekable payload, so it decodes standalone from `{root key, object}` with
//! no index. Chunks and metadata share the DEK in disjoint nonce spaces (byte[23]
//! marker); every wrap binds the full 68-byte head. The symmetric `kem_id=0` owner path
//! is [`seal`]/[`open`]; the `kem_id=1` recipient-hybrid path (§12) is
//! [`seal_to_recipients`]/[`open_as_recipient`].

mod head;
mod meta;
mod nonce;
mod recipient;
mod seal;
mod stream;

pub use head::{Head, parse_head};
pub use meta::{Metadata, build_metadata, parse_metadata};
pub use recipient::{open_as_recipient, seal_to_recipients};
pub use seal::{Opened, open, seal};
pub use stream::{open_reader, open_stream, seal_stream};
