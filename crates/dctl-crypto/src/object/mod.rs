//! DSF1 self-describing encrypted object (`crates/dctl-decode/FORMAT.md` §3–§4).
//!
//! Each object embeds its own root-wrapped DEK + encrypted per-item metadata +
//! chunked, seekable payload, so it decodes standalone from `{root key, object}` with
//! no index. Chunks and metadata share the DEK in disjoint nonce spaces (byte[23]
//! marker); every wrap binds the full 68-byte head. The symmetric `kem_id=0` owner path
//! is [`seal`]/[`open`]; the `kem_id=1` recipient-hybrid path (§12) is
//! [`seal_to_recipients`]/[`open_as_recipient`].
//!
//! Reads come in three shapes, and the choice is a cost decision the caller owns:
//! [`open`] buffers the whole plaintext, [`open_reader`]/[`open_stream`] stream it at
//! `O(chunk_size)`, and [`range`] serves a byte window by fetching only the chunks that
//! cover it — the §3 "Random-access" property, and the only one of the three whose cost
//! is `O(window)` rather than `O(object)` in *egress* as well as memory.

mod head;
mod meta;
mod nonce;
pub mod range;
mod recipient;
mod seal;
mod sealer;
mod stream;

pub use head::{Head, parse_head};
pub use meta::{Metadata, build_metadata, parse_metadata};
pub use range::{ChunkSpan, HeaderExtent, RangeHeader, header_extent};
pub use recipient::{open_as_recipient, open_with_kw, seal_to_recipients};
pub use seal::{Opened, open, seal};
pub use sealer::{PlannedSeal, seal_stream};
pub use stream::{open_reader, open_stream};
