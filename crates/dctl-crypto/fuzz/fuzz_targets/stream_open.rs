#![no_main]
//! Fuzz the object parser/decryptor against arbitrary bytes.
//!
//! Invariant: parsing or opening attacker-controlled data must NEVER panic — it
//! may only ever return `Err`. A panic here would be a denial-of-service (or
//! worse) on untrusted input from a compromised backend.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0u8; 32];
    let _ = dctl_crypto::stream::parse_header(data);
    let _ = dctl_crypto::stream::verify_footer(data);
    let _ = dctl_crypto::stream::open(&key, data);
    if data.len() >= 8 {
        let off = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
        let _ = dctl_crypto::stream::read_range(&key, data, off, len);
    }
});
