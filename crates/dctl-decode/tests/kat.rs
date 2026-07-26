//! Known-answer cross-validation of the C99 reference decoder against the Rust
//! implementation for the **v1** on-disk format (`DKE1` slot-list envelope + `DSF1`
//! self-describing object).
//!
//! Every vector is produced by the Rust encoder (`dctl-crypto`) and then decoded by
//! the compiled standalone C decoder (`reference/dctl-decode.c`), so the two
//! independent implementations are proven to agree byte-for-byte:
//!
//! * `argon2id_matches_rfc9106_vector` — the format-independent Argon2id KDF port
//!   vs. the official RFC 9106 vector.
//! * `root_mode_boundary_roundtrip` — DSF1 decode at every chunk boundary size
//!   (empty, sub-chunk, exact, +1, multi-chunk), using `--root` (skips Argon2).
//! * `password_mode_full_chain` — the whole chain: DKE1 envelope + password →
//!   Argon2id KEK → unwrap root → DSF1 → plaintext, plus wrong-password rejection.
//! * `negative_vectors` — tampered head, tampered chunk, truncation, and a wrong
//!   root are all REJECTED (non-zero exit).
//!
//! If `cc` is unavailable the tests skip (print a notice) rather than failing.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use dctl_crypto::constants::{KDF_ID_ARGON2ID, SLOT_TYPE_PASSWORD};
use dctl_crypto::envelope::{Envelope, generate_vault_id, serialize, wrap_slot};
use dctl_crypto::kdf::{derive_kek_with_params, generate_salt};
use dctl_crypto::object::{Metadata, seal, seal_stream};
use tempfile::TempDir;

const RFC9106_ARGON2ID_TAG: &str =
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

/// Small Argon2id params (m=64 KiB, t=1, p=1) — keep password-mode KATs fast while
/// still exercising the full derive-KEK-then-unwrap-root chain against the C port.
const KAT_M_COST: u32 = 64;
const KAT_T_COST: u32 = 1;
const KAT_P_LANES: u32 = 1;

// ───────────────────────────────── test harness helpers ─────────────────────────

fn cc_available() -> bool {
    Command::new("cc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn compile(dir: &Path) -> PathBuf {
    let bin = dir.join("dctl-decode");
    let status = Command::new("cc")
        .args(["-O2", "-std=c99", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&bin)
        .arg(dctl_decode::REFERENCE_C_PATH)
        .status()
        .expect("failed to invoke cc");
    assert!(
        status.success(),
        "reference C decoder did not compile cleanly"
    );
    bin
}

/// A deterministic 32-byte root for the round-trip tests.
fn test_root() -> [u8; 32] {
    let mut r = [0u8; 32];
    for (i, b) in r.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    r
}

/// Deterministic pseudo-random plaintext of length `n`.
fn plaintext(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// Seal `pt` into a DSF1 object under `root` (symmetric `kem_id=0` path).
fn seal_obj(root: &[u8; 32], pt: &[u8], chunk_size: u32) -> Vec<u8> {
    seal(root, pt, &Metadata::new("f.bin"), chunk_size).expect("seal")
}

/// Seal `pt` via the constant-memory streaming sealer (`seal_stream`) over a `Cursor`.
/// Must yield a DSF1 object the C reference decoder accepts byte-for-byte.
fn seal_obj_stream(root: &[u8; 32], pt: &[u8], chunk_size: u32) -> Vec<u8> {
    let mut input = Cursor::new(pt.to_vec());
    let mut out = Vec::new();
    seal_stream(
        root,
        &mut input,
        pt.len() as u64,
        &Metadata::new("f.bin"),
        chunk_size,
        &mut out,
    )
    .expect("seal_stream");
    out
}

/// Build a single-password-slot DKE1 envelope that wraps `root` under `password`.
fn make_envelope(password: &str, root: &[u8; 32]) -> Vec<u8> {
    let vault_id = generate_vault_id();
    let salt = generate_salt();
    let kek: [u8; 32] =
        *derive_kek_with_params(password, None, &salt, KAT_M_COST, KAT_T_COST, KAT_P_LANES)
            .expect("derive_kek");
    let slot = wrap_slot(
        &kek,
        root,
        &vault_id,
        SLOT_TYPE_PASSWORD,
        KDF_ID_ARGON2ID,
        KAT_M_COST,
        KAT_T_COST,
        KAT_P_LANES,
        salt.to_vec(),
        Vec::new(),
    )
    .expect("wrap_slot");
    let env = Envelope {
        vault_id,
        slots: vec![slot],
    };
    serialize(&env).expect("serialize envelope")
}

/// Decode `obj` under `--root <hex>`. Returns the plaintext on success, `None` if the
/// C decoder exits non-zero (rejection).
fn decode_root(bin: &Path, dir: &Path, obj: &[u8], root: &[u8; 32]) -> Option<Vec<u8>> {
    let obj_path = dir.join("obj.bin");
    let out_path = dir.join("plain.bin");
    fs::write(&obj_path, obj).unwrap();
    let _ = fs::remove_file(&out_path);
    let status = Command::new(bin)
        .arg("--root")
        .arg(hex::encode(root))
        .arg("--in")
        .arg(&obj_path)
        .arg("--out")
        .arg(&out_path)
        .status()
        .unwrap();
    if status.success() {
        Some(fs::read(&out_path).unwrap())
    } else {
        None
    }
}

/// Decode `obj` under `--envelope <env> --password <pw>`. Returns plaintext on success.
fn decode_password(
    bin: &Path,
    dir: &Path,
    obj: &[u8],
    env: &[u8],
    password: &str,
) -> Option<Vec<u8>> {
    let obj_path = dir.join("obj.bin");
    let env_path = dir.join("env.bin");
    let out_path = dir.join("plain.bin");
    fs::write(&obj_path, obj).unwrap();
    fs::write(&env_path, env).unwrap();
    let _ = fs::remove_file(&out_path);
    let status = Command::new(bin)
        .arg("--envelope")
        .arg(&env_path)
        .arg("--password")
        .arg(password)
        .arg("--in")
        .arg(&obj_path)
        .arg("--out")
        .arg(&out_path)
        .status()
        .unwrap();
    if status.success() {
        Some(fs::read(&out_path).unwrap())
    } else {
        None
    }
}

// ───────────────────────────────────── tests ────────────────────────────────────

#[test]
fn argon2id_matches_rfc9106_vector() {
    if !cc_available() {
        eprintln!("skipping KAT: no C compiler (cc) available");
        return;
    }
    let dir = TempDir::new().unwrap();
    let bin = compile(dir.path());
    let out = Command::new(&bin).arg("--argon2-kat").output().unwrap();
    assert!(out.status.success());
    let got = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        got.trim(),
        RFC9106_ARGON2ID_TAG,
        "Argon2id port disagrees with RFC 9106"
    );
}

#[test]
fn root_mode_boundary_roundtrip() {
    if !cc_available() {
        eprintln!("skipping KAT: no C compiler (cc) available");
        return;
    }
    let dir = TempDir::new().unwrap();
    let bin = compile(dir.path());
    let root = test_root();
    let chunk_size: u32 = 64;

    // Boundary sizes around `chunk_size`: empty, sub-chunk, exact, +1, multi-chunk.
    for &n in &[0usize, 1, 10, 63, 64, 65, 128, 200, 256] {
        let pt = plaintext(n);
        let obj = seal_obj(&root, &pt, chunk_size);
        let got = decode_root(&bin, dir.path(), &obj, &root)
            .unwrap_or_else(|| panic!("decode failed for size {n}"));
        assert_eq!(got, pt, "round-trip mismatch for size {n}");
    }
}

#[test]
fn stream_mode_boundary_roundtrip() {
    if !cc_available() {
        eprintln!("skipping KAT: no C compiler (cc) available");
        return;
    }
    let dir = TempDir::new().unwrap();
    let bin = compile(dir.path());
    let root = test_root();
    let chunk_size: u32 = 64;

    // The constant-memory `seal_stream` must be byte-format-identical to the buffered
    // `seal`: the same standalone C decoder decodes its output at every boundary size.
    for &n in &[0usize, 1, 10, 63, 64, 65, 128, 200, 256] {
        let pt = plaintext(n);
        let obj = seal_obj_stream(&root, &pt, chunk_size);
        let got = decode_root(&bin, dir.path(), &obj, &root)
            .unwrap_or_else(|| panic!("C decode of streamed object failed for size {n}"));
        assert_eq!(got, pt, "streamed round-trip mismatch for size {n}");
    }
}

#[test]
fn password_mode_full_chain() {
    if !cc_available() {
        eprintln!("skipping KAT: no C compiler (cc) available");
        return;
    }
    let dir = TempDir::new().unwrap();
    let bin = compile(dir.path());
    let root = test_root();
    let password = "correct-horse-battery-staple";
    let env = make_envelope(password, &root);

    // Full chain: envelope + password → Argon2id KEK → unwrap root → DSF1 → plaintext.
    let pt = plaintext(300);
    let obj = seal_obj(&root, &pt, 64);
    let got = decode_password(&bin, dir.path(), &obj, &env, password)
        .expect("password-mode decode failed");
    assert_eq!(got, pt, "password-mode round-trip mismatch");

    // Wrong password → root never recovered → rejected.
    assert!(
        decode_password(&bin, dir.path(), &obj, &env, "wrong-password").is_none(),
        "wrong password was NOT rejected"
    );
}

#[test]
fn negative_vectors() {
    if !cc_available() {
        eprintln!("skipping KAT: no C compiler (cc) available");
        return;
    }
    let dir = TempDir::new().unwrap();
    let bin = compile(dir.path());
    let root = test_root();

    // A multi-chunk object (200 bytes over 64-byte chunks → 4 chunks).
    let pt = plaintext(200);
    let obj = seal_obj(&root, &pt, 64);

    // Sanity: the untouched object decodes.
    assert_eq!(
        decode_root(&bin, dir.path(), &obj, &root).as_deref(),
        Some(pt.as_slice()),
        "baseline object should decode"
    );

    // (1) Tampered HEAD byte (file_id @ offset 52) → breaks the head-bound DEK-wrap AAD.
    let mut t_head = obj.clone();
    t_head[52] ^= 0xff;
    assert!(
        decode_root(&bin, dir.path(), &t_head, &root).is_none(),
        "tampered head byte was NOT rejected"
    );

    // (2) Tampered CHUNK ciphertext byte → per-chunk Poly1305 must fail.
    let meta_len = u32::from_le_bytes([obj[142], obj[143], obj[144], obj[145]]) as usize;
    let first_chunk_off = 146 + meta_len;
    let mut t_chunk = obj.clone();
    t_chunk[first_chunk_off + 3] ^= 0xff;
    assert!(
        decode_root(&bin, dir.path(), &t_chunk, &root).is_none(),
        "tampered chunk byte was NOT rejected"
    );

    // (3) Truncated object (drop the footer + part of the last chunk) → short read.
    let truncated = &obj[..obj.len() - 50];
    assert!(
        decode_root(&bin, dir.path(), truncated, &root).is_none(),
        "truncated object was NOT rejected"
    );

    // (4) Wrong root → DEK unwrap tag fails.
    let mut wrong = test_root();
    wrong[0] ^= 0xff;
    assert!(
        decode_root(&bin, dir.path(), &obj, &wrong).is_none(),
        "wrong root was NOT rejected"
    );
}
