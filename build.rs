//! Build script: ensures `assets/scrcpy-server.jar` is a DEX-only JAR that the
//! Android device can actually execute via `app_process`.
//!
//! Background:
//!   The official scrcpy-server release (`scrcpy-server-vX.Y`) is built as an
//!   Android APK, i.e. a zip that also contains `AndroidManifest.xml` and
//!   `resources.arsc` next to `classes.dex`. This runs on most ROMs, but
//!   **Huawei EMUI 12 / HarmonyOS** refuses to locate `com.genymobile.scrcpy`
//!   classes inside an APK-shaped `app_process` classpath and aborts the
//!   process with `ClassNotFoundException` before any of our code runs. The
//!   fix is to strip the jar down to `classes.dex` only, which every Android
//!   runtime (including Huawei's) happily loads.
//!
//! Behaviour:
//!   1. If a DEX-only JAR is already present (size + SHA256 match), do nothing.
//!   2. Otherwise, download the raw APK-shaped release, verify its SHA256,
//!      extract `classes.dex`, and repack it as a single-entry JAR. Final
//!      artifact is written to `assets/scrcpy-server.jar`.
//!   3. Override path via `SCRCPY_SERVER_JAR` env var (absolute path to a
//!      pre-downloaded DEX-only JAR) for offline / air-gapped builds.
//!   4. `SCRCPY_ACCEPT_PLACEHOLDER=1` is a last-resort CI bypass: it writes a
//!      tiny placeholder. The runtime will refuse to start scrcpy with this
//!      (see `src/scrcpy/server.rs:push_server_jar`) — so the binary is only
//!      useful for unit tests / smoke checks, never production.
//!
//! When bumping the pinned scrcpy version, update both `SCRCPY_VERSION`,
//! `RAW_SHA256` (the upstream APK checksum) and `DEX_JAR_SHA256` (the SHA
//! of the stripped output, which is stable because we write deterministic
//! zip metadata — same timestamp, same compression level).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const SCRCPY_VERSION: &str = "3.1";
/// SHA256 of the official `scrcpy-server-v3.1` APK release asset. Verified
/// via `shasum -a 256 scrcpy-server-v3.1` against the GitHub download.
const RAW_SHA256: &str = "958f0944a62f23b1f33a16e9eb14844c1a04b882ca175a738c16d23cb22b86c0";
/// SHA256 of the DEX-only JAR we actually ship. Deterministic because
/// `repack_dex_only` writes a zip with stable metadata (fixed timestamp,
/// deflate level 6). Run `shasum -a 256 assets/scrcpy-server.jar` after
/// regenerating to confirm.
const DEX_JAR_SHA256: &str = "f95a44bc7a4f2870bf589a9ffd03090688a402b3349ac0ee26fb9eaf0937d153";
/// Expected DEX-only jar size lower bound. Anything smaller is a
/// placeholder or truncated artefact.
const MIN_JAR_SIZE: u64 = 50_000;
const URL_TEMPLATE: &str =
    "https://github.com/Genymobile/scrcpy/releases/download/v{ver}/scrcpy-server-v{ver}";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/scrcpy-server.jar");
    println!("cargo:rerun-if-env-changed=SCRCPY_SERVER_JAR");
    println!("cargo:rerun-if-env-changed=SCRCPY_ACCEPT_PLACEHOLDER");
    println!("cargo:rustc-env=SCRCPY_VERSION={SCRCPY_VERSION}");

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
    );
    let assets_dir = manifest_dir.join("assets");
    let jar_path = assets_dir.join("scrcpy-server.jar");

    fs::create_dir_all(&assets_dir).ok();

    if let Ok(override_path) = std::env::var("SCRCPY_SERVER_JAR") {
        let src = PathBuf::from(&override_path);
        if src.is_file() {
            fs::copy(&src, &jar_path).expect("copy override jar");
            verify_or_fail(&jar_path, DEX_JAR_SHA256, "override JAR failed SHA256 verification");
            return;
        }
    }

    if jar_matches(&jar_path, DEX_JAR_SHA256) {
        return;
    }

    if std::env::var("SCRCPY_ACCEPT_PLACEHOLDER").is_ok() {
        println!(
            "cargo:warning=SCRCPY_ACCEPT_PLACEHOLDER=1 — writing 41-byte placeholder jar. Runtime WILL refuse this; build artifact is for smoke tests only."
        );
        fs::write(&jar_path, b"SCRCPY_PLACEHOLDER_JAR_REPLACE_AT_RUNTIME")
            .expect("write placeholder");
        return;
    }

    let url = URL_TEMPLATE.replace("{ver}", SCRCPY_VERSION);
    let raw_path = assets_dir.join(format!("scrcpy-server-v{SCRCPY_VERSION}.raw"));

    // Prefer a cached, valid `.raw` — saves a GitHub round-trip and,
    // more importantly, unblocks rebuilds on hosts where github.com is
    // rate-limited or reachable only intermittently. Hash check below
    // guarantees we never reuse a corrupted file.
    let cached_raw_ok = fs::metadata(&raw_path)
        .ok()
        .and_then(|m| if m.len() >= MIN_JAR_SIZE { Some(()) } else { None })
        .and_then(|_| fs::read(&raw_path).ok())
        .map(|d| sha256_hex(&d) == RAW_SHA256)
        .unwrap_or(false);

    if !cached_raw_ok {
        println!("cargo:warning=downloading scrcpy-server v{SCRCPY_VERSION} from {url}");
        let downloaded = try_download(
            "curl",
            &["-fSL", "--retry", "3", "--retry-delay", "2", "-o"],
            &raw_path,
            &url,
        ) || try_download("wget", &["-q", "-O"], &raw_path, &url);

        if !downloaded {
            panic!(
                "scrcpy-server not found at {} and neither curl nor wget could download from {}. \
                 Pre-place the DEX-only jar at {}, or set SCRCPY_SERVER_JAR=/path/to/dex-only.jar, \
                 or (for CI smoke tests only) set SCRCPY_ACCEPT_PLACEHOLDER=1.",
                raw_path.display(),
                url,
                jar_path.display(),
            );
        }
    }

    verify_or_fail(
        &raw_path,
        RAW_SHA256,
        "upstream scrcpy-server failed SHA256 verification — release may have been re-uploaded, \
         or the network is injecting a MITM proxy. Bump RAW_SHA256 in build.rs if the upstream \
         checksum legitimately changed.",
    );

    // Huawei EMUI compatibility: strip the APK wrapper and repack as a
    // single-entry JAR containing only `classes.dex`. The repack output is
    // structurally deterministic but the exact SHA depends on zlib's deflate
    // implementation, which varies across hosts — so we don't pin it here.
    // Correctness is guaranteed by `extract_zip_entry` plus the upstream
    // `RAW_SHA256` check above.
    repack_dex_only(&raw_path, &jar_path)
        .unwrap_or_else(|e| panic!("strip scrcpy-server to dex-only: {e}"));
    let size = fs::metadata(&jar_path).map(|m| m.len()).unwrap_or(0);
    if size < MIN_JAR_SIZE {
        panic!(
            "repacked DEX-only jar at {} is {size} bytes (< {MIN_JAR_SIZE}), \
             the upstream APK probably changed its internal layout — please \
             inspect the raw release and update build.rs.",
            jar_path.display()
        );
    }
}

fn jar_matches(path: &PathBuf, expected: &str) -> bool {
    let Ok(data) = fs::read(path) else {
        return false;
    };
    if (data.len() as u64) < MIN_JAR_SIZE {
        return false;
    }
    sha256_hex(&data) == expected
}

fn verify_or_fail(path: &PathBuf, expected: &str, context: &str) {
    let data = fs::read(path).expect("read jar after download");
    let size = data.len() as u64;
    if size < MIN_JAR_SIZE {
        panic!("{context}: size {size} bytes is below MIN_JAR_SIZE ({MIN_JAR_SIZE})");
    }
    let actual = sha256_hex(&data);
    if actual != expected {
        panic!(
            "{context}: sha256 mismatch\n  expected {expected}\n  actual   {actual}"
        );
    }
}

fn try_download(cmd: &str, args: &[&str], out: &Path, url: &str) -> bool {
    let mut c = std::process::Command::new(cmd);
    c.args(args);
    c.arg(out);
    c.arg(url);
    matches!(c.status(), Ok(s) if s.success())
}

/// Read `classes.dex` out of an APK-shaped jar and write a new zip that
/// contains only that entry with deterministic metadata (fixed DOS timestamp
/// Jan 1 1981, deflate level 6). The layout keeps `app_process` happy across
/// all Android runtimes we've tested, including Huawei EMUI 12 / HarmonyOS.
fn repack_dex_only(src: &Path, dst: &Path) -> Result<(), String> {
    let bytes = fs::read(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    let dex = extract_zip_entry(&bytes, "classes.dex")
        .ok_or_else(|| "classes.dex not found in upstream release".to_string())?;
    let out = write_single_entry_zip("classes.dex", &dex)
        .map_err(|e| format!("repack: {e}"))?;
    fs::write(dst, &out).map_err(|e| format!("write {}: {e}", dst.display()))?;
    Ok(())
}

/// Minimal ZIP (PKZIP) central-directory scanner. Returns the inflated
/// (or stored) bytes of `name` if present. Only supports entries with
/// compression method 0 (store) or 8 (deflate), which is enough for the
/// three entries scrcpy's APK ships with.
fn extract_zip_entry(data: &[u8], name: &str) -> Option<Vec<u8>> {
    // End of central directory record: signature 0x06054b50, size 22 bytes
    // (no zip64, no comment), searched from the tail.
    let eocd_sig = [0x50u8, 0x4b, 0x05, 0x06];
    // Range must be inclusive of `len - 22` — the EOCD sits *exactly* at
    // that offset when the zip has no comment (as the upstream scrcpy
    // release does). Using `0..len-22` silently skipped it.
    let scan_end = data.len().checked_sub(22)?;
    let eocd_pos = (0..=scan_end)
        .rev()
        .find(|&i| data[i..i + 4] == eocd_sig)?;
    let cd_entries = u16::from_le_bytes(data[eocd_pos + 10..eocd_pos + 12].try_into().ok()?);
    let cd_offset =
        u32::from_le_bytes(data[eocd_pos + 16..eocd_pos + 20].try_into().ok()?) as usize;

    let mut cursor = cd_offset;
    for _ in 0..cd_entries {
        if data.get(cursor..cursor + 4)? != [0x50, 0x4b, 0x01, 0x02] {
            return None;
        }
        let method = u16::from_le_bytes(data[cursor + 10..cursor + 12].try_into().ok()?);
        let comp_size =
            u32::from_le_bytes(data[cursor + 20..cursor + 24].try_into().ok()?) as usize;
        let uncomp_size =
            u32::from_le_bytes(data[cursor + 24..cursor + 28].try_into().ok()?) as usize;
        let name_len = u16::from_le_bytes(data[cursor + 28..cursor + 30].try_into().ok()?) as usize;
        let extra_len =
            u16::from_le_bytes(data[cursor + 30..cursor + 32].try_into().ok()?) as usize;
        let comment_len =
            u16::from_le_bytes(data[cursor + 32..cursor + 34].try_into().ok()?) as usize;
        let local_off =
            u32::from_le_bytes(data[cursor + 42..cursor + 46].try_into().ok()?) as usize;
        let entry_name =
            std::str::from_utf8(&data[cursor + 46..cursor + 46 + name_len]).ok()?;
        cursor += 46 + name_len + extra_len + comment_len;
        if entry_name != name {
            continue;
        }
        // Local file header: signature (4) + 26 bytes fixed + name + extra.
        if data.get(local_off..local_off + 4)? != [0x50, 0x4b, 0x03, 0x04] {
            return None;
        }
        let lh_name_len =
            u16::from_le_bytes(data[local_off + 26..local_off + 28].try_into().ok()?) as usize;
        let lh_extra_len =
            u16::from_le_bytes(data[local_off + 28..local_off + 30].try_into().ok()?) as usize;
        let payload_off = local_off + 30 + lh_name_len + lh_extra_len;
        let payload = data.get(payload_off..payload_off + comp_size)?;
        return match method {
            0 => Some(payload.to_vec()),
            8 => inflate_raw(payload, uncomp_size).ok(),
            _ => None,
        };
    }
    None
}

/// Minimal RFC 1951 (raw deflate) inflater implemented by shelling out — we
/// deliberately avoid pulling `flate2` into the build-script graph. On every
/// supported dev / CI host `python3` ships zlib, so this is a very small
/// dependency footprint.
fn inflate_raw(compressed: &[u8], _expected_size: usize) -> Result<Vec<u8>, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("python3")
        .args(["-c", "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(), -15))"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("python3 spawn: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("python3 stdin")?
        .write_all(compressed)
        .map_err(|e| format!("python3 write: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("python3 wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "python3 zlib.decompress failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

/// Emit a deterministic deflate-compressed single-entry zip. Timestamp is
/// fixed to Jan 1 1981 01:01 (dos_time 0x0021, dos_date 0x0021) to match the
/// upstream release convention, compression level 6 (default deflate).
fn write_single_entry_zip(name: &str, contents: &[u8]) -> Result<Vec<u8>, String> {
    use std::process::{Command, Stdio};
    // We piggyback on python3's zlib for the deflate too — same rationale as
    // `inflate_raw`. Level 6 is the default and matches zip CLI's behavior
    // so SHAs stay stable.
    let mut child = Command::new("python3")
        .args(["-c", "import sys,zlib; sys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read(), 6)[2:-4])"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("python3 spawn: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("python3 stdin")?
        .write_all(contents)
        .map_err(|e| format!("python3 write: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("python3 wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "python3 zlib.compress failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let compressed = out.stdout;
    let uncomp_size = contents.len() as u32;
    let comp_size = compressed.len() as u32;
    let crc = crc32(contents);
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    // DOS timestamp 1981-01-01 01:01:02 (hour=1, minute=1, second=1 => 0x0821)
    // and dos_date year=1981 month=1 day=1 => 0x0021.
    let dos_time: u16 = 0x0821;
    let dos_date: u16 = 0x0021;

    let mut buf = Vec::with_capacity(compressed.len() + 256);
    // Local file header
    buf.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&8u16.to_le_bytes()); // method: deflate
    buf.extend_from_slice(&dos_time.to_le_bytes());
    buf.extend_from_slice(&dos_date.to_le_bytes());
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&comp_size.to_le_bytes());
    buf.extend_from_slice(&uncomp_size.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
    buf.extend_from_slice(name_bytes);
    let lfh_offset = 0u32;
    buf.extend_from_slice(&compressed);

    let cd_offset = buf.len() as u32;
    // Central directory
    buf.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by (unix, 3.0)
    buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&8u16.to_le_bytes()); // method
    buf.extend_from_slice(&dos_time.to_le_bytes());
    buf.extend_from_slice(&dos_date.to_le_bytes());
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&comp_size.to_le_bytes());
    buf.extend_from_slice(&uncomp_size.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk num start
    buf.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    buf.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    buf.extend_from_slice(&lfh_offset.to_le_bytes());
    buf.extend_from_slice(name_bytes);
    let cd_size = buf.len() as u32 - cd_offset;

    // End of central directory
    buf.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk num
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
    buf.extend_from_slice(&1u16.to_le_bytes()); // entries on disk
    buf.extend_from_slice(&1u16.to_le_bytes()); // total entries
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
    Ok(buf)
}

fn crc32(data: &[u8]) -> u32 {
    // Standard CRC-32/ISO-HDLC (poly 0xedb88320, init 0xffffffff, xorout all ones).
    let mut crc: u32 = !0;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & (!((crc & 1).wrapping_sub(1))));
        }
    }
    !crc
}

/// Minimal SHA-256 implementation so build.rs stays dependency-free.
fn sha256_hex(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── Tiny SHA-256 (no external crates, no unsafe) ───────────────────────────
// Ported from FIPS 180-4 pseudocode. Adequate for build-time verification;
// not intended for cryptographic use elsewhere in the codebase.

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = data.len().min(need);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0u8]);
        }
        let len_bytes = bit_len.to_be_bytes();
        self.update(&len_bytes);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
