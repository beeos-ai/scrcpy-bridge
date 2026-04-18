//! Build script: ensures `assets/scrcpy-server.jar` is a real, version-pinned
//! scrcpy-server JAR so `include_bytes!` embeds something the Android device
//! can actually execute.
//!
//! Behaviour:
//!   1. If a real JAR is already present (size + SHA256 match), do nothing.
//!   2. Otherwise, download it from the official release URL and verify SHA256.
//!   3. Override path via `SCRCPY_SERVER_JAR` env var (absolute path to a
//!      pre-downloaded JAR) for offline / air-gapped builds.
//!   4. `SCRCPY_ACCEPT_PLACEHOLDER=1` is a last-resort CI bypass: it writes a
//!      tiny placeholder. The runtime will refuse to start scrcpy with this
//!      (see `src/scrcpy/server.rs:push_server_jar`) — so the binary is only
//!      useful for unit tests / smoke checks, never production.
//!
//! When bumping the pinned scrcpy version, update both `SCRCPY_VERSION` and
//! `SHA256` below. Compute SHA256 with:
//!   `shasum -a 256 scrcpy-server-vX.Y`

use std::fs;
use std::path::PathBuf;

const SCRCPY_VERSION: &str = "3.1";
/// SHA256 of the official `scrcpy-server-v3.1` release asset, verified via
/// `shasum -a 256 scrcpy-server-v3.1` against the GitHub release download.
const SHA256: &str = "958f0944a62f23b1f33a16e9eb14844c1a04b882ca175a738c16d23cb22b86c0";
/// Expected file size in bytes. Anything smaller than this is treated as a
/// placeholder or truncated download.
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
            verify_or_fail(&jar_path, "override JAR failed SHA256 verification");
            return;
        }
    }

    if jar_matches(&jar_path) {
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
    println!(
        "cargo:warning=downloading scrcpy-server.jar v{SCRCPY_VERSION} from {url}"
    );

    let downloaded = try_download("curl", &["-fSL", "--retry", "3", "--retry-delay", "2", "-o"], &jar_path, &url)
        || try_download("wget", &["-q", "-O"], &jar_path, &url);

    if !downloaded {
        panic!(
            "scrcpy-server.jar not found at {} and neither curl nor wget could download from {}. \
             Pre-place the file and retry, or set SCRCPY_SERVER_JAR=/path/to/jar, \
             or (for CI smoke tests only) set SCRCPY_ACCEPT_PLACEHOLDER=1.",
            jar_path.display(),
            url
        );
    }

    verify_or_fail(
        &jar_path,
        "downloaded JAR failed SHA256 verification — release may have been re-uploaded, \
         or the network is injecting a MITM proxy. Bump SHA256 in build.rs if the upstream \
         checksum legitimately changed.",
    );
}

fn jar_matches(path: &PathBuf) -> bool {
    let Ok(data) = fs::read(path) else {
        return false;
    };
    if (data.len() as u64) < MIN_JAR_SIZE {
        return false;
    }
    sha256_hex(&data) == SHA256
}

fn verify_or_fail(path: &PathBuf, context: &str) {
    let data = fs::read(path).expect("read jar after download");
    let size = data.len() as u64;
    if size < MIN_JAR_SIZE {
        panic!(
            "{context}: size {size} bytes is below MIN_JAR_SIZE ({MIN_JAR_SIZE})"
        );
    }
    let actual = sha256_hex(&data);
    if actual != SHA256 {
        panic!(
            "{context}: sha256 mismatch\n  expected {SHA256}\n  actual   {actual}"
        );
    }
}

fn try_download(cmd: &str, args: &[&str], out: &PathBuf, url: &str) -> bool {
    let mut c = std::process::Command::new(cmd);
    c.args(args);
    c.arg(out);
    c.arg(url);
    matches!(c.status(), Ok(s) if s.success())
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
