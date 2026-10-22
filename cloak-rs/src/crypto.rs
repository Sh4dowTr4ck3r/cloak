use base64::Engine;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::fs;
use std::io;
use std::path::Path;

use crate::ui::cyan;

pub fn md5_hex(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode_upper(result)
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode_upper(result)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode_upper(result)
}

/// Compute independent digests concurrently only for large inputs on multi-core hosts.
pub fn all_hashes(data: &[u8]) -> [String; 3] {
    if data.len() < 1024 * 1024
        || std::thread::available_parallelism().map_or(true, |n| n.get() < 3)
    {
        return [md5_hex(data), sha1_hex(data), sha256_hex(data)];
    }
    std::thread::scope(|scope| {
        // Fall back to local computation if the OS cannot create a worker.
        let md5 = std::thread::Builder::new().spawn_scoped(scope, || md5_hex(data));
        let sha1 = std::thread::Builder::new().spawn_scoped(scope, || sha1_hex(data));
        let sha256 = sha256_hex(data);
        let md5 = md5.map_or_else(
            |_| md5_hex(data),
            |h| h.join().expect("MD5 worker panicked"),
        );
        let sha1 = sha1.map_or_else(
            |_| sha1_hex(data),
            |h| h.join().expect("SHA1 worker panicked"),
        );
        [md5, sha1, sha256]
    })
}

pub fn show_hashes(path: &Path) -> io::Result<()> {
    let data = fs::read(path)?;
    show_hashes_data(path, &data);
    Ok(())
}

/// Print hashes of an existing snapshot without reading the file again.
pub fn show_hashes_data(path: &Path, data: &[u8]) {
    println!();
    println!("{}", cyan(&format!("  Hashes for: {}", path.display())));
    let [md5, sha1, sha256] = all_hashes(data);
    println!("  MD5:    {}", md5);
    println!("  SHA1:   {}", sha1);
    println!("  SHA256: {}", sha256);
}

pub fn rc4(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err("RC4 key must not be empty".to_string());
    }
    let mut s: [u8; 256] = [0; 256];
    for (i, value) in s.iter_mut().enumerate() {
        *value = i as u8;
    }
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i: usize = 0;
    let mut j: usize = 0;
    for &byte in data {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) % 256];
        out.push(byte ^ k);
    }
    Ok(out)
}

pub fn parse_rc4_key(raw: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("0x") {
        return Err("RC4 key must not be empty".to_string());
    }
    if trimmed.to_lowercase().starts_with("0x") {
        let hex_part = &trimmed[2..];
        let padded;
        let hex_str = if !hex_part.len().is_multiple_of(2) {
            padded = format!("0{}", hex_part);
            &padded
        } else {
            hex_part
        };
        hex::decode(hex_str).map_err(|e| format!("Invalid hex RC4 key: {}", e))
    } else {
        Ok(trimmed.as_bytes().to_vec())
    }
}

pub fn parse_xor_key(raw: &str) -> Result<u8, String> {
    let raw = raw.trim();
    if raw.to_lowercase().starts_with("0x") {
        u8::from_str_radix(&raw[2..], 16).map_err(|e| format!("Invalid hex XOR key: {}", e))
    } else {
        raw.parse::<u8>()
            .map_err(|e| format!("Invalid decimal XOR key: {}", e))
    }
}

pub fn xor_bytes(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

pub fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Match Python's base64.b64decode(validate=False), including ignored junk,
/// non-canonical trailing bits and termination after sufficient padding.
pub fn b64_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(data) {
        return Ok(decoded);
    }
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let (mut bits, mut position, mut padding) = (0u32, 0usize, 0usize);
    for &byte in data {
        if byte == b'=' {
            padding += 1;
            if position >= 2 && position + padding >= 4 {
                return Ok(out);
            }
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        padding = 0;
        bits = ((bits << 6) | u32::from(value)) & 0xffffff;
        position = (position + 1) % 4;
        match position {
            2 => out.push((bits >> 4) as u8),
            3 => out.push((bits >> 2) as u8),
            0 => out.push(bits as u8),
            _ => {}
        }
    }
    if position != 0 {
        return Err("Base64 decode error: incorrect padding or invalid length".to_string());
    }
    Ok(out)
}

pub fn hex_encode(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = vec![0; data.len().checked_mul(2).expect("hex length overflow")];
    for (&byte, pair) in data.iter().zip(out.chunks_exact_mut(2)) {
        pair[0] = DIGITS[(byte >> 4) as usize];
        pair[1] = DIGITS[(byte & 15) as usize];
    }
    String::from_utf8(out).expect("hex is ASCII")
}

/// Like bytes.fromhex: ASCII whitespace is allowed only between complete bytes.
pub fn hex_decode(data: &str) -> Result<Vec<u8>, String> {
    let mut cleaned = Vec::with_capacity(data.len());
    for byte in data.bytes() {
        if matches!(byte, b' ' | b'\t'..=b'\r') {
            if !cleaned.len().is_multiple_of(2) {
                return Err("Hex decode error: whitespace inside a byte".to_string());
            }
        } else {
            cleaned.push(byte);
        }
    }
    hex::decode(cleaned).map_err(|e| format!("Hex decode error: {e}"))
}
