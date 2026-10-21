use crate::ui::{ok, warn};
use std::fs;
use std::io;
use std::path::Path;

pub const MAGIC_MAP: &[(&str, &[u8])] = &[
    (".pdf", &[0x25, 0x50, 0x44, 0x46]),
    (".png", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    (".jpg", &[0xFF, 0xD8, 0xFF]),
    (".jpeg", &[0xFF, 0xD8, 0xFF]),
    (".gif", &[0x47, 0x49, 0x46, 0x38]),
    (".zip", &[0x50, 0x4B, 0x03, 0x04]),
    (".docx", &[0x50, 0x4B, 0x03, 0x04]),
    (".xlsx", &[0x50, 0x4B, 0x03, 0x04]),
    (".pptx", &[0x50, 0x4B, 0x03, 0x04]),
    (".7z", &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
    (".gz", &[0x1F, 0x8B]),
    (".bz2", &[0x42, 0x5A, 0x68]),
    (".rar", &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]),
    (".exe", &[0x4D, 0x5A]),
    (".dll", &[0x4D, 0x5A]),
    (".elf", &[0x7F, 0x45, 0x4C, 0x46]),
    (".mp3", &[0x49, 0x44, 0x33]),
    (".mp4", &[0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]),
    (".wav", &[0x52, 0x49, 0x46, 0x46]),
    (".bmp", &[0x42, 0x4D]),
    (".ico", &[0x00, 0x00, 0x01, 0x00]),
    (".xml", &[0x3C, 0x3F, 0x78, 0x6D, 0x6C]),
    (
        ".sqlite",
        &[
            0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20,
            0x33,
        ],
    ),
    (".class", &[0xCA, 0xFE, 0xBA, 0xBE]),
    (".dmg", &[0x78, 0x01, 0x73, 0x0D, 0x62, 0x62]),
    (".iso", &[0x43, 0x44, 0x30, 0x30, 0x31]),
];

pub fn get_magic_bytes(ext: &str) -> Option<&'static [u8]> {
    let ext_lower = ext.to_lowercase();
    MAGIC_MAP
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&ext_lower))
        .map(|(_, v)| *v)
}

pub fn match_magic_bytes(data: &[u8]) -> Vec<&'static str> {
    let mut matches = Vec::new();
    for (ext, magic) in MAGIC_MAP {
        if data.len() >= magic.len() && &data[..magic.len()] == *magic {
            matches.push(*ext);
        }
    }
    matches
}

pub fn set_magic_bytes(path: &Path, ext: &str) -> io::Result<()> {
    let ext_lower = ext.to_lowercase();
    let magic = match get_magic_bytes(&ext_lower) {
        Some(m) => m,
        None => {
            warn(&format!(
                "No magic bytes defined for '{}' — header unchanged.",
                ext_lower
            ));
            return Ok(());
        }
    };

    let mut data = fs::read(path)?;
    if data.len() < magic.len() {
        data.resize(magic.len(), 0);
    }
    data[..magic.len()].copy_from_slice(magic);
    fs::write(path, &data)?;

    let hex_str = magic
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");
    ok(&format!("Magic bytes set for '{}': {}", ext_lower, hex_str));
    Ok(())
}
