pub mod ads;
pub mod crypto;
pub mod entropy;
pub mod lolbins;
pub mod magic;
pub mod ui;

// Re-export common functions for library consumers and benchmarks
pub use crypto::{
    b64_decode, b64_encode, hex_decode, hex_encode, md5_hex, parse_rc4_key, parse_xor_key, rc4,
    sha1_hex, sha256_hex, show_hashes, xor_bytes,
};
pub use entropy::{
    calc_entropy, lower_entropy, lower_entropy_raw, strip_null_padding, strip_null_padding_raw,
};
pub use lolbins::{LOLBINS, LolBin, get_lolbin};
pub use magic::{MAGIC_MAP, get_magic_bytes, match_magic_bytes, set_magic_bytes};
pub use ui::{banner, err, fmt_bytes, info, ok, warn};
