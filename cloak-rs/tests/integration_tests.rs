use cloak_rs::crypto::{
    b64_decode, b64_encode, hex_decode, hex_encode, md5_hex, parse_rc4_key, parse_xor_key, rc4,
    sha1_hex, sha256_hex, xor_bytes,
};
use cloak_rs::entropy::{calc_entropy, lower_entropy, strip_null_padding};
use cloak_rs::lolbins::{LOLBINS, get_lolbin};
use cloak_rs::magic::{get_magic_bytes, match_magic_bytes};

#[test]
fn test_magic_bytes() {
    assert_eq!(get_magic_bytes(".pdf"), Some(&[0x25, 0x50, 0x44, 0x46][..]));
    assert_eq!(
        get_magic_bytes(".png"),
        Some(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A][..])
    );
    assert_eq!(get_magic_bytes(".nonexistent"), None);

    let pdf_sample = b"%PDF-1.7\nSample content";
    let matches = match_magic_bytes(pdf_sample);
    assert_eq!(matches, vec![".pdf"]);
}

#[test]
fn test_hashes() {
    let data = b"hello world";
    assert_eq!(md5_hex(data), "5EB63BBBE01EEED093CB22BB8F5ACDC3");
    assert_eq!(sha1_hex(data), "2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED");
    assert_eq!(
        sha256_hex(data),
        "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"
    );
}

#[test]
fn test_rc4_roundtrip() {
    let key = b"SecretKey123";
    let plaintext =
        b"Antigravity red team utility test payload with various bytes \x00\xff\x7f\x80";
    let ciphertext = rc4(plaintext, key).unwrap();
    assert_ne!(plaintext.as_slice(), ciphertext.as_slice());
    let decrypted = rc4(&ciphertext, key).unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_parse_keys() {
    assert_eq!(parse_xor_key("0x41").unwrap(), 0x41);
    assert_eq!(parse_xor_key("65").unwrap(), 65);
    assert_eq!(
        parse_rc4_key("0xDEADBEEF").unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
    assert_eq!(parse_rc4_key("secret").unwrap(), b"secret".to_vec());
}

#[test]
fn test_xor_roundtrip() {
    let data = b"Testing XOR cipher algorithm!";
    let key = 0xAA;
    let enc = xor_bytes(data, key);
    assert_ne!(data.as_slice(), enc.as_slice());
    let dec = xor_bytes(&enc, key);
    assert_eq!(data.as_slice(), dec.as_slice());
}

#[test]
fn test_b64_and_hex() {
    let data = b"Testing Base64 and Hex encoding.";
    let b64 = b64_encode(data);
    let dec_b64 = b64_decode(b64.as_bytes()).unwrap();
    assert_eq!(data.as_slice(), dec_b64.as_slice());

    let h = hex_encode(data);
    let dec_hex = hex_decode(&h).unwrap();
    assert_eq!(data.as_slice(), dec_hex.as_slice());
}

#[test]
fn test_entropy_and_padding_roundtrip() {
    // Highly patterned low entropy
    let low = vec![0u8; 1000];
    assert_eq!(calc_entropy(&low), 0.0);

    // High entropy data
    let mut high = Vec::new();
    for i in 0..256 {
        for _ in 0..10 {
            high.push(i as u8);
        }
    }
    let orig_entropy = calc_entropy(&high);
    assert!(orig_entropy > 7.9);

    let (padded, interval_opt) = lower_entropy(&high, 6.0);
    let interval = interval_opt.expect("Interval should be chosen");
    let padded_entropy = calc_entropy(&padded);
    assert!(padded_entropy <= 6.0);

    let recovered = strip_null_padding(&padded, interval).unwrap();
    assert_eq!(high, recovered);
}

#[test]
fn test_all_18_lolbins() {
    assert_eq!(LOLBINS.len(), 18);
    for lb in LOLBINS {
        assert!(!lb.name.is_empty());
        assert!(!lb.desc.is_empty());
        let cmds = (lb.generate)("payload.dll", "http://host/payload.dll", "DllMain", ".dll");
        assert!(!cmds.is_empty(), "LOLBin {} generated no commands", lb.name);
    }
    assert!(get_lolbin("regsvr32").is_some());
    assert!(get_lolbin("nonexistent").is_none());
}
