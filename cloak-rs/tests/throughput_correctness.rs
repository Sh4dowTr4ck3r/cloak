use cloak_rs::crypto::{all_hashes, hex_encode, md5_hex, sha1_hex, sha256_hex};
#[test]
fn hex_matches_reference_at_boundaries() {
    for len in [0, 1, 15, 16, 17, 255, 256, 257, 4096, 65537] {
        let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        assert_eq!(hex_encode(&data), hex::encode_upper(&data));
    }
}
#[test]
fn combined_hashes_match_serial_across_threshold() {
    for len in [0, 1, 1048575, 1048576, 1048577, 4194304] {
        let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
        assert_eq!(
            all_hashes(&data),
            [md5_hex(&data), sha1_hex(&data), sha256_hex(&data)]
        );
    }
}

#[test]
fn empty_rc4_keys_fail_closed() {
    assert!(cloak_rs::crypto::rc4(b"hello", b"").is_err());
    assert!(cloak_rs::crypto::rc4(b"", b"").is_err());
    for raw in ["", " ", "0x", "0X"] {
        assert!(cloak_rs::crypto::parse_rc4_key(raw).is_err());
    }
}
