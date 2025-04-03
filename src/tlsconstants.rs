use lazy_static::lazy_static;
use std::collections::HashMap;

pub mod CipherSuite {
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
    // Initial list taken from 8.4 in RFC85446
	pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301; // [RFC8446]
	pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302; // [RFC8446]
	pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303; // [RFC8446]
	pub const TLS_AES_128_CCM_SHA256: u16 = 0x1304; // [RFC8446]
	pub const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305; // [RFC8446]

    /* added for completeness; not sure if these are deployed anywhere yet */
    pub const TLS_AEGIS_256_SHA512: u16 = 0x1306; // [draft-irtf-cfrg-aegis-aead-08]
    pub const TLS_AEGIS_128L_SHA256: u16 = 0x1307; // [draft-irtf-cfrg-aegis-aead-08]
}

pub mod SigScheme {
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
    pub const ECCSI_SHA256: u16 = 0x0704; // [draft-wang-tls-raw-public-key-with-ibc-02]
    pub const ECDSA_BRAINPOOLP256R1TLS13_SHA256: u16 = 0x081A; // [RFC8734]
    pub const ECDSA_BRAINPOOLP384R1TLS13_SHA384: u16 = 0x081B; // [RFC8734]
    pub const ECDSA_BRAINPOOLP512R1TLS13_SHA512: u16 = 0x081C; // [RFC8734]
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403; // [RFC8446]
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503; // [RFC8446]
    pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603; // [RFC8446]
    pub const ECDSA_SHA1: u16 = 0x0203; // [RFC8446][RFC9155]
    pub const ED25519: u16 = 0x0807; // [RFC8446]
    pub const ED448: u16 = 0x0808; // [RFC8446]
    pub const GOSTR34102012_256A: u16 = 0x0709; // [RFC9367]
    pub const GOSTR34102012_256B: u16 = 0x070A; // [RFC9367]
    pub const GOSTR34102012_256C: u16 = 0x070B; // [RFC9367]
    pub const GOSTR34102012_256D: u16 = 0x070C; // [RFC9367]
    pub const GOSTR34102012_512A: u16 = 0x070D; // [RFC9367]
    pub const GOSTR34102012_512B: u16 = 0x070E; // [RFC9367]
    pub const GOSTR34102012_512C: u16 = 0x070F; // [RFC9367]
    pub const ISO_CHINESE_IBS: u16 = 0x0707; // [draft-wang-tls-raw-public-key-with-ibc-02]
    pub const ISO_IBS1: u16 = 0x0705; // [draft-wang-tls-raw-public-key-with-ibc-02]
    pub const ISO_IBS2: u16 = 0x0706; // [draft-wang-tls-raw-public-key-with-ibc-02]
    pub const RSA_PKCS1_SHA1: u16 = 0x0201; // [RFC8446][RFC9155]
    pub const RSA_PKCS1_SHA256: u16 = 0x0401; // [RFC8446]
    pub const RSA_PKCS1_SHA256_LEGACY: u16 = 0x0420; // [draft-davidben-tls13-pkcs1-00]
    pub const RSA_PKCS1_SHA384: u16 = 0x0501; // [RFC8446]
    pub const RSA_PKCS1_SHA384_LEGACY: u16 = 0x0520; // [draft-davidben-tls13-pkcs1-00]
    pub const RSA_PKCS1_SHA512: u16 = 0x0601; // [RFC8446]
    pub const RSA_PKCS1_SHA512_LEGACY: u16 = 0x0620; // [draft-davidben-tls13-pkcs1-00]
    pub const RSA_PSS_PSS_SHA256: u16 = 0x0809; // [RFC8446]
    pub const RSA_PSS_PSS_SHA384: u16 = 0x080A; // [RFC8446]
    pub const RSA_PSS_PSS_SHA512: u16 = 0x080B; // [RFC8446]
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804; // [RFC8446]
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805; // [RFC8446]
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806; // [RFC8446]
    pub const SM2SIG_SM3: u16 = 0x0708; // [RFC8998]
}

pub mod Group {
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
	// and filtered on those which are recommended and not obsolete as of 2024-04-01.
    pub const ARBITRARY_EXPLICIT_CHAR2_CURVES: u16 = 65282; // [RFC8422]
    pub const ARBITRARY_EXPLICIT_PRIME_CURVES: u16 = 65281; // [RFC8422]
    pub const BRAINPOOLP256R1: u16 = 26; // [RFC7027]
    pub const BRAINPOOLP256R1TLS13: u16 = 31; // [RFC8734]
    pub const BRAINPOOLP384R1: u16 = 27; // [RFC7027]
    pub const BRAINPOOLP384R1TLS13: u16 = 32; // [RFC8734]
    pub const BRAINPOOLP512R1: u16 = 28; // [RFC7027]
    pub const BRAINPOOLP512R1TLS13: u16 = 33; // [RFC8734]
    pub const CURVESM2: u16 = 41; // [RFC8998]
    pub const FFDHE2048: u16 = 256; // [RFC7919]
    pub const FFDHE3072: u16 = 257; // [RFC7919]
    pub const FFDHE4096: u16 = 258; // [RFC7919]
    pub const FFDHE6144: u16 = 259; // [RFC7919]
    pub const FFDHE8192: u16 = 260; // [RFC7919]
    pub const GC256A: u16 = 34; // [RFC9189]
    pub const GC256B: u16 = 35; // [RFC9189]
    pub const GC256C: u16 = 36; // [RFC9189]
    pub const GC256D: u16 = 37; // [RFC9189]
    pub const GC512A: u16 = 38; // [RFC9189]
    pub const GC512B: u16 = 39; // [RFC9189]
    pub const GC512C: u16 = 40; // [RFC9189]
    pub const MLKEM1024: u16 = 514; // [draft-connolly-tls-mlkem-key-agreement-05]
    pub const MLKEM512: u16 = 512; // [draft-connolly-tls-mlkem-key-agreement-05]
    pub const MLKEM768: u16 = 513; // [draft-connolly-tls-mlkem-key-agreement-05]
    pub const SECP160K1: u16 = 15; // [RFC8422]
    pub const SECP160R1: u16 = 16; // [RFC8422]
    pub const SECP160R2: u16 = 17; // [RFC8422]
    pub const SECP192K1: u16 = 18; // [RFC8422]
    pub const SECP192R1: u16 = 19; // [RFC8422]
    pub const SECP224K1: u16 = 20; // [RFC8422]
    pub const SECP224R1: u16 = 21; // [RFC8422]
    pub const SECP256K1: u16 = 22; // [RFC8422]
    pub const SECP256R1: u16 = 23; // [RFC8422]
    pub const SECP256R1MLKEM768: u16 = 4587; // [draft-kwiatkowski-tls-ecdhe-mlkem-03]
    pub const SECP384R1: u16 = 24; // [RFC8422]
    pub const SECP384R1MLKEM1024: u16 = 4589; // [draft-kwiatkowski-tls-ecdhe-mlkem-03]
    pub const SECP521R1: u16 = 25; // [RFC8422]
    pub const SECT163K1: u16 = 1; // [RFC8422]
    pub const SECT163R1: u16 = 2; // [RFC8422]
    pub const SECT163R2: u16 = 3; // [RFC8422]
    pub const SECT193R1: u16 = 4; // [RFC8422]
    pub const SECT193R2: u16 = 5; // [RFC8422]
    pub const SECT233K1: u16 = 6; // [RFC8422]
    pub const SECT233R1: u16 = 7; // [RFC8422]
    pub const SECT239K1: u16 = 8; // [RFC8422]
    pub const SECT283K1: u16 = 9; // [RFC8422]
    pub const SECT283R1: u16 = 10; // [RFC8422]
    pub const SECT409K1: u16 = 11; // [RFC8422]
    pub const SECT409R1: u16 = 12; // [RFC8422]
    pub const SECT571K1: u16 = 13; // [RFC8422]
    pub const SECT571R1: u16 = 14; // [RFC8422]
    pub const X25519: u16 = 29; // [RFC8446][RFC8422]
    pub const X25519MLKEM768: u16 = 4588; // [draft-kwiatkowski-tls-ecdhe-mlkem-03]
    pub const X448: u16 = 30; // [RFC8446][RFC8422]
}

lazy_static! {
    pub static ref KeyShareLengths: HashMap<u16, usize> = {
            let mut m = HashMap::new();
            m.insert(Group::X25519MLKEM768, 1216); // [draft-kwiatkowski-tls-ecdhe-mlkem-03 3.1.1]
            m.insert(Group::X25519, 32); // [RFC8446 4.2.8.2]
            m.insert(Group::SECP256R1, 65); // [RFC8446 4.2.8.2]
            m.insert(Group::SECP256R1MLKEM768, 1249); // [draft-kwiatkowski-tls-ecdhe-mlkem-03 3.1.1]
            m.insert(Group::SECP384R1MLKEM1024, 1665); // [draft-kwiatkowski-tls-ecdhe-mlkem-03 3.1.1]
            m.insert(Group::MLKEM1024, 1216);
            m.insert(Group::MLKEM512, 1249);
            m.insert(Group::MLKEM768, 1665);
            m
    };
}

lazy_static! {
    pub static ref GroupDescription: HashMap<u16, String> = {
        let mut m = HashMap::new();
        m.insert(Group::X25519MLKEM768, "X25519MLKEM768".to_string()); // [draft-kwiatkowski-tls-ecdhe-mlkem-03 3.1.1]
        m.insert(Group::X25519, "32".to_string()); // [RFC8446 4.2.8.2]
        m.insert(Group::SECP256R1, "65".to_string()); // [RFC8446 4.2.8.2]
        m.insert(Group::SECP256R1MLKEM768, "SECP256R1MLKEM768".to_string()); // [draft-kwiatkowski-tls-ecdhe-mlkem-03 3.1.1]
        m.insert(Group::SECP384R1MLKEM1024, "SECP384R1MLKEM1024".to_string()); // [draft-kwiatkowski-tls-ecdhe-mlkem-03 3.1.1]
        m.insert(Group::MLKEM1024, "MLKEM1024".to_string());
        m.insert(Group::MLKEM512, "MLKEM512".to_string());
        m.insert(Group::MLKEM768, "MLKEM768".to_string());
        m
    };
}

lazy_static! {
    pub static ref TlsAlerts: HashMap<u8, String> = {
        let mut m = HashMap::new();
        m.insert(0, "close_notify".to_string()); // [RFC8446][RFC
        m.insert(10, "unexpected_message".to_string()); // [RFC8446]
        m.insert(20, "bad_record_mac".to_string()); // [RFC8446]
        m.insert(21, "decryption_failed_RESERVED".to_string()); // [RFC8446]
        m.insert(22, "record_overflow".to_string()); // [RFC8446]
        m.insert(30, "decompression_failure_RESERVED".to_string()); // [RFC8446]
        m.insert(40, "handshake_failure".to_string()); // [RFC8446]
        m.insert(41, "no_certificate_RESERVED".to_string()); // [RFC8446]
        m.insert(42, "bad_certificate".to_string()); // [RFC8446]
        m.insert(43, "unsupported_certificate".to_string()); // [RFC8446]
        m.insert(44, "certificate_revoked".to_string()); // [RFC8446]
        m.insert(45, "certificate_expired".to_string()); // [RFC8446]
        m.insert(46, "certificate_unknown".to_string()); // [RFC8446]
        m.insert(47, "illegal_parameter".to_string()); // [RFC8446]
        m.insert(48, "unknown_ca".to_string()); // [RFC8446]
        m.insert(49, "access_denied".to_string()); // [RFC8446]
        m.insert(50, "decode_error".to_string()); // [RFC8446]
        m.insert(51, "decrypt_error".to_string()); // [RFC8446]
        m.insert(52, "too_many_cids_requested".to_string()); // [RFC9147]
        m.insert(60, "export_restriction_RESERVED".to_string()); // [RFC8446]
        m.insert(70, "protocol_version".to_string()); // [RFC8446]
        m.insert(71, "insufficient_security".to_string()); // [RFC8446]
        m.insert(80, "internal_error".to_string()); // [RFC8446]
        m.insert(86, "inappropriate_fallback".to_string()); // [RFC7507]
        m.insert(90, "user_canceled".to_string()); // [RFC8446]
        m.insert(100, "no_renegotiation_RESERVED".to_string()); // [RFC8446]
        m.insert(109, "missing_extension".to_string()); // [RFC8446]
        m.insert(110, "unsupported_extension".to_string()); // [RFC8446]
        m.insert(111, "certificate_unobtainable_RESERVED".to_string()); // [RFC6066][RFC8446]
        m.insert(112, "unrecognized_name".to_string()); // [RFC6066]
        m.insert(113, "bad_certificate_status_response".to_string()); // [RFC6066]
        m.insert(114, "bad_certificate_hash_value_RESERVED".to_string()); // [RFC6066][RFC8446]
        m.insert(115, "unknown_psk_identity".to_string()); // [RFC4279]
        m.insert(116, "certificate_required".to_string()); // [RFC8446]
        m.insert(120, "no_application_protocol".to_string()); // [RFC7301][RFC8447]
        m
	};
}
