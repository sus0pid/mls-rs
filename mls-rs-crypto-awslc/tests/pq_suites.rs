//! Provider-level checks for the draft-ietf-mls-pq-ciphersuites-07 suites (§3.1, Table 2).

#![cfg(all(feature = "post-quantum", not(mls_build_async)))]

#[path = "common/hpke_pq.rs"]
mod hpke_pq;

use mls_rs_core::crypto::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_awslc::{AwsLcCipherSuite, AwsLcCryptoProvider};

struct Expected {
    cipher_suite: CipherSuite,
    hpke_kem_id: u16,
    kdf_extract_size: usize,
    aead_key_size: usize,
    hash_len: usize,
    hpke_pk_len: usize,
    hpke_sk_len: usize,
    hpke_enc_len: usize,
    sig_pk_len: usize,
    sig_len: usize,
}

/// draft-ietf-mls-pq-ciphersuites-07 Table 2, draft-ietf-hpke-pq-05 §8.2, FIPS 204 Table 2.
const DRAFT_SUITES: [Expected; 1] = [Expected {
    cipher_suite: CipherSuite::MLKEM768X25519_CHACHA_MLDSA44,
    hpke_kem_id: 0x647a,
    kdf_extract_size: 48,
    aead_key_size: 32,
    hash_len: 48,
    hpke_pk_len: 1216,
    hpke_sk_len: 32,
    hpke_enc_len: 1120,
    sig_pk_len: 1312,
    sig_len: 2420,
}];

fn provider(cs: CipherSuite) -> AwsLcCipherSuite {
    AwsLcCryptoProvider::new()
        .cipher_suite_provider(cs)
        .unwrap_or_else(|| panic!("{cs:?} not supported"))
}

#[test]
fn suites_are_advertised() {
    let supported = AwsLcCryptoProvider::new().supported_cipher_suites();

    for e in &DRAFT_SUITES {
        assert!(supported.contains(&e.cipher_suite), "{:?}", e.cipher_suite);
    }
}

#[test]
fn algorithm_parameters() {
    for e in &DRAFT_SUITES {
        let cs = provider(e.cipher_suite);

        assert_eq!(cs.cipher_suite(), e.cipher_suite);
        assert_eq!(cs.kdf_extract_size(), e.kdf_extract_size);
        assert_eq!(cs.aead_key_size(), e.aead_key_size);
        assert_eq!(cs.aead_nonce_size(), 12);
        assert_eq!(cs.hash(b"abc").unwrap().len(), e.hash_len);
        assert_eq!(cs.mac(&[1u8; 32], b"abc").unwrap().len(), e.hash_len);

        let (sk, pk) = cs.kem_generate().unwrap();
        assert_eq!((sk.len(), pk.len()), (e.hpke_sk_len, e.hpke_pk_len));
        let ct = cs.hpke_seal(&pk, b"info", None, b"pt").unwrap();
        assert_eq!(ct.kem_output.len(), e.hpke_enc_len);
    }
}

#[test]
fn signatures() {
    for e in &DRAFT_SUITES {
        let cs = provider(e.cipher_suite);

        let (sk, pk) = cs.signature_key_generate().unwrap();
        assert_eq!(pk.as_bytes().len(), e.sig_pk_len);

        let sig = cs.sign(&sk, b"message").unwrap();
        assert_eq!(sig.len(), e.sig_len);
        assert_eq!(cs.signature_key_derive_public(&sk).unwrap(), pk);
        cs.verify(&pk, &sig, b"message").unwrap();
        assert!(cs.verify(&pk, &sig, b"other message").is_err());
    }
}

/// DeriveKeyPair uses only the KEM's suite_id (draft-ietf-hpke-hpke-06 §4.4).
#[test]
fn kem_derive_matches_the_hpke_pq_vectors() {
    for e in &DRAFT_SUITES {
        let v = hpke_pq::test_vector(e.hpke_kem_id);

        let (sk, pk) = provider(e.cipher_suite).kem_derive(&v.ikm_r).unwrap();

        assert_eq!(sk.as_ref(), v.sk_rm.as_slice(), "{:?}", e.cipher_suite);
        assert_eq!(pk.as_ref(), v.pk_rm.as_slice(), "{:?}", e.cipher_suite);
    }
}
