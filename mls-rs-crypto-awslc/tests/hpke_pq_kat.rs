//! Known-answer tests for the HPKE PQ KEMs of draft-ietf-hpke-pq-05, using the Appendix A
//! test vectors in `test_data/hpke_pq/` (see the README there for provenance and license).

#![cfg(feature = "post-quantum")]

use mls_rs_crypto_awslc::AwsLcShake256;
use mls_rs_crypto_hpke::kdf::labeled_derive;
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVector {
    kem_id: u16,
    #[serde(rename = "ikmR", with = "hex::serde")]
    ikm_r: Vec<u8>,
    #[serde(rename = "skRm", with = "hex::serde")]
    sk_rm: Vec<u8>,
}

fn test_vectors() -> Vec<TestVector> {
    serde_json::from_str(include_str!("../test_data/hpke_pq/test_vectors.json")).unwrap()
}

/// `Nseed` of the KEM, which is also its `Nsk`: 64 for ML-KEM-768 (draft-ietf-hpke-pq §3,
/// §8.1) and 32 for MLKEM768-X25519 (§4, §8.2).
fn seed_len(kem_id: u16) -> u16 {
    match kem_id {
        0x0041 => 64,
        0x647a => 32,
        other => panic!("unexpected kem_id {other:#06x}"),
    }
}

/// draft-ietf-hpke-pq §3 and §4: `DeriveKeyPair(ikm)` starts with
/// `seed = SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", Nseed)`, with
/// `suite_id = "KEM" || I2OSP(kem_id, 2)` (draft-ietf-hpke-hpke-06 §4.4). The serialized
/// private key is that seed, so it must equal the vector's `skRm`.
#[test]
fn labeled_derive_reproduces_sk_rm() {
    let vectors = test_vectors();
    assert_eq!(vectors.len(), 2);

    for v in vectors {
        let suite_id = [b"KEM" as &[u8], &v.kem_id.to_be_bytes()].concat();

        let seed = labeled_derive(
            &AwsLcShake256,
            &suite_id,
            &v.ikm_r,
            b"DeriveKeyPair",
            b"",
            seed_len(v.kem_id),
        )
        .unwrap();

        assert_eq!(seed, v.sk_rm, "kem_id {:#06x}", v.kem_id);
    }
}
