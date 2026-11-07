use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_hpke::ml_kem::{MlKemHpkeKem, ML_KEM_768_KEM_ID};

use crate::{AwsLcRandom, AwsLcShake256, MlKemKem};

/// ML-KEM-768, HPKE KEM 0x0041 (draft-ietf-hpke-pq-05 §3).
pub type MlKem768Kem = MlKemHpkeKem<MlKemKem, AwsLcShake256, AwsLcRandom>;

/// Build the aws-lc [`MlKem768Kem`].
pub fn mlkem768_kem() -> Option<MlKem768Kem> {
    let pq = MlKemKem::new(CipherSuite::ML_KEM_768)?;

    Some(MlKemHpkeKem::new(
        pq,
        AwsLcShake256,
        AwsLcRandom,
        ML_KEM_768_KEM_ID,
    ))
}
