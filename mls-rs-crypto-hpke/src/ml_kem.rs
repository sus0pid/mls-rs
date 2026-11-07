//! ML-KEM as an HPKE KEM with seed-format keys (draft-ietf-hpke-pq-05 §3).

use alloc::vec;
use alloc::vec::Vec;

use mls_rs_core::{
    crypto::{HpkePublicKey, HpkeSecretKey},
    error::IntoAnyError,
};
use mls_rs_crypto_traits::{KemResult, KemType, VariableLengthHash};
use zeroize::Zeroizing;

use crate::kdf::labeled_derive;
use crate::kem_combiner::{Error, FixedLengthKemType, SeedRng};

/// HPKE KEM ids of ML-KEM (draft-ietf-hpke-pq-05 §8.1).
pub const ML_KEM_512_KEM_ID: u16 = 0x0040;
pub const ML_KEM_768_KEM_ID: u16 = 0x0041;
pub const ML_KEM_1024_KEM_ID: u16 = 0x0042;

/// `Nsk`: the seed-format decapsulation key `d || z` (draft-ietf-hpke-pq-05 §3).
const NSK: usize = 64;

/// ML-KEM as an HPKE KEM (draft-ietf-hpke-pq-05 §3); the secret key is the 64-byte seed.
#[derive(Clone, Debug)]
pub struct MlKemHpkeKem<PQ, D, RNG> {
    pq: PQ,
    derive: D,
    rng: RNG,
    kem_id: u16,
}

impl<PQ, D, RNG> MlKemHpkeKem<PQ, D, RNG> {
    pub fn new(pq: PQ, derive: D, rng: RNG, kem_id: u16) -> Self {
        Self {
            pq,
            derive,
            rng,
            kem_id,
        }
    }
}

impl<PQ, D, RNG> MlKemHpkeKem<PQ, D, RNG>
where
    PQ: FixedLengthKemType,
    D: VariableLengthHash,
    RNG: SeedRng,
{
    /// `expandDecapsKey(dk) = ML-KEM.KeyGen_internal(dk[:32], dk[32:])`.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn expand_decaps_key(&self, dk: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        if dk.len() != NSK || self.pq.seed_length_for_derive() != NSK {
            return Err(Error::InvalidKeyData);
        }

        self.pq
            .generate_deterministic(dk)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn key_pair_from_seed(
        &self,
        dk: Zeroizing<Vec<u8>>,
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let (_expanded_dk, ek) = self.expand_decaps_key(&dk).await?;
        Ok((HpkeSecretKey::from(dk.to_vec()), ek))
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl<PQ, D, RNG> KemType for MlKemHpkeKem<PQ, D, RNG>
where
    PQ: FixedLengthKemType,
    D: VariableLengthHash,
    RNG: SeedRng,
{
    type Error = Error;

    fn kem_id(&self) -> u16 {
        self.kem_id
    }

    /// HPKE `DeriveKeyPair(ikm)` (draft-ietf-hpke-pq-05 §3).
    async fn generate_deterministic(
        &self,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let suite_id = [b"KEM" as &[u8], &self.kem_id.to_be_bytes()].concat();

        let dk = Zeroizing::new(
            labeled_derive(
                &self.derive,
                &suite_id,
                ikm,
                b"DeriveKeyPair",
                b"",
                NSK as u16,
            )
            .map_err(|e| Error::KdfError(e.into_any_error()))?,
        );

        self.key_pair_from_seed(dk).await
    }

    /// `GenerateKeyPair()`: `dk = random(64)`, then `(dk, ek)`.
    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let mut dk = Zeroizing::new(vec![0u8; NSK]);

        self.rng
            .fill(&mut dk)
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        self.key_pair_from_seed(dk).await
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Error> {
        if key.len() != self.pq.public_key_size() {
            return Err(Error::InvalidKeyData);
        }

        self.pq
            .public_key_validate(key)
            .map_err(|e| Error::KemError(e.into_any_error()))
    }

    /// `Encap(pkR) = ML-KEM.Encaps(pkR)`; an encapsulation key check failure is an error.
    async fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Error> {
        if remote_key.len() != self.pq.public_key_size() {
            return Err(Error::InvalidKeyData);
        }

        self.pq
            .encap(remote_key)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))
    }

    /// `Decap(enc, skR)` (draft-ietf-hpke-pq-05 §3).
    async fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Error> {
        if enc.len() != self.pq.enc_size() {
            return Err(Error::InvalidKeyData);
        }

        let (expanded_dk, ek) = self.expand_decaps_key(secret_key).await?;

        self.pq
            .decap(enc, &expanded_dk, &ek)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))
    }

    fn seed_length_for_derive(&self) -> usize {
        NSK
    }

    fn derive_key_pair_uses_dkp_prk(&self) -> bool {
        false
    }
}

impl<PQ, D, RNG> FixedLengthKemType for MlKemHpkeKem<PQ, D, RNG>
where
    PQ: FixedLengthKemType,
    D: VariableLengthHash,
    RNG: SeedRng,
{
    fn public_key_size(&self) -> usize {
        self.pq.public_key_size()
    }

    fn secret_key_size(&self) -> usize {
        NSK
    }

    fn enc_size(&self) -> usize {
        self.pq.enc_size()
    }
}

#[cfg(all(test, not(mls_build_async)))]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
    use mls_rs_crypto_traits::{
        mock::{MockKemType, MockVariableLengthHash, TestError},
        KemResult, KemType,
    };

    use super::{MlKemHpkeKem, ML_KEM_768_KEM_ID};
    use crate::kem_combiner::{FixedLengthKemType, MockSeedRng};

    const EK_LEN: usize = 4;
    const CT_LEN: usize = 3;

    struct TestPq(MockKemType);

    impl KemType for TestPq {
        type Error = TestError;

        fn kem_id(&self) -> u16 {
            unreachable!()
        }

        fn generate_deterministic(
            &self,
            seed: &[u8],
        ) -> Result<(HpkeSecretKey, HpkePublicKey), TestError> {
            self.0.generate_deterministic(seed)
        }

        fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), TestError> {
            unreachable!("MlKemHpkeKem samples the seed itself")
        }

        fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), TestError> {
            self.0.public_key_validate(key)
        }

        fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, TestError> {
            self.0.encap(remote_key)
        }

        fn decap(
            &self,
            enc: &[u8],
            secret_key: &HpkeSecretKey,
            local_public: &HpkePublicKey,
        ) -> Result<Vec<u8>, TestError> {
            self.0.decap(enc, secret_key, local_public)
        }

        fn seed_length_for_derive(&self) -> usize {
            64
        }
    }

    impl FixedLengthKemType for TestPq {
        fn public_key_size(&self) -> usize {
            EK_LEN
        }

        fn secret_key_size(&self) -> usize {
            unreachable!()
        }

        fn enc_size(&self) -> usize {
            CT_LEN
        }
    }

    type TestKem = MlKemHpkeKem<TestPq, MockVariableLengthHash, MockSeedRng>;

    fn test_kem() -> TestKem {
        MlKemHpkeKem::new(
            TestPq(MockKemType::new()),
            MockVariableLengthHash::new(),
            MockSeedRng::new(),
            ML_KEM_768_KEM_ID,
        )
    }

    fn expect_expand(kem: &mut TestKem, dk: Vec<u8>) {
        kem.pq
            .0
            .expect_generate_deterministic()
            .withf(move |seed| seed == dk.as_slice())
            .once()
            .returning(|_| Ok((b"expanded".to_vec().into(), b"ekek".to_vec().into())));
    }

    #[test]
    fn kem_parameters() {
        let kem = test_kem();

        assert_eq!(kem.kem_id(), 0x0041);
        assert!(!kem.derive_key_pair_uses_dkp_prk());
        assert_eq!(kem.seed_length_for_derive(), 64);
        assert_eq!(kem.public_key_size(), EK_LEN);
        assert_eq!(kem.secret_key_size(), 64);
        assert_eq!(kem.enc_size(), CT_LEN);
    }

    #[test]
    fn derive_key_pair_returns_the_labeled_derive_seed() {
        let mut kem = test_kem();

        let labeled_ikm = [
            b"ikm" as &[u8],
            b"HPKE-v1",
            b"KEM\x00\x41",
            b"\x00\x0dDeriveKeyPair",
            b"\x00\x40",
        ]
        .concat();

        kem.derive
            .expect_hash()
            .withf(move |input, len| input == labeled_ikm.as_slice() && *len == 64)
            .once()
            .returning(|_, _| Ok(vec![0x11; 64]));

        expect_expand(&mut kem, vec![0x11; 64]);

        let (sk, pk) = kem.generate_deterministic(b"ikm").unwrap();

        assert_eq!(sk.as_ref(), [0x11; 64].as_slice());
        assert_eq!(pk.as_ref(), b"ekek");
    }

    #[test]
    fn generate_key_pair_samples_a_64_byte_seed() {
        let mut kem = test_kem();

        kem.rng
            .expect_fill()
            .withf(|out| out.len() == 64)
            .once()
            .returning(|out| {
                out.fill(0x22);
                Ok(())
            });

        expect_expand(&mut kem, vec![0x22; 64]);

        let (sk, pk) = kem.generate().unwrap();

        assert_eq!(sk.as_ref(), [0x22; 64].as_slice());
        assert_eq!(pk.as_ref(), b"ekek");
    }

    #[test]
    fn encap_is_ml_kem_encaps() {
        let mut kem = test_kem();

        kem.pq
            .0
            .expect_encap()
            .withf(|ek| ek.as_ref() == b"ekek")
            .once()
            .returning(|_| Ok(KemResult::new(b"ss".to_vec(), b"ct!".to_vec())));

        let res = kem.encap(&b"ekek".to_vec().into()).unwrap();

        assert_eq!(res.shared_secret(), b"ss");
        assert_eq!(res.enc(), b"ct!");
    }
}
