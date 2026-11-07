use mls_rs_crypto_hpke::kem_combiner::SeedRng;

use crate::AwsLcCryptoError;

/// The aws-lc random number generator, as a [`SeedRng`] for generic KEMs that sample
/// seed-format secret keys (for example `GenerateKeyPair` of draft-irtf-cfrg-hybrid-kems).
#[derive(Clone, Copy, Debug, Default)]
pub struct AwsLcRandom;

impl SeedRng for AwsLcRandom {
    type Error = AwsLcCryptoError;

    fn fill(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        Ok(aws_lc_rs::rand::fill(out)?)
    }
}
