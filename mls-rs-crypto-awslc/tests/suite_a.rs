//! "Suite A": a private-use suite (RFC 9420 §17.1) built with `AwsLcCipherSuiteBuilder`.

#![cfg(all(feature = "post-quantum", not(mls_build_async)))]

use mls_rs::{
    client_builder::MlsConfig,
    group::ReceivedMessage,
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider,
};
use mls_rs_crypto_awslc::{AwsLcCipherSuite, AwsLcCipherSuiteBuilder};
use mls_rs_crypto_traits::{AeadId, Curve, KdfId};

/// An example private-use codepoint (RFC 9420 §17.1: 0xF000–0xFFFF).
const SUITE_A: CipherSuite = CipherSuite::new(0xF0A0);

fn suite_a() -> AwsLcCipherSuite {
    AwsLcCipherSuiteBuilder::new()
        .mlkem768_x25519_hpke(KdfId::HkdfSha256, AeadId::Aes256Gcm)
        .kdf(KdfId::HkdfSha256)
        .aead(AeadId::Aes256Gcm)
        .signing(Curve::MlDsa44)
        .fallback_cipher_suite(CipherSuite::CURVE25519_AES128)
        .build(SUITE_A)
        .unwrap()
}

#[derive(Clone)]
struct SuiteAProvider;

impl CryptoProvider for SuiteAProvider {
    type CipherSuiteProvider = AwsLcCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        vec![SUITE_A]
    }

    fn cipher_suite_provider(&self, cipher_suite: CipherSuite) -> Option<AwsLcCipherSuite> {
        (cipher_suite == SUITE_A).then(suite_a)
    }
}

#[test]
fn algorithm_parameters() {
    let cs = suite_a();

    assert_eq!(cs.cipher_suite(), SUITE_A);
    assert_eq!(cs.kdf_extract_size(), 32);
    assert_eq!(cs.aead_key_size(), 32);
    assert_eq!(cs.hash(b"abc").unwrap().len(), 32);

    let (sk, pk) = cs.kem_generate().unwrap();
    assert_eq!((sk.len(), pk.len()), (32, 1216));
    let ct = cs.hpke_seal(&pk, b"info", None, b"pt").unwrap();
    assert_eq!(ct.kem_output.len(), 1120);

    let (sk, pk) = cs.signature_key_generate().unwrap();
    assert_eq!(pk.as_bytes().len(), 1312);
    assert_eq!(cs.sign(&sk, b"message").unwrap().len(), 2420);
}

fn client(name: &str) -> Client<impl MlsConfig> {
    let (secret, public) = suite_a().signature_key_generate().unwrap();
    let credential = BasicCredential::new(name.as_bytes().to_vec()).into_credential();

    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(SuiteAProvider)
        .signing_identity(SigningIdentity::new(credential, public), secret, SUITE_A)
        .build()
}

#[test]
fn group_lifecycle() {
    let alice = client("alice");
    let bob = client("bob");
    let charlie = client("charlie");

    let mut alice_group = alice.group_builder().unwrap().build().unwrap();

    let bob_kp = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let commit = alice_group
        .commit_builder()
        .add_member(bob_kp)
        .unwrap()
        .build()
        .unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (mut bob_group, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .unwrap();

    let commit = bob_group.commit_builder().build().unwrap();
    bob_group.apply_pending_commit().unwrap();
    alice_group
        .process_incoming_message(commit.commit_message)
        .unwrap();

    let group_info = alice_group
        .group_info_message_allowing_ext_commit(true)
        .unwrap();
    let (mut charlie_group, commit) = charlie
        .external_commit_builder()
        .unwrap()
        .build(group_info)
        .unwrap();
    alice_group
        .process_incoming_message(commit.clone())
        .unwrap();
    bob_group.process_incoming_message(commit).unwrap();

    let secret = alice_group.export_secret(b"suite a", b"", 32).unwrap();
    for g in [&bob_group, &charlie_group] {
        assert_eq!(g.cipher_suite(), SUITE_A);
        assert_eq!(g.current_epoch(), alice_group.current_epoch());
        assert_eq!(
            g.export_secret(b"suite a", b"", 32).unwrap().as_bytes(),
            secret.as_bytes()
        );
    }

    let msg = charlie_group
        .encrypt_application_message(b"hello", Default::default())
        .unwrap();
    for g in [&mut alice_group, &mut bob_group] {
        match g.process_incoming_message(msg.clone()).unwrap() {
            ReceivedMessage::ApplicationMessage(m) => assert_eq!(m.data(), b"hello"),
            other => panic!("unexpected message {other:?}"),
        }
    }
}
