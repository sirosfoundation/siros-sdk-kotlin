//! DEMO ONLY. The ZKP demo wallet's BBS demo issuer: issues the nym_auth attestation in its `bbs_cd`
//! encoding to a device key on the phone (a StrongBox key), under an issuer derived from a seed the
//! demo app bundles. Not an issuer: the seed is demo material, and anyone holding it can issue.
//!
//! The issuance is community-demo's `bbs-issuer` (and the ZKP demo wallet core's `bbs_hw.rs`):
//! the device key attested by a demo manufacturer key made for the call (the `ecdsa-pop` plugin's
//! key handler; the verifier does not check the attestation), the birth date, and the `secret_seed`
//! attribute hash_to_scalar(secret_seed, "nym_auth/v1/bbs-seed"), so the BBS pseudonym follows the
//! holder's mdoc seed. The credential is verified before it is returned.

uniffi::setup_scaffolding!();

use bbs_cd::params::Ciphersuite;
use bbs_cd::utils::hash_to_scalar;
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use cd_date_range::{DateHandler, date_input};
use cd_ecdsa_pop::Mode;
use cd_ecdsa_pop::attestation::{Manufacturer, P256KeyHandler, key_input};
use cd_pseudonym::NymSeedHandler;
use nym_bbs::credential::CredentialJson;
use nym_bbs::profile;
use p256::ecdsa::VerifyingKey;

/// The DST of the seed derivation (community-demo `bbs-issuer`, `docs/bbs_cd.md`).
const SEED_DST: &[u8] = b"nym_auth/v1/bbs-seed";

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DemoIssuerError {
  /// A key, date or seed of the wrong form.
  #[error("invalid input: {detail}")]
  InvalidInput { detail: String },
  /// The issuance failed (or its credential does not verify).
  #[error("issuance failed: {detail}")]
  Failed { detail: String },
}

fn failed(detail: impl std::fmt::Debug) -> DemoIssuerError {
  DemoIssuerError::Failed { detail: format!("{detail:?}") }
}

fn invalid(detail: &str) -> DemoIssuerError {
  DemoIssuerError::InvalidInput { detail: detail.into() }
}

fn issuer(issuer_seed: &[u8], manufacturer: &Manufacturer) -> Result<Issuer, DemoIssuerError> {
  if issuer_seed.len() < 32 {
    return Err(invalid("the issuer seed is shorter than 32 bytes"));
  }
  Issuer::from_seed(
    profile::schema().map_err(failed)?,
    vec![Box::new(P256KeyHandler::new(vec![manufacturer.public_key()], Mode::Hashed)), Box::new(DateHandler), Box::new(NymSeedHandler)],
    issuer_seed,
  )
  .map_err(failed)
}

/// The demo issuer's parameters (`IssuerParams::encode`: its public key and the schema), as a BBS
/// verifier takes them (community-demo's `issuer-params.bin`). The same for every call with a seed.
#[uniffi::export]
pub fn bbs_demo_issuer_params(issuer_seed: Vec<u8>) -> Result<Vec<u8>, DemoIssuerError> {
  Ok(issuer(&issuer_seed, &Manufacturer::new())?.params.encode())
}

/// One holder's `bbs_cd` credential (JSON, community-demo's `CredentialJson`) under the issuer of
/// `issuer_seed`, bound to `device_public_key` (SEC1 P-256), for `birth_date` (`YYYY-MM-DD`) and the
/// holder's 16-byte `secret_seed`.
#[uniffi::export]
pub fn bbs_demo_issue(issuer_seed: Vec<u8>, device_public_key: Vec<u8>, birth_date: String, secret_seed: Vec<u8>) -> Result<String, DemoIssuerError> {
  if secret_seed.len() != 16 {
    return Err(invalid("secret_seed is not 16 bytes"));
  }
  let key = VerifyingKey::from_sec1_bytes(&device_public_key).map_err(|_| invalid("the device key is not a P-256 public key"))?;
  let device: [u8; 33] = key.to_encoded_point(true).as_bytes().try_into().map_err(|_| invalid("the device key"))?;
  let valid_date = birth_date.len() == 10 && birth_date.as_bytes()[4] == b'-' && birth_date.as_bytes()[7] == b'-' && birth_date.chars().filter(char::is_ascii_digit).count() == 8;
  if !valid_date {
    return Err(invalid("birth_date is not YYYY-MM-DD"));
  }
  let seed = hash_to_scalar(Ciphersuite::Sha256, &secret_seed, SEED_DST).map_err(failed)?.0;
  if seed == [0u8; 32] {
    return Err(failed("the seed scalar is zero: not issued"));
  }
  let manufacturer = Manufacturer::new();
  let attestation = manufacturer.attest(&device, Mode::Hashed);
  let credential = issuer(&issuer_seed, &manufacturer)?
    .issue(&[AttrValue::Input(key_input(&device, &attestation)), AttrValue::Input(date_input(&birth_date)), AttrValue::Input(seed.to_vec())])
    .map_err(failed)?;
  credential.verify().map_err(failed)?;
  serde_json::to_string(&CredentialJson::from_credential(&credential)).map_err(failed)
}
