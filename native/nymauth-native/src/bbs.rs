//! The nym_auth attestation in its `bbs_cd` encoding (rulebook v0.4): one `zkp_req` presentation from
//! a BBS credential with committed disclosures, through community-demo's `nym-bbs` (the code its
//! verifier checks against) on sirosfoundation/bbs-cd-plugins.
//!
//! The device key never comes here. `nym-bbs`'s `Prover::prove_with` asks the caller's
//! [`BbsDeviceSigner`] for the one ecdsa-pop signature (hashed mode: ECDSA-P256-SHA256 over the
//! plugin's device message, which binds the request's nonce): a StrongBox or TEE key in the SDK.
//! Each signature is checked against the device key before it is used.
//!
//! The statement (the BBS request with its audience, the OpenID4VPHandoverInfo hash, and the plugins)
//! is derived from the verified Request Object and its handover by `nym-bbs`, as the verifier derives
//! it; the age range is checked before the device is asked, so an unmet request signs nothing.

use std::sync::{Arc, Mutex};

use bbs_cd_plugin::error::Error as PluginError;
use cd_ecdsa_pop::HashSigner;
use nym_bbs::credential::CredentialJson;
use nym_bbs::profile::{Handover, RequestObject};
use nym_bbs::prover::{PresentInput, Prover};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value as Json;

use crate::error::{NymAuthNativeError as E, NymAuthRefusal};

/// The device key's signer, implemented by the host (Kotlin: a StrongBox key; tests: a software key).
#[uniffi::export(with_foreign)]
pub trait BbsDeviceSigner: Send + Sync {
  /// ECDSA-P256 with SHA-256 over `message` (the signer hashes), as raw `r || s` (64 bytes). An error
  /// here (the user cancelled, the key is gone) ends the presentation with that error.
  fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, E>;
}

/// The OpenID4VPHandover values of the request (OpenID4VP 1.0 B.2.6.1): what the BBS audience binds.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BbsHandover {
  pub client_id: String,
  pub nonce: String,
  pub response_uri: String,
  /// The RFC 7638 thumbprint of the response-encryption key (`direct_post.jwt`); null when unencrypted.
  pub jwk_thumbprint: Option<String>,
}

/// Where the time and memory of one presentation went, in community-demo's meaning.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BbsProveMetrics {
  /// Building the date-range tables when the prover loaded.
  pub load_ms: f64,
  /// The BBS commitments and the ecdsa-pop preparation (independent of the request's nonce).
  pub offline_ms: f64,
  pub bbs_ms: f64,
  pub ecdsa_pop_ms: Option<f64>,
  /// The device signature inside ecdsa-pop (the key store's time).
  pub device_sign_ms: f64,
  pub pseudonym_ms: Option<f64>,
  pub date_range_ms: Option<f64>,
  pub online_ms: f64,
  pub prove_ms: f64,
  pub total_ms: f64,
  /// The most heap this library held above what it held when the presentation began.
  pub heap_mb: Option<f64>,
  /// The BBS envelope (the `ZkpPresentation`'s `proof`).
  pub proof_bytes: u64,
  pub presentation_bytes: u64,
  pub threads: u32,
}

/// One `bbs_cd` presentation.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BbsPresentation {
  /// The `ZkpPresentation` (CBOR): `system_id`, the envelope as `proof`, the issuer key as `issuer_key_set`, `results`.
  pub presentation: Vec<u8>,
  pub system_id: String,
  /// The `return` handle of the pseudonym, and its value (the 48-byte G1 point).
  pub pseudonym_handle: String,
  pub pseudonym: Vec<u8>,
  /// The handles of the predicates proved true (`age_check`).
  pub predicate_handles: Vec<String>,
  pub metrics: BbsProveMetrics,
}

/// The BBS prover: the date-range tables, built once.
#[derive(uniffi::Object)]
pub struct BbsProver {
  inner: Prover,
}

#[uniffi::export]
impl BbsProver {
  #[uniffi::constructor]
  pub fn load() -> Arc<Self> {
    Arc::new(BbsProver { inner: Prover::load() })
  }

  /// The presentation for the `zkp_req` query `credential_query_id` of `request_object` (the verified
  /// Request Object, JSON), from `credential` (the stored `bbs_cd` credential, JSON), with the device
  /// key `device_public_key` (SEC1 P-256, compressed or not) signing through `signer`.
  ///
  /// Errors: [`E::InvalidInput`] for a request, handover or key this cannot read;
  /// [`E::UnsupportedCircuit`] when the request does not offer this scheme; refusals
  /// `Unsatisfied` (the birth date is outside the asked range: nothing is signed), `Credential` (the
  /// credential is not the profile's or its issuer's signature fails) and `DeviceSignature` (the
  /// signer's answer is not a valid signature by the device key); the signer's own error as it
  /// raised it.
  #[allow(clippy::too_many_arguments)]
  pub fn prove(
    &self,
    request_object: String,
    credential_query_id: String,
    handover: BbsHandover,
    credential: String,
    device_public_key: Vec<u8>,
    signer: Arc<dyn BbsDeviceSigner>,
    parallel: bool,
  ) -> Result<BbsPresentation, E> {
    let request: RequestObject = serde_json::from_str(&request_object).map_err(|_| E::InvalidInput)?;
    let credential: CredentialJson = serde_json::from_str(&credential).map_err(|_| E::refused(NymAuthRefusal::Credential))?;
    let key = VerifyingKey::from_sec1_bytes(&device_public_key).map_err(|_| E::InvalidInput)?;
    let handover = Handover {
      client_id: handover.client_id,
      nonce: handover.nonce,
      response_uri: handover.response_uri,
      jwk_thumbprint: handover.jwk_thumbprint,
    };
    let device = Device { signer: signer.as_ref(), key, failed: Mutex::new(None) };
    let input = PresentInput {
      request: &request,
      credential_query_id: &credential_query_id,
      handover: &handover,
      credential: &credential,
      parallel,
    };
    let out = {
      let _one = nym_bbs::measure::exclusive().map_err(|_| E::Internal)?;
      self.inner.prove_with(&input, &device)
    };
    if let Some(e) = device.failed.lock().map_err(|_| E::Internal)?.take() {
      return Err(e);
    }
    let out = out.map_err(|r| refusal(r.error))?;
    presentation(&out)
  }
}

/// The host's signer as the ecdsa-pop plugin's hashed-mode signer. The first failure is kept, so the
/// caller gets the signer's own error rather than the plugin's.
struct Device<'a> {
  signer: &'a dyn BbsDeviceSigner,
  key: VerifyingKey,
  failed: Mutex<Option<E>>,
}

impl Device<'_> {
  fn fail(&self, e: E) -> PluginError {
    if let Ok(mut f) = self.failed.lock() {
      f.get_or_insert(e);
    }
    PluginError::Prover("device signature".into())
  }
}

impl HashSigner for Device<'_> {
  fn hash_public_key(&self) -> bbs_cd_plugin::error::Result<[u8; 33]> {
    self.key.to_encoded_point(true).as_bytes().try_into().map_err(|_| PluginError::Prover("device key".into()))
  }

  fn sign_message(&self, msg: &[u8]) -> bbs_cd_plugin::error::Result<(p256::Scalar, p256::Scalar)> {
    let raw = self.signer.sign(msg.to_vec()).map_err(|e| self.fail(e))?;
    let sig = Signature::from_slice(&raw).map_err(|_| self.fail(E::refused(NymAuthRefusal::DeviceSignature)))?;
    self.key.verify(msg, &sig).map_err(|_| self.fail(E::refused(NymAuthRefusal::DeviceSignature)))?;
    let (r, s) = sig.split_scalars();
    Ok((*r, *s))
  }
}

/// nym-bbs's refusal codes (community-demo `docs/backend-api.md`) as this library's coarse errors.
fn refusal(code: &str) -> E {
  match code {
    "unsatisfiable" => E::refused(NymAuthRefusal::Unsatisfied),
    "bad_credential" => E::refused(NymAuthRefusal::Credential),
    "unsupported_circuit" => E::UnsupportedCircuit,
    "unsupported_request" | "unsupported_config" | "unsupported_function" | "bad_request" => E::InvalidInput,
    _ => E::Internal,
  }
}

/// nym-bbs's answer (`system_id`, `presentation` base64url, `results`, `metrics`) as a record.
fn presentation(out: &Json) -> Result<BbsPresentation, E> {
  let text = |k: &str| out.get(k).and_then(Json::as_str).ok_or(E::Internal);
  let bytes = nym_bbs::unb64url("presentation", text("presentation")?).map_err(|_| E::Internal)?;
  let mut pseudonym = None;
  let mut predicates = Vec::new();
  for (handle, value) in out.get("results").and_then(Json::as_object).ok_or(E::Internal)? {
    match value {
      Json::String(nym) => pseudonym = Some((handle.clone(), hex::decode(nym).map_err(|_| E::Internal)?)),
      Json::Bool(true) => predicates.push(handle.clone()),
      _ => return Err(E::Internal),
    }
  }
  let (pseudonym_handle, pseudonym) = pseudonym.ok_or(E::Internal)?;
  let m = out.get("metrics").ok_or(E::Internal)?;
  let f = |k: &str| m.get(k).and_then(Json::as_f64);
  let n = |k: &str| m.get(k).and_then(Json::as_u64).unwrap_or(0);
  Ok(BbsPresentation {
    presentation: bytes,
    system_id: text("system_id")?.to_string(),
    pseudonym_handle,
    pseudonym,
    predicate_handles: predicates,
    metrics: BbsProveMetrics {
      load_ms: f("load_ms").unwrap_or(0.0),
      offline_ms: f("offline_ms").unwrap_or(0.0),
      bbs_ms: f("bbs_ms").unwrap_or(0.0),
      ecdsa_pop_ms: f("ecdsa_pop_ms"),
      device_sign_ms: f("device_sign_ms").unwrap_or(0.0),
      pseudonym_ms: f("pseudonym_ms"),
      date_range_ms: f("date_range_ms"),
      online_ms: f("online_ms").unwrap_or(0.0),
      prove_ms: f("prove_ms").unwrap_or(0.0),
      total_ms: f("total_ms").unwrap_or(0.0),
      heap_mb: f("heap_mb"),
      proof_bytes: n("proof_bytes"),
      presentation_bytes: n("presentation_bytes"),
      threads: n("threads") as u32,
    },
  })
}
