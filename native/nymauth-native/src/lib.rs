//! Native nymauth provers for the SIROS SDKs, through UniFFI.
//!
//! | Module | Role |
//! | --- | --- |
//! | [`longfellow`] | The nym_auth mdoc circuits on Google's longfellow-zk Rust runtime (community-demo's nym-longfellow): load, prove, verify |
//! | [`error`] | Coarse error kinds that carry no native detail |
//!
//! The request a prover takes is exactly the SDK's `NymAuthProveRequest` (the values both sides
//! know, and the holder's private ones), so an SDK binding is a field-for-field copy. A circuit is
//! proved only if it is an approved build: its parameters and the SHA-256 and length of its
//! decompressed bytes are pinned here, with the slot map that goes with it.

uniffi::setup_scaffolding!();

#[cfg(feature = "counting-alloc")]
mod alloc;
pub mod error;
#[cfg(feature = "longfellow")]
pub mod longfellow;

pub use error::{NymAuthNativeError, NymAuthRefusal};

/// The nym_auth docType.
pub const NYM_AUTH_DOCTYPE: &str = "eu.europa.ec.eudi.nym_auth.1";

/// This library and the runtimes it carries, for logs and benchmark records.
#[uniffi::export]
pub fn nymauth_native_version() -> String {
  let mut parts = vec![format!("nymauth-native {}", env!("CARGO_PKG_VERSION"))];
  #[cfg(feature = "longfellow")]
  parts.push(nym_longfellow::circuit::RUNTIME.to_string());
  parts.join("; ")
}

/// e2: SHA-256 of the DeviceAuthentication message for `doc_type` over `transcript_seed` (the
/// SessionTranscript), the digest the device key signs (nym_auth circuit spec, section 3).
#[cfg(feature = "longfellow")]
#[uniffi::export]
pub fn nymauth_challenge_digest(transcript_seed: Vec<u8>, doc_type: String) -> Vec<u8> {
  nym_longfellow::handover::challenge_digest(&transcript_seed, &doc_type).to_vec()
}

/// The pseudonym's `verifier_input` for `known-offender-matching-ssc` with `prf` `sha-256`: SHA-256(verifier_id).
#[uniffi::export]
pub fn nymauth_verifier_input(verifier_id: String) -> Vec<u8> {
  use sha2::Digest;
  sha2::Sha256::digest(verifier_id.as_bytes()).to_vec()
}
