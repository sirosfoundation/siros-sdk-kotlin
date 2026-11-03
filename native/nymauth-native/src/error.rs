//! The errors every entry point returns: coarse kinds that mirror the SDK's `NymAuthNativeErrorKind`
//! and `NymAuthRefusal`, and carry nothing the native side computed (no digest, rule or value), so
//! nothing a verifier could learn from leaks through a log or an exception message.

/// Why the prover refused to make a proof for holder data that does not fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NymAuthRefusal {
  /// `SHA-256(secret_seed)` is not the credential's `ssc`.
  SeedMismatch,
  /// The issuer's signature on the MSO does not verify under the given issuer key.
  IssuerSignature,
  /// The device signature does not verify on `e2` under the credential's device key.
  DeviceSignature,
  /// The credential is not a nym_auth mdoc these circuits read (docType, items, issuer key).
  Credential,
  /// The credential cannot meet the request: not valid at `time`, or the birth date outside `[earliest, cutoff]`.
  Unsatisfied,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum NymAuthNativeError {
  /// An argument has the wrong size, format or range, or `challenge_digest` is not the digest of
  /// `transcript_seed` under DeviceAuthentication.
  #[error("invalid input")]
  InvalidInput,
  /// The circuit bytes or parameters are not the approved build they claim to be.
  #[error("invalid circuit")]
  InvalidCircuit,
  /// No approved build has this circuit id: this library cannot prove it.
  #[error("unsupported circuit")]
  UnsupportedCircuit,
  /// The holder data does not fit (see [`NymAuthRefusal`]).
  #[error("refused: {refusal:?}")]
  Refused { refusal: NymAuthRefusal },
  /// The proof system failed on inputs that passed every check.
  #[error("prover failed")]
  ProverFailed,
  /// A proof does not verify.
  #[error("proof invalid")]
  ProofInvalid,
  /// The proof verifies, but not for the pseudonym given.
  #[error("pseudonym mismatch")]
  Mismatch,
  /// A failure of this library itself.
  #[error("internal error")]
  Internal,
}

impl NymAuthNativeError {
  pub(crate) fn refused(refusal: NymAuthRefusal) -> Self {
    NymAuthNativeError::Refused { refusal }
  }
}
