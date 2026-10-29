//! Longfellow for the nym_auth mdoc circuits, on Google's longfellow-zk Rust runtime, through
//! community-demo's nym-longfellow (the code its verifier runs).
//!
//! [`LongfellowProver::load`] takes the circuit as the SDK's catalog delivers it (the decompressed
//! LFC2 pair, the descriptor's parameters and the compressed artifact's hash) and proves it only if
//! it is an approved build ([`APPROVED`]). [`LongfellowProver::prove`] checks the holder's data as
//! the circuits will (so it refuses with a reason instead of failing inside the proof), builds the
//! witness and proves. [`LongfellowVerifier`] verifies a proof against the public values.

use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use nym_longfellow::measure::{Heap, mb, ms};
use nym_longfellow::witness::{Layout, Private, Public};
use nym_longfellow::x509::PublicKey;
use nym_longfellow::zk::{Circuits, ZkProverPair, ZkVerifierPair};
use nym_longfellow::{dates, handover, mdoc, x509};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::NYM_AUTH_DOCTYPE;
use crate::error::{NymAuthNativeError as E, NymAuthRefusal as R};

/// One approved circuit build: what the catalog descriptor must say, the decompressed artifact's
/// exact length and SHA-256, and the build's `params.tsv` and `hash-semantic.tsv` (sizes and slot map).
pub struct Approved {
  pub hash_circuit_id: &'static str,
  pub sig_circuit_id: &'static str,
  pub block_enc_hash: u32,
  pub block_enc_sig: u32,
  pub artifact_len: usize,
  pub artifact_sha256: &'static str,
  params_tsv: &'static str,
  semantic_tsv: &'static str,
}

/// The builds this library proves. To approve a new build, the circuit authors supply its artifact
/// (length and SHA-256), its two circuit ids and `block_enc` values, and its `params.tsv` and
/// `hash-semantic.tsv`; add them under `circuits/` and append an entry. Nothing else names a circuit.
pub const APPROVED: &[Approved] = &[Approved {
  // nym-auth-circuits archive, longfellow/mdoc: community-demo's native/longfellow/circuits/mdoc.
  hash_circuit_id: "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729",
  sig_circuit_id: "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb",
  block_enc_hash: 6983,
  block_enc_sig: 4679,
  artifact_len: 1_062_842,
  artifact_sha256: "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f",
  params_tsv: include_str!("../circuits/longfellow-mdoc/params.tsv"),
  semantic_tsv: include_str!("../circuits/longfellow-mdoc/hash-semantic.tsv"),
}];

/// The catalog descriptor's parameters of a Longfellow nym_auth circuit.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LongfellowCircuitParams {
  pub block_enc_hash: u32,
  pub block_enc_sig: u32,
  pub hash_circuit_id: String,
  pub sig_circuit_id: String,
}

/// The SDK's `NymAuthProveRequest`, field for field (without the catalog fields the binding uses to load).
#[derive(uniffi::Record)]
pub struct LongfellowProveRequest {
  /// The IssuerSigned CBOR of the nym_auth mdoc.
  pub issuer_signed: Vec<u8>,
  /// The issuer-delivered `secret_seed`, 16 bytes. This library zeroes its copies.
  pub secret_seed: Vec<u8>,
  /// The issuer key Q (the Document Signer's), 32 bytes each.
  pub issuer_key_x: Vec<u8>,
  pub issuer_key_y: Vec<u8>,
  /// T, `YYYY-MM-DDThh:mm:ssZ`.
  pub time: String,
  /// E and C, `YYYY-MM-DD` (`0000-00-00` and `9999-12-31` for an open end).
  pub earliest: String,
  pub cutoff: String,
  /// e2, 32 bytes: the digest the device key signed.
  pub challenge_digest: Vec<u8>,
  /// The device key's signature on e2, `r || s`, 64 bytes.
  pub device_signature: Vec<u8>,
  /// SHA-256(verifier_id), 32 bytes.
  pub verifier_input: Vec<u8>,
  /// The SessionTranscript: seeds the proof's transcript; e2 must be its DeviceAuthentication digest.
  pub transcript_seed: Vec<u8>,
}

/// The public values of a proof, for [`LongfellowVerifier::verify`].
#[derive(uniffi::Record)]
pub struct LongfellowPublicValues {
  pub issuer_key_x: Vec<u8>,
  pub issuer_key_y: Vec<u8>,
  pub time: String,
  pub earliest: String,
  pub cutoff: String,
  pub challenge_digest: Vec<u8>,
  pub verifier_input: Vec<u8>,
  pub transcript_seed: Vec<u8>,
}

/// Where the time and memory of one proof went, in community-demo's meaning.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LongfellowProveMetrics {
  pub witness_ms: f64,
  pub prove_ms: f64,
  pub total_ms: f64,
  /// The most heap this library held above what it held when the proof began (witness and proof).
  pub heap_mb: Option<f64>,
  /// The witness held into the proof (part of `heap_mb`).
  pub witness_mb: Option<f64>,
}

/// A proof: the bytes (tags, then the hash and the signature circuit's proofs), the pseudonym it
/// reveals, and its metrics.
#[derive(uniffi::Record)]
pub struct LongfellowProof {
  pub proof: Vec<u8>,
  pub pseudonym: Vec<u8>,
  pub metrics: LongfellowProveMetrics,
}

/// What loading the circuits cost.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LongfellowLoadMetrics {
  pub load_ms: f64,
  /// The heap the loaded circuits keep.
  pub keys_mb: Option<f64>,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
  hex::decode(s).ok()?.try_into().ok()
}

fn bytes<const N: usize>(v: &[u8]) -> Result<[u8; N], E> {
  v.try_into().map_err(|_| E::InvalidInput)
}

/// The approved build `params` names, with `circuit` checked against it, as loaded circuits.
fn circuits(circuit: &[u8], params: &LongfellowCircuitParams, artifact_hash: &str) -> Result<Circuits, E> {
  let a = APPROVED
    .iter()
    .find(|a| a.hash_circuit_id.eq_ignore_ascii_case(&params.hash_circuit_id))
    .ok_or(E::UnsupportedCircuit)?;
  if !a.sig_circuit_id.eq_ignore_ascii_case(&params.sig_circuit_id)
    || a.block_enc_hash != params.block_enc_hash
    || a.block_enc_sig != params.block_enc_sig
  {
    return Err(E::InvalidCircuit);
  }
  // Length first: nothing is hashed or parsed for bytes that cannot be the build.
  if circuit.len() != a.artifact_len || hex32(a.artifact_sha256) != Some(Sha256::digest(circuit).into()) {
    return Err(E::InvalidCircuit);
  }
  let zst_sha256 = artifact_hash.strip_prefix("sha256:").and_then(hex32).ok_or(E::InvalidInput)?;
  let layout = Layout::parse(a.params_tsv, a.semantic_tsv).map_err(|_| E::Internal)?;
  Circuits::from_pair(layout, circuit, zst_sha256).map_err(|_| E::InvalidCircuit)
}

/// The prover side, built once per circuit (it is the resident state the SDK keeps).
#[derive(uniffi::Object)]
pub struct LongfellowProver {
  pair: ZkProverPair,
  load: LongfellowLoadMetrics,
}

#[uniffi::export]
impl LongfellowProver {
  /// Loads an approved circuit build. `circuit` is the decompressed artifact, `artifact_hash` the
  /// catalog's `sha256:<hex>` of the compressed one.
  #[uniffi::constructor]
  pub fn load(circuit: Vec<u8>, params: LongfellowCircuitParams, artifact_hash: String) -> Result<Arc<Self>, E> {
    let t = Instant::now();
    let heap = Heap::start();
    let c = circuits(&circuit, &params, &artifact_hash)?;
    drop(circuit);
    let pair = ZkProverPair::new(c);
    let load = LongfellowLoadMetrics { load_ms: ms(t), keys_mb: mb(heap.held()) };
    Ok(Arc::new(LongfellowProver { pair, load }))
  }

  pub fn load_metrics(&self) -> LongfellowLoadMetrics {
    self.load.clone()
  }

  /// Proves the statement for [`LongfellowProveRequest`], after checking the holder's data as the
  /// circuits will (each misfit is a [`NymAuthRefusal`], before anything is committed).
  pub fn prove(&self, request: LongfellowProveRequest) -> Result<LongfellowProof, E> {
    let t = Instant::now();
    let heap = Heap::start();
    let seed = Zeroizing::new(bytes::<16>(&request.secret_seed)?);
    let public = public_values(
      &request.issuer_key_x,
      &request.issuer_key_y,
      &request.time,
      &request.earliest,
      &request.cutoff,
      &request.challenge_digest,
      &request.verifier_input,
      &request.transcript_seed,
    )?;
    let device: [u8; 64] = bytes(&request.device_signature)?;

    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&request.issuer_signed);
    let m = mdoc::parse(&encoded).map_err(|_| E::refused(R::Credential))?;
    if m.doc_type != NYM_AUTH_DOCTYPE || !m.digests_listed() {
      return Err(E::refused(R::Credential));
    }
    // The issuer key the SDK took from the x5chain leaf is the Document Signer's in the MSO.
    let signer = x509::parse(&m.document_signer).map_err(|_| E::refused(R::Credential))?;
    if signer.key != public.issuer_key {
      return Err(E::refused(R::Credential));
    }
    let issuer = verifying_key(&public.issuer_key).ok_or(E::refused(R::Credential))?;
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&m.r);
    rs[32..].copy_from_slice(&m.s);
    let issuer_sig = Signature::from_slice(&rs).map_err(|_| E::refused(R::IssuerSignature))?;
    issuer.verify(&m.signed, &issuer_sig).map_err(|_| E::refused(R::IssuerSignature))?;
    if Sha256::digest(&seed[..]).as_slice() != m.ssc {
      return Err(E::refused(R::SeedMismatch));
    }
    let device_key = verifying_key(&m.device_key).ok_or(E::refused(R::Credential))?;
    let device_sig = Signature::from_slice(&device).map_err(|_| E::refused(R::DeviceSignature))?;
    device_key.verify_prehash(&public.challenge, &device_sig).map_err(|_| E::refused(R::DeviceSignature))?;

    // The holder's data against the request: valid at T, the birth date in [E, C].
    let at = dates::unix(&dates::date_time(&public.time).map_err(|_| E::InvalidInput)?);
    if !(dates::unix(&m.valid_from) <= at && at < dates::unix(&m.valid_until)) {
      return Err(E::refused(R::Unsatisfied));
    }
    let born = m.birth_date.text();
    if born < public.earliest || born > public.cutoff {
      return Err(E::refused(R::Unsatisfied));
    }

    let private = Private { mdoc: &m, secret_seed: *seed, device_signature: device };
    let w = nym_longfellow::witness::witness(&self.pair.layout, &public, &private).map_err(|_| E::ProverFailed)?;
    let witness_ms = ms(t);
    let witness_high = heap.high();
    let tp = Instant::now();
    let proved = self.pair.prove(w, &request.transcript_seed).map_err(|_| E::ProverFailed)?;
    let prove_ms = ms(tp);
    Ok(LongfellowProof {
      proof: proved.proof,
      pseudonym: proved.nym.to_vec(),
      metrics: LongfellowProveMetrics {
        witness_ms,
        prove_ms,
        total_ms: ms(t),
        heap_mb: mb(heap.high().saturating_sub(heap.base())),
        witness_mb: mb(witness_high.saturating_sub(heap.base())),
      },
    })
  }
}

/// The verifier side, built once per circuit.
#[derive(uniffi::Object)]
pub struct LongfellowVerifier {
  pair: ZkVerifierPair,
}

#[uniffi::export]
impl LongfellowVerifier {
  #[uniffi::constructor]
  pub fn load(circuit: Vec<u8>, params: LongfellowCircuitParams, artifact_hash: String) -> Result<Arc<Self>, E> {
    Ok(Arc::new(LongfellowVerifier { pair: ZkVerifierPair::new(circuits(&circuit, &params, &artifact_hash)?) }))
  }

  /// Verifies `proof` for the public values and `pseudonym`: [`E::ProofInvalid`] when it does not
  /// verify, [`E::InvalidInput`] for malformed values.
  pub fn verify(&self, values: LongfellowPublicValues, proof: Vec<u8>, pseudonym: Vec<u8>) -> Result<(), E> {
    let public = public_values(
      &values.issuer_key_x,
      &values.issuer_key_y,
      &values.time,
      &values.earliest,
      &values.cutoff,
      &values.challenge_digest,
      &values.verifier_input,
      &values.transcript_seed,
    )?;
    let nym: [u8; 32] = bytes(&pseudonym)?;
    self.pair.verify(&proof, &public, &nym, &values.transcript_seed).map_err(|_| E::ProofInvalid)
  }
}

fn verifying_key(k: &PublicKey) -> Option<VerifyingKey> {
  let mut sec1 = [0u8; 65];
  sec1[0] = 4;
  sec1[1..33].copy_from_slice(&k.x);
  sec1[33..].copy_from_slice(&k.y);
  VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// The values both sides know, checked: sizes, T and the bounds well formed (an open end is the
/// sentinel), E ≤ C, a transcript of 32 B to 64 KiB, and e2 the DeviceAuthentication digest of it.
#[allow(clippy::too_many_arguments)]
fn public_values(
  x: &[u8],
  y: &[u8],
  time: &str,
  earliest: &str,
  cutoff: &str,
  challenge: &[u8],
  verifier_input: &[u8],
  transcript: &[u8],
) -> Result<Public, E> {
  let issuer_key = PublicKey { x: bytes(x)?, y: bytes(y)? };
  verifying_key(&issuer_key).ok_or(E::InvalidInput)?;
  dates::date_time(time).map_err(|_| E::InvalidInput)?;
  if time.len() != 20 {
    return Err(E::InvalidInput);
  }
  let bound = |d: &str, open: &str| d == open || (d.len() == 10 && dates::date(d).is_ok());
  if !bound(earliest, "0000-00-00") || !bound(cutoff, "9999-12-31") || earliest > cutoff {
    return Err(E::InvalidInput);
  }
  if !(32..=65_536).contains(&transcript.len()) {
    return Err(E::InvalidInput);
  }
  let challenge: [u8; 32] = bytes(challenge)?;
  if handover::challenge_digest(transcript, NYM_AUTH_DOCTYPE) != challenge {
    return Err(E::InvalidInput);
  }
  Ok(Public {
    time: time.to_string(),
    earliest: earliest.to_string(),
    cutoff: cutoff.to_string(),
    verifier_input: bytes(verifier_input)?,
    issuer_key,
    challenge,
  })
}
