//! Proves with the teen's demo mdoc for a request captured from community-demo, and checks the proof
//! three ways: this library's verifier, community-demo's own verifier on a full ZkpPresentation (the
//! code fly.dev runs), and the refusals.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nym_longfellow::presentation::{Presentation, ResultValue};
use nym_longfellow::{handover, mdoc, x509};
use nymauth_native::longfellow::{
  APPROVED, LongfellowCircuitParams, LongfellowProveRequest, LongfellowProver, LongfellowPublicValues, LongfellowVerifier,
};
use nymauth_native::{NymAuthNativeError as E, NymAuthRefusal as R, nymauth_challenge_digest, nymauth_verifier_input};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::{Value, json};

const TEEN_PSEUDONYM: &str = "61266c285395e6fa97f3fa2d93ee428de03d99e9e0e62a3fcc38664faaaa4c30";

fn circuits_dir() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../readdit-demo/native/longfellow/circuits/mdoc")
}

fn fixture() -> Value {
  serde_json::from_str(include_str!("fixtures/teen-request.json")).unwrap()
}

fn s(v: &Value, k: &str) -> String {
  v[k].as_str().unwrap().to_string()
}

fn b64(s: &str) -> Vec<u8> {
  use base64::Engine;
  base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

/// The decompressed circuit, the descriptor's params and the compressed artifact's hash, as the SDK's catalog delivers them.
fn circuit() -> (Vec<u8>, LongfellowCircuitParams, String) {
  use sha2::Digest;
  let zst = std::fs::read(circuits_dir().join("circuits.zst")).unwrap();
  let pair = zstd::decode_all(&zst[..]).unwrap();
  let a = &APPROVED[0];
  let params = LongfellowCircuitParams {
    block_enc_hash: a.block_enc_hash,
    block_enc_sig: a.block_enc_sig,
    hash_circuit_id: a.hash_circuit_id.into(),
    sig_circuit_id: a.sig_circuit_id.into(),
  };
  (pair, params, format!("sha256:{}", hex::encode(sha2::Sha256::digest(&zst))))
}

fn prover() -> Arc<LongfellowProver> {
  let (c, p, h) = circuit();
  LongfellowProver::load(c, p, h).unwrap()
}

struct Case {
  request: LongfellowProveRequest,
  transcript: Vec<u8>,
  document_signer: Vec<u8>,
}

/// The request as the SDK's adapter builds it: Q from the x5chain leaf, T now, E and C from the
/// age_check, e2 from the redirect handover, the device signature on e2, SHA-256(verifier_id).
fn case() -> Case {
  let f = fixture();
  let h = &f["handover"];
  let thumb: [u8; 32] = b64(&s(h, "jwk_thumbprint")).try_into().unwrap();
  let transcript = handover::session_transcript(&s(h, "client_id"), &s(h, "nonce"), Some(&thumb), &s(h, "response_uri"));
  let e2 = nymauth_challenge_digest(transcript.clone(), nymauth_native::NYM_AUTH_DOCTYPE.into());
  let issuer_signed = s(&f["credential"], "issuer_signed");
  let m = mdoc::parse(&issuer_signed).unwrap();
  let q = x509::parse(&m.document_signer).unwrap().key;
  let d: [u8; 32] = b64(&s(&f["device_key"], "d")).try_into().unwrap();
  let sig: p256::ecdsa::Signature = SigningKey::from_bytes(&d.into()).unwrap().sign_prehash(&e2).unwrap();
  let sig = sig.normalize_s().unwrap_or(sig);
  let age = &f["request"]["dcql_query"]["credentials"][0]["_req"][1]["params"];
  Case {
    request: LongfellowProveRequest {
      issuer_signed: b64(&issuer_signed),
      secret_seed: hex::decode(s(&f, "secret_seed")).unwrap(),
      issuer_key_x: q.x.to_vec(),
      issuer_key_y: q.y.to_vec(),
      time: nym_longfellow::dates::now().unwrap().text(),
      earliest: s(age, "ge"),
      cutoff: s(age, "le"),
      challenge_digest: e2,
      device_signature: sig.to_bytes().to_vec(),
      verifier_input: nymauth_verifier_input(s(&f, "verifier_id")),
      transcript_seed: transcript.clone(),
    },
    transcript,
    document_signer: m.document_signer.clone(),
  }
}

fn values(r: &LongfellowProveRequest) -> LongfellowPublicValues {
  LongfellowPublicValues {
    issuer_key_x: r.issuer_key_x.clone(),
    issuer_key_y: r.issuer_key_y.clone(),
    time: r.time.clone(),
    earliest: r.earliest.clone(),
    cutoff: r.cutoff.clone(),
    challenge_digest: r.challenge_digest.clone(),
    verifier_input: r.verifier_input.clone(),
    transcript_seed: r.transcript_seed.clone(),
  }
}

/// A copy of `r` (the record is not Clone: UniFFI records that carry a seed stay explicit).
fn again(r: &LongfellowProveRequest) -> LongfellowProveRequest {
  LongfellowProveRequest {
    issuer_signed: r.issuer_signed.clone(),
    secret_seed: r.secret_seed.clone(),
    issuer_key_x: r.issuer_key_x.clone(),
    issuer_key_y: r.issuer_key_y.clone(),
    time: r.time.clone(),
    earliest: r.earliest.clone(),
    cutoff: r.cutoff.clone(),
    challenge_digest: r.challenge_digest.clone(),
    device_signature: r.device_signature.clone(),
    verifier_input: r.verifier_input.clone(),
    transcript_seed: r.transcript_seed.clone(),
  }
}

#[test]
fn proves_the_teen_pseudonym_and_age_and_both_verifiers_accept() {
  let p = prover();
  let load = p.load_metrics();
  println!("load {:.0} ms, keys {:?} MB", load.load_ms, load.keys_mb);
  let c = case();
  let proof = p.prove(again(&c.request)).unwrap();
  println!(
    "proof {} B, witness {:.0} ms, prove {:.0} ms, heap {:?} MB (witness {:?} MB)",
    proof.proof.len(),
    proof.metrics.witness_ms,
    proof.metrics.prove_ms,
    proof.metrics.heap_mb,
    proof.metrics.witness_mb
  );
  assert_eq!(hex::encode(&proof.pseudonym), TEEN_PSEUDONYM);

  // This library's verifier.
  let (cb, params, hash) = circuit();
  let v = LongfellowVerifier::load(cb, params, hash).unwrap();
  v.verify(values(&c.request), proof.proof.clone(), proof.pseudonym.clone()).unwrap();
  let mut other = proof.pseudonym.clone();
  other[0] ^= 1;
  assert!(matches!(v.verify(values(&c.request), proof.proof.clone(), other), Err(E::ProofInvalid)));

  // community-demo's verifier, on the ZkpPresentation its wallet would send.
  let presentation = Presentation {
    system_id: nym_longfellow::circuit::CIRCUIT_ID.into(),
    proof: proof.proof,
    issuer_key_set: vec![c.document_signer],
    proof_time: c.request.time.clone(),
    results: vec![("nym".into(), ResultValue::Pseudonym(proof.pseudonym.try_into().unwrap())), ("age".into(), ResultValue::True)],
  }
  .encode()
  .unwrap();
  let anchors = std::fs::read_to_string(circuits_dir().join("../../../vega/demo/document-signer.pem")).unwrap();
  let verifier = nym_longfellow::verifier::Verifier::load(&circuits_dir(), &anchors, 300).unwrap();
  let f = fixture();
  let input = serde_json::from_value(json!({
    "request": f["request"],
    "credential_query_id": "nym_attestation",
    "presentation": nym_longfellow::b64url(&presentation),
    "handover": f["handover"],
    "now": c.request.time,
  }))
  .unwrap();
  let out = verifier.verify(&input);
  assert_eq!(out["ok"], json!(true), "community-demo's verifier: {out}");
  assert_eq!(out["results"]["nym"], json!(TEEN_PSEUDONYM));
  assert_eq!(out["results"]["age"], json!(true));
  let _ = c.transcript;
}

#[test]
fn refuses_holder_data_that_does_not_fit() {
  let p = prover();
  let c = case();
  let mut r = again(&c.request);
  r.secret_seed[0] ^= 1;
  assert!(matches!(p.prove(r), Err(E::Refused { refusal: R::SeedMismatch })));

  let mut r = again(&c.request);
  r.device_signature[5] ^= 1;
  assert!(matches!(p.prove(r), Err(E::Refused { refusal: R::DeviceSignature })));

  // 18+ for the teen: the birth date is after the cutoff.
  let mut r = again(&c.request);
  r.earliest = "0000-00-00".into();
  r.cutoff = "2008-10-26".into();
  assert!(matches!(p.prove(r), Err(E::Refused { refusal: R::Unsatisfied })));

  let mut r = again(&c.request);
  r.issuer_key_x[3] ^= 1;
  assert!(matches!(p.prove(r), Err(E::InvalidInput) | Err(E::Refused { refusal: R::Credential })));

  let mut r = again(&c.request);
  r.issuer_signed.truncate(100);
  assert!(matches!(p.prove(r), Err(E::Refused { refusal: R::Credential })));
}

#[test]
fn refuses_inputs_that_are_malformed_or_inconsistent() {
  let p = prover();
  let c = case();
  // e2 that is not the DeviceAuthentication digest of the transcript.
  let mut r = again(&c.request);
  r.challenge_digest[0] ^= 1;
  assert!(matches!(p.prove(r), Err(E::InvalidInput)));
  let mut r = again(&c.request);
  r.transcript_seed = vec![0; 8];
  assert!(matches!(p.prove(r), Err(E::InvalidInput)));
  let mut r = again(&c.request);
  r.time = "2026-10-26 12:00:00Z".into();
  assert!(matches!(p.prove(r), Err(E::InvalidInput)));
  let mut r = again(&c.request);
  r.earliest = "2014-01-01".into();
  assert!(matches!(p.prove(r), Err(E::InvalidInput)), "E after C");
  let mut r = again(&c.request);
  r.secret_seed.pop();
  assert!(matches!(p.prove(r), Err(E::InvalidInput)));
}

#[test]
fn proves_only_the_approved_build() {
  let (c, params, hash) = circuit();
  let unknown = LongfellowCircuitParams { hash_circuit_id: "00".repeat(32), ..params.clone() };
  assert!(matches!(LongfellowProver::load(c.clone(), unknown, hash.clone()), Err(E::UnsupportedCircuit)));
  let wrong_block = LongfellowCircuitParams { block_enc_hash: params.block_enc_hash + 1, ..params.clone() };
  assert!(matches!(LongfellowProver::load(c.clone(), wrong_block, hash.clone()), Err(E::InvalidCircuit)));
  let mut tampered = c.clone();
  tampered[1000] ^= 1;
  assert!(matches!(LongfellowProver::load(tampered, params.clone(), hash.clone()), Err(E::InvalidCircuit)));
  assert!(matches!(LongfellowProver::load(c[..c.len() - 1].to_vec(), params.clone(), hash.clone()), Err(E::InvalidCircuit)));
  assert!(matches!(LongfellowProver::load(c, params, "md5:00".into()), Err(E::InvalidInput)));
}

#[test]
fn reports_its_runtime() {
  let v = nymauth_native::nymauth_native_version();
  assert!(v.contains("longfellow-zk 61a8a73"), "{v}");
}
