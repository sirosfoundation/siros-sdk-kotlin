//! Google's runtime (nymauth-native) and ISRG's (zk-cred-longfellow) on the same circuit and inputs:
//! each verifies the other's proof, and refuses it for another pseudonym.

use nym_longfellow::{handover, mdoc, x509};
use nymauth_native::longfellow::{APPROVED, LongfellowCircuitParams, LongfellowProveRequest, LongfellowProver, LongfellowPublicValues, LongfellowVerifier};
use nymauth_native::{nymauth_challenge_digest, nymauth_verifier_input};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::Value;
use sha2::Digest;
use zk_cred_longfellow::nymauth::{NymAuthCircuitParams, NymAuthProver, NymAuthRequest, NymAuthVerifier, NymAuthWitnessInput};

fn b64(s: &str) -> Vec<u8> {
  use base64::Engine;
  base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

struct Inputs {
  circuit: Vec<u8>,
  artifact_hash: String,
  issuer_signed: Vec<u8>,
  seed: Vec<u8>,
  qx: Vec<u8>,
  qy: Vec<u8>,
  time: String,
  earliest: String,
  cutoff: String,
  e2: Vec<u8>,
  device_signature: Vec<u8>,
  verifier_input: Vec<u8>,
  transcript: Vec<u8>,
}

fn inputs() -> Inputs {
  let f: Value = serde_json::from_str(include_str!("../../tests/fixtures/teen-request.json")).unwrap();
  let s = |v: &Value, k: &str| v[k].as_str().unwrap().to_string();
  let h = &f["handover"];
  let thumb: [u8; 32] = b64(&s(h, "jwk_thumbprint")).try_into().unwrap();
  let transcript = handover::session_transcript(&s(h, "client_id"), &s(h, "nonce"), Some(&thumb), &s(h, "response_uri"));
  let e2 = nymauth_challenge_digest(transcript.clone(), nymauth_native::NYM_AUTH_DOCTYPE.into());
  let issuer_signed = s(&f["credential"], "issuer_signed");
  let q = x509::parse(&mdoc::parse(&issuer_signed).unwrap().document_signer).unwrap().key;
  let d: [u8; 32] = b64(&s(&f["device_key"], "d")).try_into().unwrap();
  let sig: p256::ecdsa::Signature = SigningKey::from_bytes(&d.into()).unwrap().sign_prehash(&e2).unwrap();
  let sig = sig.normalize_s().unwrap_or(sig);
  let age = &f["request"]["dcql_query"]["credentials"][0]["_req"][1]["params"];
  let zst = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../readdit-demo/native/longfellow/circuits/mdoc/circuits.zst")).unwrap();
  Inputs {
    circuit: zstd::decode_all(&zst[..]).unwrap(),
    artifact_hash: format!("sha256:{}", hex::encode(sha2::Sha256::digest(&zst))),
    issuer_signed: b64(&issuer_signed),
    seed: hex::decode(s(&f, "secret_seed")).unwrap(),
    qx: q.x.to_vec(),
    qy: q.y.to_vec(),
    time: nym_longfellow::dates::now().unwrap().text(),
    earliest: s(age, "ge"),
    cutoff: s(age, "le"),
    e2,
    device_signature: sig.to_bytes().to_vec(),
    verifier_input: nymauth_verifier_input(s(&f, "verifier_id")),
    transcript,
  }
}

fn google_params() -> LongfellowCircuitParams {
  let a = &APPROVED[0];
  LongfellowCircuitParams { block_enc_hash: a.block_enc_hash, block_enc_sig: a.block_enc_sig, hash_circuit_id: a.hash_circuit_id.into(), sig_circuit_id: a.sig_circuit_id.into() }
}

fn isrg_params() -> NymAuthCircuitParams {
  let a = &APPROVED[0];
  NymAuthCircuitParams { block_enc_hash: a.block_enc_hash as usize, block_enc_sig: a.block_enc_sig as usize, hash_circuit_id: a.hash_circuit_id.into(), sig_circuit_id: a.sig_circuit_id.into() }
}

fn isrg_request(i: &Inputs) -> NymAuthRequest<'_> {
  NymAuthRequest {
    issuer_key_x: &i.qx,
    issuer_key_y: &i.qy,
    time: &i.time,
    earliest: &i.earliest,
    cutoff: &i.cutoff,
    challenge_digest: &i.e2,
    verifier_input: &i.verifier_input,
    transcript_seed: &i.transcript,
  }
}

fn google_values(i: &Inputs) -> LongfellowPublicValues {
  LongfellowPublicValues {
    issuer_key_x: i.qx.clone(),
    issuer_key_y: i.qy.clone(),
    time: i.time.clone(),
    earliest: i.earliest.clone(),
    cutoff: i.cutoff.clone(),
    challenge_digest: i.e2.clone(),
    verifier_input: i.verifier_input.clone(),
    transcript_seed: i.transcript.clone(),
  }
}

#[test]
fn google_proof_verifies_with_isrg_and_isrg_proof_with_google() {
  let i = inputs();

  // Google's runtime proves; ISRG's verifier checks.
  let g = LongfellowProver::load(i.circuit.clone(), google_params(), i.artifact_hash.clone()).unwrap();
  let gp = g
    .prove(LongfellowProveRequest {
      issuer_signed: i.issuer_signed.clone(),
      secret_seed: i.seed.clone(),
      issuer_key_x: i.qx.clone(),
      issuer_key_y: i.qy.clone(),
      time: i.time.clone(),
      earliest: i.earliest.clone(),
      cutoff: i.cutoff.clone(),
      challenge_digest: i.e2.clone(),
      device_signature: i.device_signature.clone(),
      verifier_input: i.verifier_input.clone(),
      transcript_seed: i.transcript.clone(),
    })
    .unwrap();
  let isrg_v = NymAuthVerifier::new(&i.circuit, &isrg_params()).unwrap();
  isrg_v.verify(&isrg_request(&i), &gp.pseudonym, &gp.proof).expect("ISRG verifies Google's proof");
  let mut other = gp.pseudonym.clone();
  other[31] ^= 1;
  assert!(isrg_v.verify(&isrg_request(&i), &other, &gp.proof).is_err());

  // ISRG proves; Google's verifier checks.
  let isrg_p = NymAuthProver::new(&i.circuit, &isrg_params()).unwrap();
  let ip = isrg_p
    .prove(
      &isrg_request(&i),
      &NymAuthWitnessInput { issuer_signed: &i.issuer_signed, secret_seed: &i.seed, device_signature: &i.device_signature },
    )
    .unwrap();
  assert_eq!(ip.pseudonym.to_vec(), gp.pseudonym, "the same pseudonym from both");
  let gv = LongfellowVerifier::load(i.circuit.clone(), google_params(), i.artifact_hash.clone()).unwrap();
  gv.verify(google_values(&i), ip.proof.to_vec(), ip.pseudonym.to_vec()).expect("Google verifies ISRG's proof");
  println!("proof sizes: Google {} B, ISRG {} B", gp.proof.len(), ip.proof.len());
}
