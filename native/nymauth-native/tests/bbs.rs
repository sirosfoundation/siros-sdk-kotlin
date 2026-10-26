//! BBS (bbs_cd) through this library's UniFFI surface: community-demo's teen BBS credential, its device
//! key signing as a host's signer would, checked by community-demo's own BBS verifier (nym-bbs), and
//! the refusals. Reads readdit-demo's `app/wallet/demo-wallet-bbs.json` and `native/bbs/demo/issuer-params.bin`.
#![cfg(feature = "bbs")]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use nym_bbs::verifier::{VerifyInput, Verifier};
use nymauth_native::bbs::{BbsDeviceSigner, BbsHandover, BbsProver};
use nymauth_native::{NymAuthNativeError as E, NymAuthRefusal as R};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};

fn demo(p: &str) -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../readdit-demo").join(p)
}

fn wallet() -> Value {
  serde_json::from_str(&std::fs::read_to_string(demo("app/wallet/demo-wallet-bbs.json")).unwrap()).unwrap()
}

fn request(nonce: &str, age: Option<Value>) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "hashdh-bls12381g1" } })];
  if let Some(a) = age {
    req.push(json!({ "fn_id": "age_check", "return": "age", "params": a }));
  }
  json!({
    "client_id": "x509_san_dns:community.example",
    "nonce": nonce,
    "response_uri": "https://community.example/api/vp/response/s1",
    "dcql_query": { "credentials": [{ "id": "nym_attestation_bbs", "format": "zkp_req",
      "meta": { "source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1" }, "_req": req }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": { "proof_system_values": ["bbs-cd-plugins-v0.1"], "system_id_values": ["urn:mms:bbs-cd:nym_auth:v1"] } } },
  })
}

fn handover(req: &Value) -> BbsHandover {
  BbsHandover {
    client_id: req["client_id"].as_str().unwrap().into(),
    nonce: req["nonce"].as_str().unwrap().into(),
    response_uri: req["response_uri"].as_str().unwrap().into(),
    jwk_thumbprint: None,
  }
}

/// The teen's device key as a host's signer: counts its signatures, and can be told to fail or lie.
struct Software {
  key: SigningKey,
  calls: AtomicU32,
  mode: Mode,
}

#[derive(Clone, Copy)]
enum Mode {
  Honest,
  Fails,
  Garbage,
  OtherKey,
}

impl BbsDeviceSigner for Software {
  fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, E> {
    self.calls.fetch_add(1, Ordering::SeqCst);
    match self.mode {
      Mode::Honest => {
        let sig: Signature = self.key.sign(&message);
        Ok(sig.to_bytes().to_vec())
      }
      Mode::Fails => Err(E::Internal),
      Mode::Garbage => Ok(vec![7u8; 64]),
      Mode::OtherKey => {
        let sig: Signature = SigningKey::from_slice(&[9u8; 32]).unwrap().sign(&message);
        Ok(sig.to_bytes().to_vec())
      }
    }
  }
}

fn teen(mode: Mode) -> (Arc<Software>, Vec<u8>, String) {
  let w = wallet();
  let d = nym_bbs::unb64url("d", w["holders"][0]["device_key"]["d"].as_str().unwrap()).unwrap();
  let key = SigningKey::from_slice(&d).unwrap();
  let public = key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
  let credential = w["holders"][0]["credential"].to_string();
  (Arc::new(Software { key, calls: AtomicU32::new(0), mode }), public, credential)
}

fn prove(p: &BbsProver, req: &Value, signer: Arc<Software>, public: Vec<u8>, credential: String) -> Result<nymauth_native::bbs::BbsPresentation, E> {
  p.prove(req.to_string(), "nym_attestation_bbs".into(), handover(req), credential, public, signer, false)
}

fn verify(req: &Value, presentation: &[u8]) -> Value {
  let verifier = Verifier::load(&std::fs::read(demo("native/bbs/demo/issuer-params.bin")).unwrap()).unwrap();
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation_bbs", "presentation": nym_bbs::b64url(presentation),
    "handover": { "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": null },
  }))
  .unwrap();
  verifier.verify(&input)
}

const TEEN: &str = r#"{ "ge": "2008-10-20", "le": "2013-10-19" }"#;

#[test]
fn proves_with_the_hosts_signer_and_community_demo_verifies() {
  let p = BbsProver::load();
  let req = request("0123456789abcdef0123456789abcdef", Some(serde_json::from_str(TEEN).unwrap()));
  let (signer, public, credential) = teen(Mode::Honest);
  let out = prove(&p, &req, signer.clone(), public, credential).expect("prove");
  assert_eq!(signer.calls.load(Ordering::SeqCst), 1, "the device signs once");
  assert_eq!(out.system_id, "urn:mms:bbs-cd:nym_auth:v1");
  assert_eq!(out.pseudonym_handle, "nym");
  assert_eq!(out.pseudonym.len(), 48);
  assert_eq!(out.predicate_handles, vec!["age".to_string()]);
  assert_eq!(out.metrics.presentation_bytes as usize, out.presentation.len());
  assert!(out.metrics.proof_bytes > 0 && out.metrics.prove_ms > 0.0);
  let v = verify(&req, &out.presentation);
  assert_eq!(v["ok"], true, "{v}");
  assert_eq!(v["results"]["nym"].as_str().unwrap(), hex::encode(&out.pseudonym));
  assert_eq!(v["results"]["age"], true);
  println!(
    "BBS teen: presentation {} B (envelope {} B), prove {:.1} ms (device {:.2} ms), heap {:?} MB",
    out.presentation.len(),
    out.metrics.proof_bytes,
    out.metrics.prove_ms,
    out.metrics.device_sign_ms,
    out.metrics.heap_mb
  );
}

#[test]
fn an_unmet_age_range_is_refused_before_the_device_is_asked() {
  let p = BbsProver::load();
  let req = request("0123456789abcdef0123456789abcdef", Some(json!({ "le": "2000-01-01" })));
  let (signer, public, credential) = teen(Mode::Honest);
  let e = prove(&p, &req, signer.clone(), public, credential).unwrap_err();
  assert!(matches!(e, E::Refused { refusal: R::Unsatisfied }), "{e:?}");
  assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn the_signers_own_error_comes_back_and_a_bad_signature_is_refused() {
  let p = BbsProver::load();
  let req = request("0123456789abcdef0123456789abcdef", None);
  let (signer, public, credential) = teen(Mode::Fails);
  assert!(matches!(prove(&p, &req, signer, public, credential), Err(E::Internal)));
  for mode in [Mode::Garbage, Mode::OtherKey] {
    let (signer, public, credential) = teen(mode);
    let e = prove(&p, &req, signer, public, credential).unwrap_err();
    assert!(matches!(e, E::Refused { refusal: R::DeviceSignature }), "{e:?}");
  }
}

#[test]
fn refuses_what_it_cannot_read() {
  let p = BbsProver::load();
  let req = request("0123456789abcdef0123456789abcdef", None);
  let (signer, public, credential) = teen(Mode::Honest);
  // Not a Request Object.
  let e = p.prove("{}".into(), "nym_attestation_bbs".into(), handover(&req), credential.clone(), public.clone(), signer.clone(), false).unwrap_err();
  assert!(matches!(e, E::InvalidInput), "{e:?}");
  // A handover for another request.
  let mut h = handover(&req);
  h.nonce = "another".into();
  let e = p.prove(req.to_string(), "nym_attestation_bbs".into(), h, credential.clone(), public.clone(), signer.clone(), false).unwrap_err();
  assert!(matches!(e, E::InvalidInput), "{e:?}");
  // No such query.
  let e = p.prove(req.to_string(), "other".into(), handover(&req), credential.clone(), public.clone(), signer.clone(), false).unwrap_err();
  assert!(matches!(e, E::InvalidInput), "{e:?}");
  // Not a device key.
  let e = p.prove(req.to_string(), "nym_attestation_bbs".into(), handover(&req), credential.clone(), vec![4u8; 65], signer.clone(), false).unwrap_err();
  assert!(matches!(e, E::InvalidInput), "{e:?}");
  // Not a credential, and a credential whose signature does not verify.
  let e = p.prove(req.to_string(), "nym_attestation_bbs".into(), handover(&req), "{}".into(), public.clone(), signer.clone(), false).unwrap_err();
  assert!(matches!(e, E::Refused { refusal: R::Credential }), "{e:?}");
  let mut forged: Value = serde_json::from_str(&credential).unwrap();
  forged["messages"][1] = json!("0000000000000000000000000000000000000000000000000000000000000001");
  let e = p.prove(req.to_string(), "nym_attestation_bbs".into(), handover(&req), forged.to_string(), public, signer.clone(), false).unwrap_err();
  assert!(matches!(e, E::Refused { refusal: R::Credential }), "{e:?}");
  assert_eq!(signer.calls.load(Ordering::SeqCst), 0, "nothing was signed for a refused request");
}
