//! A credential from the demo issuer, presented with the SDK's nymauth-native (the device key signing
//! through the host signer) and verified by community-demo's BBS verifier with the issuer's parameters.

use std::sync::Arc;

use nym_bbs::verifier::{VerifyInput, Verifier};
use nymauth_demo_issuer::{DemoIssuerError, bbs_demo_issue, bbs_demo_issuer_params};
use nymauth_native::NymAuthNativeError;
use nymauth_native::bbs::{BbsDeviceSigner, BbsHandover, BbsProver};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::OsRng;
use serde_json::json;

struct Key(SigningKey);

impl BbsDeviceSigner for Key {
  fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, NymAuthNativeError> {
    let sig: Signature = self.0.sign(&message);
    Ok(sig.to_bytes().to_vec())
  }
}

#[test]
fn issues_a_credential_the_sdk_presents_and_the_verifier_accepts() {
  let issuer_seed = [5u8; 32];
  let device = SigningKey::random(&mut OsRng);
  let public = device.verifying_key().to_encoded_point(false).as_bytes().to_vec();
  // The adult: born 1990-05-20; a 16-byte secret_seed.
  let credential = bbs_demo_issue(issuer_seed.to_vec(), public.clone(), "1990-05-20".into(), vec![3u8; 16]).expect("issue");
  let params = bbs_demo_issuer_params(issuer_seed.to_vec()).unwrap();
  assert_eq!(params, bbs_demo_issuer_params(issuer_seed.to_vec()).unwrap(), "the issuer is the seed's, every time");
  let c: serde_json::Value = serde_json::from_str(&credential).unwrap();
  assert_eq!(c["issuer_params"], json!(nym_bbs::b64url(&params)));

  let req = json!({
    "client_id": "x509_san_dns:community.example",
    "nonce": "00112233445566778899aabbccddeeff",
    "response_uri": "https://community.example/api/vp/response/s1",
    "dcql_query": { "credentials": [{ "id": "nym_attestation_bbs", "format": "zkp_req",
      "meta": { "source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1" },
      "_req": [
        { "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "hashdh-bls12381g1" } },
        { "fn_id": "age_check", "return": "age", "params": { "le": "2008-10-19" } }
      ] }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": { "proof_system_values": ["bbs-cd-plugins-v0.1"], "system_id_values": ["urn:mms:bbs-cd:nym_auth:v1"] } } },
  });
  let handover = BbsHandover {
    client_id: "x509_san_dns:community.example".into(),
    nonce: "00112233445566778899aabbccddeeff".into(),
    response_uri: "https://community.example/api/vp/response/s1".into(),
    jwk_thumbprint: Some("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".into()),
  };
  let out = BbsProver::load()
    .prove(req.to_string(), "nym_attestation_bbs".into(), handover, credential, public, Arc::new(Key(device)), false)
    .expect("prove");

  let verifier = Verifier::load(&params).unwrap();
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation_bbs", "presentation": nym_bbs::b64url(&out.presentation),
    "handover": { "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" },
  }))
  .unwrap();
  let v = verifier.verify(&input);
  assert_eq!(v["ok"], true, "{v}");
  assert_eq!(v["results"]["age"], true);
  assert_eq!(v["results"]["nym"].as_str().unwrap(), hex(&out.pseudonym));
}

#[test]
fn refuses_inputs_of_the_wrong_form() {
  let seed = vec![5u8; 32];
  let key = SigningKey::random(&mut OsRng).verifying_key().to_encoded_point(true).as_bytes().to_vec();
  let bad = |r: Result<String, DemoIssuerError>| assert!(matches!(r, Err(DemoIssuerError::InvalidInput { .. })), "{r:?}");
  bad(bbs_demo_issue(seed.clone(), key.clone(), "1990-05-20".into(), vec![3u8; 15]));
  bad(bbs_demo_issue(seed.clone(), vec![4u8; 20], "1990-05-20".into(), vec![3u8; 16]));
  bad(bbs_demo_issue(seed.clone(), key.clone(), "20-05-1990".into(), vec![3u8; 16]));
  bad(bbs_demo_issue(vec![1u8; 8], key, "1990-05-20".into(), vec![3u8; 16]));
}

fn hex(b: &[u8]) -> String {
  b.iter().map(|x| format!("{x:02x}")).collect()
}
