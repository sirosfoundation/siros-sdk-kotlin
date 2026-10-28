// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.transport.engine

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * `wallet_metadata` for OpenID4VP 1.0 §5.10's `request_uri_method=post`:
 * what this wallet tells a verifier it can present, so the verifier can
 * tailor the Request Object it returns.
 *
 * It belongs on this side of the connection. The backend engine never sees a
 * credential and never builds a VP token - matching and signing both happen
 * here - so left to itself it has to guess, and does
 * (go-wallet-backend's `defaultWalletMetadata`). Sending this replaces that
 * guess with what the SDK actually implements.
 *
 * Kept to `vp_formats_supported`: it is the part a verifier acts on, and
 * every further field would be a claim about this wallet that nothing here
 * checks.
 */
object WalletMetadata {

    /**
     * The formats this SDK can present: SD-JWT VC under both the current
     * (`dc+sd-jwt`) and the legacy (`vc+sd-jwt`) identifier, and ISO mdoc.
     * A holder key is not always ES256: `WscdKeystoreAdapter` signs both the
     * SD-JWT VC Key Binding JWT and the mdoc device signature with whatever
     * `key.algorithm` the selected holder key actually is, which can be
     * EdDSA, so `kb-jwt_alg_values` and `deviceauth_alg_values` (this SDK's
     * own holder-key-signed material - see below) list both.
     *
     * The formats are spelled as OpenID4VP 1.0 Annex B defines them, which
     * is not the same shape across all three: SD-JWT VC takes
     * `sd-jwt_alg_values` (the ISSUER's signature algorithm on the SD-JWT
     * itself - out of this wallet's control, kept at ES256) and
     * `kb-jwt_alg_values` with JOSE names; mdoc takes
     * `issuerauth_alg_values` and `deviceauth_alg_values` with COSE algorithm
     * identifiers. `-7` is ES256, `-8` is EdDSA (`MdocCose.algorithmValue`
     * writes either into the device signature's protected header, whichever
     * the holder key's own algorithm is); `-9` (ES256, fully-specified) is
     * never advertised because `MdocCose` never emits or verifies it.
     * `issuerauth_alg_values` stays at `-7` only, since `MdocCose.verify1`
     * (used for an issuer's own signature) does not implement EdDSA
     * verification. No `DeviceMac` value is offered because this SDK only
     * ever produces a `DeviceSignature`.
     */
    val DEFAULT: JsonObject = buildJsonObject {
        putJsonObject("vp_formats_supported") {
            putJsonObject("dc+sd-jwt") {
                putJsonArray("sd-jwt_alg_values") { add("ES256") }
                putJsonArray("kb-jwt_alg_values") { add("ES256"); add("EdDSA") }
            }
            putJsonObject("vc+sd-jwt") {
                putJsonArray("sd-jwt_alg_values") { add("ES256") }
                putJsonArray("kb-jwt_alg_values") { add("ES256"); add("EdDSA") }
            }
            putJsonObject("mso_mdoc") {
                putJsonArray("issuerauth_alg_values") { add(-7) }
                putJsonArray("deviceauth_alg_values") { add(-7); add(-8) }
            }
        }
    }
}
