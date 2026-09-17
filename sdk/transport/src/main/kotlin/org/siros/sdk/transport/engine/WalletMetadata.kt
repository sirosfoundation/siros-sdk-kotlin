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
     * ES256 throughout - it is what every WSCD this SDK drives produces,
     * from the platform keystore to a remote signer over R2PS.
     */
    val DEFAULT: JsonObject = buildJsonObject {
        putJsonObject("vp_formats_supported") {
            putJsonObject("dc+sd-jwt") {
                putJsonArray("sd-jwt_alg_values") { add("ES256") }
                putJsonArray("kb-jwt_alg_values") { add("ES256") }
            }
            putJsonObject("vc+sd-jwt") {
                putJsonArray("sd-jwt_alg_values") { add("ES256") }
                putJsonArray("kb-jwt_alg_values") { add("ES256") }
            }
            putJsonObject("mso_mdoc") {
                putJsonArray("alg_values") { add("ES256") }
            }
        }
    }
}
