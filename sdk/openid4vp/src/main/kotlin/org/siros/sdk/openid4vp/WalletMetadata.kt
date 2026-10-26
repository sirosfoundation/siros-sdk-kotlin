// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.siros.sdk.credentials.CircuitZkCircuit

/**
 * The `wallet_metadata` a wallet posts to a `request_uri` (OpenID4VP 1.0 section 10), so the verifier can tailor its
 * request to what the wallet runs.
 */
object WalletMetadata {
    /**
     * For a wallet that answers `zkp_req` with [circuits]: `vp_formats_supported.zkp_req` with the circuits' ids and
     * aliases (`system_id_values`) and their proof systems (`proof_system_values`), and the response encryption this
     * client applies (`ECDH-ES`; `A128GCM`, `A256GCM`). Offer only the circuits the prover has loaded, so the verifier
     * never asks for one the wallet cannot prove.
     */
    fun circuitZk(circuits: Collection<CircuitZkCircuit>): JsonObject {
        val systemIds = LinkedHashSet<String>()
        val proofSystems = LinkedHashSet<String>()
        for (c in circuits) {
            systemIds += c.circuitId
            systemIds += c.aliases
            proofSystems += c.offeredProofSystem
        }
        fun list(values: Collection<String>) = JsonArray(values.map { JsonPrimitive(it) })
        return buildJsonObject {
            put(
                "vp_formats_supported",
                buildJsonObject {
                    if (circuits.isNotEmpty()) {
                        put(
                            AuthorizationRequest.ZKP_REQ_FORMAT,
                            buildJsonObject {
                                put("proof_system_values", list(proofSystems))
                                put("system_id_values", list(systemIds))
                            },
                        )
                    }
                },
            )
            put("authorization_encryption_alg_values_supported", list(listOf("ECDH-ES")))
            put("authorization_encryption_enc_values_supported", list(listOf("A128GCM", "A256GCM")))
        }
    }
}
