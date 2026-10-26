// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkPlanResult
import org.siros.sdk.credentials.CircuitZkPlanner
import org.siros.sdk.credentials.SharedCircuitZkPlanner
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.keystore.CircuitZkPresenter

/**
 * Answers the `zkp_req` queries of an [AuthorizationRequest] (nym_auth rulebook v0.4) with the SDK's own `circuit_zk`
 * path: the shared matcher plans the query against the request's `client_metadata`, and [presenter] (rulebook validator,
 * catalog prover, nymauth adapter) makes the `ZkpPresentation`, bound to the request's session transcript
 * ([AuthorizationRequest.sessionTranscript]) and with the request's `client_id` as `verifier_id` (the `x509_san_dns` form,
 * the only `client_id` prefix this client accepts).
 *
 * The host chooses the query and the credential, shows the consent ([plan] says what is asked), and posts the result with
 * [OpenId4VpClient.sendPresentation]; a refusal of the presenter ([org.siros.sdk.keystore.CircuitZkError.AccessDenied])
 * is answered with [OpenId4VpClient.sendError].
 */
/**
 * The shared matcher's plan of the `zkp_req` query [queryId] of [request], against the request's `client_metadata`.
 *
 * @throws OpenId4VpException.Unsupported when the request has no such `zkp_req` query, or the matcher refuses it.
 */
internal fun planZkpReq(planner: CircuitZkPlanner, request: AuthorizationRequest, queryId: String): CircuitZkPlan {
    val query = request.circuitZkQueries.firstOrNull { (it["id"] as? JsonPrimitive)?.content == queryId }
        ?: throw OpenId4VpException.Unsupported("no zkp_req query $queryId")
    val planned = try {
        planner.plan(query, request.clientMetadata)
    } catch (e: Exception) {
        CircuitZkPlanResult.InvalidRequest
    }
    return (planned as? CircuitZkPlanResult.Plan)?.plan ?: throw OpenId4VpException.Unsupported("the zkp_req query $queryId is not well formed")
}

class CircuitZkResponder(
    private val presenter: CircuitZkPresenter,
    private val planner: CircuitZkPlanner = SharedCircuitZkPlanner(),
) {
    /**
     * The plan of the `zkp_req` query [queryId]: its functions (pseudonym, age_check) and the circuits the verifier accepts.
     *
     * @throws OpenId4VpException.Unsupported when the request has no such `zkp_req` query, or the matcher refuses it.
     */
    fun plan(request: AuthorizationRequest, queryId: String): CircuitZkPlan = planZkpReq(planner, request, queryId)

    /**
     * Proves [plan] (from [plan]) over the stored mdoc [credentialBytes] and returns the `vp_token` to post.
     *
     * @param secretSeed the credential's `secret_seed`; the presenter works on its own copy. The caller zeroes its array.
     * @param issuer the Credential Issuer Identifier as stored, for functions that need the device seed; null otherwise.
     * @param parallel the threads a proof system that runs in parallel (Vega) may use: true one per core, false one, null its
     *   default ([CircuitZkPresenter.Request.parallel]).
     * @throws org.siros.sdk.keystore.CircuitZkError.AccessDenied when the presenter refuses (the holder's data does not
     *   meet the request, or a rule fails): answer it with [OpenId4VpClient.ERROR_ACCESS_DENIED].
     */
    suspend fun present(
        request: AuthorizationRequest,
        queryId: String,
        plan: CircuitZkPlan,
        credentialBytes: ByteArray,
        secretSeed: ByteArray?,
        signer: ZkWitnessSigner,
        issuer: String? = null,
        parallel: Boolean? = null,
    ): Presentation {
        val result = presenter.present(
            CircuitZkPresenter.Request(
                credentialBytes = credentialBytes,
                plan = plan,
                verifierId = request.clientId,
                sessionTranscript = request.sessionTranscript(),
                secretSeed = secretSeed,
                issuer = issuer,
                parallel = parallel,
            ),
            signer,
        )
        return Presentation(queryId, result)
    }

    /** One `zkp_req` presentation and the `vp_token` that carries it. */
    class Presentation(val queryId: String, val result: CircuitZkPresenter.Result) {
        /** `{queryId: [base64url(CBOR ZkpPresentation)]}`, for [OpenId4VpClient.sendPresentation]. */
        val vpToken: JsonObject get() = JsonObject(mapOf(queryId to JsonArray(listOf(result.json))))

        override fun toString() = "CircuitZkResponder.Presentation($queryId)"
    }
}
