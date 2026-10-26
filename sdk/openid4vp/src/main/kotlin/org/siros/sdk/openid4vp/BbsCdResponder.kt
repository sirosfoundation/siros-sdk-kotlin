// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkPlanner
import org.siros.sdk.credentials.SharedCircuitZkPlanner
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.keystore.BbsCdHandover
import org.siros.sdk.keystore.BbsCdPresenter

/**
 * Answers the `zkp_req` queries of `source_format` `bbs_cd` of an [AuthorizationRequest] (nym_auth rulebook v0.4) with the
 * SDK's [BbsCdPresenter], the counterpart of [CircuitZkResponder] for the BBS scheme: the shared matcher plans the query, and
 * the presentation is bound to the verified request object and its OpenID4VPHandover values (`client_id`, `nonce`,
 * `response_uri`, the response-encryption key's thumbprint), from which the BBS statement's audience is derived as the
 * verifier derives it. The device key signs through the caller's [ZkWitnessSigner] (a StrongBox key).
 *
 * The host chooses the query and the credential, shows the consent ([plan] says what is asked), and posts the result with
 * [OpenId4VpClient.sendPresentation]; a refusal ([org.siros.sdk.keystore.CircuitZkError.AccessDenied]) is answered with
 * [OpenId4VpClient.sendError]. The signer's own exception (a cancelled prompt) comes back as it was thrown.
 */
class BbsCdResponder(
    private val presenter: BbsCdPresenter = BbsCdPresenter(),
    private val planner: CircuitZkPlanner = SharedCircuitZkPlanner(),
) {
    /**
     * The plan of the `zkp_req` query [queryId]: its functions and the schemes the verifier accepts.
     *
     * @throws OpenId4VpException.Unsupported when the request has no such `zkp_req` query, the matcher refuses it, or it is
     *   not a `bbs_cd` query.
     */
    fun plan(request: AuthorizationRequest, queryId: String): CircuitZkPlan {
        val plan = planZkpReq(planner, request, queryId)
        if (plan.sourceFormat != SOURCE_FORMAT) throw OpenId4VpException.Unsupported("the zkp_req query $queryId is not bbs_cd")
        return plan
    }

    /**
     * Proves [plan] (from [plan]) over the stored `bbs_cd` [credential] (JSON) and returns the `vp_token` to post.
     *
     * @param devicePublicKey the credential's device key (SEC1 P-256), the key [signer] signs with.
     * @throws org.siros.sdk.keystore.CircuitZkError.AccessDenied when the presenter refuses (the holder's data does not
     *   meet the request, or a rule fails): answer it with [OpenId4VpClient.ERROR_ACCESS_DENIED].
     */
    suspend fun present(
        request: AuthorizationRequest,
        queryId: String,
        plan: CircuitZkPlan,
        credential: String,
        devicePublicKey: ByteArray,
        signer: ZkWitnessSigner,
        parallel: Boolean = false,
    ): Presentation {
        val result = presenter.present(
            BbsCdPresenter.Request(
                plan = plan,
                requestObject = request.payload,
                handover = BbsCdHandover(request.clientId, request.nonce, request.responseUri, request.responseEncryptionJwkThumbprint),
                credential = credential,
                devicePublicKey = devicePublicKey,
                parallel = parallel,
            ),
            signer,
        )
        return Presentation(queryId, result)
    }

    /** One `bbs_cd` presentation and the `vp_token` that carries it. */
    class Presentation(val queryId: String, val result: BbsCdPresenter.Result) {
        /** `{queryId: [base64url(CBOR ZkpPresentation)]}`, for [OpenId4VpClient.sendPresentation]. */
        val vpToken: JsonObject get() = JsonObject(mapOf(queryId to JsonArray(listOf(result.json))))

        override fun toString() = "BbsCdResponder.Presentation($queryId)"
    }

    private companion object {
        const val SOURCE_FORMAT = "bbs_cd"
    }
}
