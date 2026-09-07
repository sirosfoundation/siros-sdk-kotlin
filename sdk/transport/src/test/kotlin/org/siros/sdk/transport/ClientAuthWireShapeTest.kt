package org.siros.sdk.transport

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.siros.sdk.transport.engine.SignResponseMessage
import org.siros.sdk.transport.wmp.FlowProgressParams
import org.siros.sdk.transport.wmp.JsonRpcResponse
import org.siros.sdk.transport.wmp.WmpCodec
import org.siros.sdk.transport.wmp.WmpMeta
import org.siros.sdk.transport.wmp.WmpMethods
import org.siros.sdk.transport.wmp.WmpPeerContext
import org.siros.sdk.transport.wmp.openid4x.OpenID4xConfig
import org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile
import org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams
import org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult

/**
 * `sign_client_auth` (go-wallet-backend#317) on both transports.
 *
 * The engine asks the wallet to authenticate one outbound request with the
 * wallet's own key: a DPoP proof and/or a fresh attestation PoP. The request
 * parameters and the result members must be the same bytes on the legacy
 * websocket protocol and on WMP, for the same reason as
 * [CredentialRequestExtrasTest]: one backend code path, one behaviour.
 */
class ClientAuthWireShapeTest {

    private val json = Json {
        encodeDefaults = false
        ignoreUnknownKeys = true
    }

    private class FakePeerContext : WmpPeerContext {
        override val codec = WmpCodec()
        val notifications = mutableListOf<Pair<String, JsonObject?>>()
        override suspend fun notify(method: String, params: JsonObject?) {
            notifications.add(method to params)
        }
        override suspend fun call(method: String, params: JsonObject?): JsonRpcResponse =
            JsonRpcResponse(id = null)
    }

    /** What go-wmp's SignSubFlowParams / the engine's SignRequestParams put on the wire. */
    private fun clientAuthPayload(): JsonObject = buildJsonObject {
        put("action", JsonPrimitive("sign_client_auth"))
        put("nonce", JsonPrimitive(""))
        put("audience", JsonPrimitive("https://as.example.com"))
        put("issuer", JsonPrimitive("siros-sample://callback"))
        put("htm", JsonPrimitive("POST"))
        put("htu", JsonPrimitive("https://as.example.com/token"))
        put("dpop_nonce", JsonPrimitive("n-1"))
        put("ath", JsonPrimitive("h"))
        put("key_id", JsonPrimitive("k-1"))
    }

    @Test
    fun wmpSignSubFlowParamsDecodeTheClientAuthMembers() {
        val p = json.decodeFromJsonElement(SignSubFlowParams.serializer(), clientAuthPayload())
        assertEquals("sign_client_auth", p.action)
        assertEquals("https://as.example.com", p.audience)
        assertEquals("siros-sample://callback", p.issuer)
        assertEquals("POST", p.htm)
        assertEquals("https://as.example.com/token", p.htu)
        assertEquals("n-1", p.dpopNonce)
        assertEquals("h", p.ath)
        assertEquals("k-1", p.keyId)
    }

    /**
     * A DPoP-only `sign_client_auth` (credential / deferred / notification
     * request) has no audience and no c_nonce; a peer that omits the members
     * instead of sending "" must still decode.
     */
    @Test
    fun wmpSignSubFlowParamsTolerateAbsentAudienceAndNonce() {
        val p = json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            buildJsonObject {
                put("action", JsonPrimitive("sign_client_auth"))
                put("htm", JsonPrimitive("POST"))
                put("htu", JsonPrimitive("https://issuer.example.com/credential"))
                put("ath", JsonPrimitive("h"))
            },
        )
        assertEquals("", p.audience)
        assertEquals("", p.nonce)
        assertEquals("POST", p.htm)
    }

    @Test
    fun bothTransportsAgreeOnTheResultShape() = runBlocking {
        val legacy = json.encodeToJsonElement(
            SignResponseMessage.serializer(),
            SignResponseMessage(
                flowId = "f1",
                clientAttestation = "wia",
                clientAttestationPoP = "pop",
                dpopKeyId = "k-1",
                dpopProof = "dpop",
            ),
        ).jsonObject

        var seen: SignSubFlowParams? = null
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, params ->
                    seen = params
                    SignSubFlowResult(clientAttestation = "wia", clientAttestationPoP = "pop", dpopKeyId = "k-1", dpopProof = "dpop")
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)
        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f1", step = "sign_request", payload = clientAuthPayload())
        )
        assertEquals("k-1", seen?.keyId)

        val wmp = ctx.notifications.first { it.first == WmpMethods.FLOW_ACTION }.second!!
        assertEquals(JsonPrimitive("sign_response"), wmp["action"])
        for (member in listOf("client_attestation", "client_attestation_pop", "dpop_key_id", "dpop_proof")) {
            assertEquals("member $member must be identical on both transports", legacy[member], wmp[member])
        }
    }

    @Test
    fun aDpopOnlyAnswerCarriesNoAttestationMembers() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(dpopKeyId = "k-1", dpopProof = "dpop") })
        )
        val ctx = FakePeerContext()
        profile.init(ctx)
        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f1", step = "sign_request", payload = clientAuthPayload())
        )
        val wmp = ctx.notifications.first { it.first == WmpMethods.FLOW_ACTION }.second!!
        assertEquals(JsonPrimitive("k-1"), wmp["dpop_key_id"])
        assertNull(wmp["client_attestation"])
        assertNull(wmp["client_attestation_pop"])

        val legacy = json.encodeToJsonElement(
            SignResponseMessage.serializer(),
            SignResponseMessage(flowId = "f1", dpopKeyId = "k-1", dpopProof = "dpop"),
        ).jsonObject
        assertFalse(legacy.containsKey("client_attestation"))
    }
}
