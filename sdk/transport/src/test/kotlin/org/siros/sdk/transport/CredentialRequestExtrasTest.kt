package org.siros.sdk.transport

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.siros.sdk.transport.engine.SignResponseMessage
import org.siros.sdk.transport.wmp.WmpCodec
import org.siros.sdk.transport.wmp.WmpMethods
import org.siros.sdk.transport.wmp.WmpPeerContext
import org.siros.sdk.transport.wmp.WmpMeta
import org.siros.sdk.transport.wmp.FlowProgressParams
import org.siros.sdk.transport.wmp.JsonRpcResponse
import org.siros.sdk.transport.wmp.openid4x.OpenID4xConfig
import org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile
import org.siros.sdk.transport.wmp.openid4x.ProofObject
import org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult

/**
 * `credential_request_extras` on both transports.
 *
 * The wallet, not the backend, holds the state some credential formats need
 * at issuance — blind BBS requires a commitment computed locally, and the
 * issuer will not sign without it. The backend builds the credential
 * request, so that value has to travel over whichever transport is in play.
 *
 * Production runs the legacy websocket protocol today; WMP is not deployed
 * yet and has to work alongside it rather than replace it. So the property
 * that matters is not that either transport carries the field, but that
 * they carry it **identically** — one member name, one shape, one backend
 * code path, and a flow that behaves the same whichever transport it runs
 * over.
 */
class CredentialRequestExtrasTest {

    private val json = Json { encodeDefaults = false }

    private val extras: JsonObject = buildJsonObject {
        put("bbs_commitment", JsonPrimitive("q29tbWl0bWVudA"))
        put("bbs_committed_claims", Json.parseToJsonElement("""["/device_pin_hash"]"""))
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

    /** The shape the backend sends to open the sign sub-flow. */
    private fun signPayload(): JsonObject = buildJsonObject {
        put("action", JsonPrimitive("generate_proof"))
        put("nonce", JsonPrimitive("abc123"))
        put("audience", JsonPrimitive("https://issuer.example.com/token"))
    }

    // -----------------------------------------------------------------------

    /** The legacy protocol carries it under the specified member name. */
    @Test
    fun theLegacyProtocolCarriesTheExtras() {
        val encoded = json.encodeToJsonElement(
            SignResponseMessage.serializer(),
            SignResponseMessage(flowId = "f1", credentialRequestExtras = extras),
        ).jsonObject

        val carried = encoded["credential_request_extras"]
        assertNotNull("legacy sign_response must carry credential_request_extras", carried)
        assertEquals(extras, carried!!.jsonObject)
    }

    /** WMP carries it under the same member name. */
    @Test
    fun wmpCarriesTheExtras() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ ->
                    SignSubFlowResult(
                        proofs = listOf(ProofObject(jwt = "jwt-token")),
                        credentialRequestExtras = extras,
                    )
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f1", step = "sign_request", payload = signPayload())
        )

        val params = ctx.notifications.first { it.first == WmpMethods.FLOW_ACTION }.second!!
        assertEquals(JsonPrimitive("sign_response"), params["action"])
        val carried = params["credential_request_extras"]
        assertNotNull("WMP sign_response must carry credential_request_extras", carried)
        assertEquals(extras, carried!!.jsonObject)
    }

    /**
     * The two transports must put the *same* thing on the wire.
     *
     * This is the test the change exists for. If the member name or shape
     * drifted between them, a backend would need two code paths and a flow
     * would behave differently depending on which transport carried it —
     * and the divergence would only show up once WMP was deployed alongside
     * the legacy protocol, which is exactly when it is most expensive.
     */
    @Test
    fun bothTransportsAgreeOnTheWireShape() = runBlocking {
        val legacy = json.encodeToJsonElement(
            SignResponseMessage.serializer(),
            SignResponseMessage(flowId = "f1", credentialRequestExtras = extras),
        ).jsonObject["credential_request_extras"]

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ -> SignSubFlowResult(credentialRequestExtras = extras) }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)
        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f1", step = "sign_request", payload = signPayload())
        )
        val wmp = ctx.notifications.first { it.first == WmpMethods.FLOW_ACTION }
            .second!!["credential_request_extras"]

        assertEquals("the two transports must serialise this identically", legacy, wmp)
    }

    /**
     * Absent on every flow that does not need it — which is all of them
     * except blind BBS issuance.
     *
     * A member that appeared as `null` on ordinary flows would change the
     * bytes on the wire for every existing issuance, which is not a change
     * worth making to carry an optional field.
     */
    @Test
    fun ordinaryFlowsCarryNoSuchMember() = runBlocking {
        val legacy = json.encodeToJsonElement(
            SignResponseMessage.serializer(),
            SignResponseMessage(flowId = "f1", proofs = null),
        ).jsonObject
        assertFalse(
            "legacy sign_response must omit the member entirely when unused",
            legacy.containsKey("credential_request_extras"),
        )

        val profile = OpenID4xProfile(
            OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(proofs = listOf(ProofObject(jwt = "t"))) })
        )
        val ctx = FakePeerContext()
        profile.init(ctx)
        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f1", step = "sign_request", payload = signPayload())
        )
        val params = ctx.notifications.first { it.first == WmpMethods.FLOW_ACTION }.second!!
        assertNull(
            "WMP sign_response must omit the member entirely when unused",
            params["credential_request_extras"],
        )
    }

    /**
     * A backend reading the legacy shape must tolerate the member being
     * absent, which is what every deployed wallet sends today.
     */
    @Test
    fun anOlderWalletsMessageStillDecodes() {
        val fromDeployedWallet = """{"type":"sign_response","flow_id":"f1","proofs":[{"proof_type":"jwt","jwt":"t"}]}"""
        val decoded = Json { ignoreUnknownKeys = true }
            .decodeFromString(SignResponseMessage.serializer(), fromDeployedWallet)
        assertNull(decoded.credentialRequestExtras)
        assertEquals("f1", decoded.flowId)
    }
}
