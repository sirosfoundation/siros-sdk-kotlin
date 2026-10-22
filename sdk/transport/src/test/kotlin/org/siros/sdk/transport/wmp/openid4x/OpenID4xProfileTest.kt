package org.siros.sdk.transport.wmp.openid4x

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.transport.wmp.FlowActionParams
import org.siros.sdk.transport.wmp.FlowCancelParams
import org.siros.sdk.transport.wmp.FlowCompleteParams
import org.siros.sdk.transport.wmp.FlowErrorParams
import org.siros.sdk.transport.wmp.FlowProgressParams
import org.siros.sdk.transport.wmp.FlowStartParams
import org.siros.sdk.transport.wmp.JsonRpcResponse
import org.siros.sdk.transport.wmp.WmpCodec
import org.siros.sdk.transport.wmp.WmpMeta
import org.siros.sdk.transport.wmp.WmpMethods
import org.siros.sdk.transport.wmp.WmpPeerContext

class OpenID4xProfileTest {

    // ---------------------------------------------------------------------------
    // Fake peer context
    // ---------------------------------------------------------------------------

    private class FakePeerContext : WmpPeerContext {
        override val codec = WmpCodec()
        val notifications = mutableListOf<Pair<String, JsonObject?>>()

        override suspend fun notify(method: String, params: JsonObject?) {
            notifications.add(method to params)
        }

        override suspend fun call(method: String, params: JsonObject?): JsonRpcResponse =
            JsonRpcResponse(id = null)
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private fun buildSignPayload(): JsonObject = buildJsonObject {
        put("action", JsonPrimitive("generate_proof"))
        put("nonce", JsonPrimitive("abc123"))
        put("audience", JsonPrimitive("https://issuer.example.com/token"))
    }

    // The engine starts a sign/match sub-flow with wmp.flow.start (go-wallet-backend feat/wmp-integration at
    // b4f33e8, internal/engine/wmphandler.go: sign L2355-2399, match L2404-2425) and reads the wallet's answer
    // from wmp.flow.complete / wmp.flow.error on the SUB-FLOW's id (FlowComplete L2031-2092, FlowError L2095-2142).
    // The wallet is told the parent flow in `parent_flow_id` (SignSubFlowParams.ParentFlowID, match map key).

    /** A profile whose sub-flow answers run inline, attached to a fake peer. */
    private fun attached(config: OpenID4xConfig = OpenID4xConfig()): Pair<OpenID4xProfile, FakePeerContext> {
        val profile = OpenID4xProfile(config)
        profile.subFlowScope = CoroutineScope(Dispatchers.Unconfined)
        val ctx = FakePeerContext()
        profile.init(ctx)
        return profile to ctx
    }

    private fun signStart(subFlowId: String = "sub-1", parent: String? = "f1", payload: JsonObject = buildSignPayload()) =
        FlowStartParams(
            wmp = WmpMeta(), flowId = subFlowId, flowType = OID4FlowTypes.SIGN,
            params = JsonObject(payload + (parent?.let { mapOf("parent_flow_id" to JsonPrimitive(it)) } ?: emptyMap())),
        )

    private fun matchStart(subFlowId: String = "sub-2", parent: String? = "f2") =
        FlowStartParams(
            wmp = WmpMeta(), flowId = subFlowId, flowType = OID4FlowTypes.MATCH,
            params = buildJsonObject {
                put("dcql_query", buildJsonObject {})
                parent?.let { put("parent_flow_id", JsonPrimitive(it)) }
            },
        )

    private fun FakePeerContext.sent(method: String): List<JsonObject> =
        notifications.filter { it.first == method }.mapNotNull { it.second }

    /** The single wmp.flow.complete, checked to be addressed to [subFlowId]; returns its `result`. */
    private fun FakePeerContext.completedResult(subFlowId: String): JsonObject {
        val complete = sent(WmpMethods.FLOW_COMPLETE).single()
        assertEquals(JsonPrimitive(subFlowId), complete["flow_id"])
        return complete["result"]!!.jsonObject
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    @Test
    fun startFlowReturnsMatchingFlowId() = runBlocking {
        val profile = OpenID4xProfile()
        val ctx = FakePeerContext()
        profile.init(ctx)

        val result = profile.startFlow(
            FlowStartParams(wmp = WmpMeta(), flowId = "f1", flowType = OID4FlowTypes.OID4VCI)
        )

        assertEquals("f1", result.flowId)
        assertEquals(OID4FlowTypes.OID4VCI, result.flowType)
    }

    @Test
    fun handleProgressUnknownStepCallsOnProgress() = runBlocking {
        var capturedStep: String? = null
        var capturedFlowId: String? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onProgress = { flowId, step, _ ->
                    capturedFlowId = flowId
                    capturedStep = step
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f4",
                step = VCIStep.RESOLVING_METADATA,
            )
        )

        assertEquals("f4", capturedFlowId)
        assertEquals(VCIStep.RESOLVING_METADATA, capturedStep)
        assertTrue("No notification should be sent for general progress", ctx.notifications.isEmpty())
    }

    @Test
    fun flowCompleteResultOfAnEncryptedIssuanceHasEmptyCredentialsAndSaysSo() {
        val result = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"format":"mso_mdoc"},{"format":"dc+sd-jwt","vct":"urn:v"}],"credential_response_encrypted":true}""",
        ) as JsonObject
        val decoded = FlowCompleteResult.decode(result)!!
        assertTrue(decoded.credentialResponseEncrypted)
        assertEquals(listOf("", ""), decoded.credentials!!.map { it.credential })
        assertEquals("urn:v", decoded.credentials!![1].vct)
        assertEquals(false, FlowCompleteResult.decode(JsonObject(emptyMap()))!!.credentialResponseEncrypted)
        assertNull(FlowCompleteResult.decode(null))
    }

    @Test
    fun flowCompleteResultKeepsOnlyTheDisplayMembersOfAPlainResponsesMetadata() {
        val result = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt","credential":"x"}],"credential_metadata":{"display":[{"name":"N"}],""" +
                """"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"},"claims":[],"ext":1}}""",
        ) as JsonObject
        val metadata = FlowCompleteResult.decode(result)!!.credentialMetadata!!
        assertEquals(listOf("display", "claims"), metadata.members.keys.toList())
        assertTrue(!metadata.members.toString().contains("00112233445566778899aabbccddeeff"))
        assertNull(FlowCompleteResult.decode(JsonObject(emptyMap()))!!.credentialMetadata)
        val malformed = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt","credential":"x","notification_id":"n1"}],"credential_metadata":"text"}""",
        ) as JsonObject
        assertTrue(FlowCompleteResult.decode(malformed)!!.credentialMetadata!!.malformed)
    }

    @Test
    fun aPlainFlowCompleteResultMustCarryAValueForEveryCredential_anEncryptedOneMayNot() {
        fun decode(body: String) = FlowCompleteResult.decode(kotlinx.serialization.json.Json.parseToJsonElement(body) as JsonObject)
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { decode("""{"credentials":[{"format":"dc+sd-jwt"}]}""") }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { decode("""{"credentials":[{"format":"dc+sd-jwt","credential":""}]}""") }
        assertEquals(1, decode("""{"credentials":[{"format":"dc+sd-jwt"}],"credential_response_encrypted":true}""")!!.credentials!!.size)
        assertEquals("x", decode("""{"credentials":[{"format":"dc+sd-jwt","credential":"x"}]}""")!!.credentials!!.single().credential)
    }

    @Test
    fun flowCompleteResultWithANonBooleanEncryptedMarkerReadsItAsFalse() {
        listOf(""""true"""", "1", "null", "{}").forEach { flag ->
            val result = kotlinx.serialization.json.Json.parseToJsonElement(
                """{"credentials":[{"format":"dc+sd-jwt","credential":"x","notification_id":"n1"}],"credential_response_encrypted":$flag}""",
            ) as JsonObject
            val decoded = FlowCompleteResult.decode(result)!!
            assertEquals(flag, false, decoded.credentialResponseEncrypted)
            assertEquals(flag, "n1", decoded.credentials!!.single().notificationId)
        }
    }

    @Test
    fun flowCompleteResultDecodesRedactedMembers() {
        fun decode(members: String?) = FlowCompleteResult.decode(
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"credentials":[{"format":"mso_mdoc","credential":"AA","notification_id":"n"}]""" +
                    (members?.let { ""","redacted_members":$it""" } ?: "") + "}",
            ) as JsonObject,
        )!!
        assertEquals(emptySet<String>(), decode(null).redactedMembers)
        assertEquals(false, decode("[]").renewalMaterialRedacted)
        val replay = decode("""["dpop_jwk","refresh_token"]""")
        assertEquals(setOf("dpop_jwk", "refresh_token"), replay.redactedMembers)
        assertTrue(replay.renewalMaterialRedacted)
        // Only part of the renewal material: still unavailable.
        assertTrue(decode("""["dpop_key_id"]""").renewalMaterialRedacted)
        // A marker that cannot be read says nothing reliable: everything it can list is withheld.
        for (bad in listOf(""""refresh_token"""", "5", "[1]", """[null]""", "{}")) {
            assertTrue(bad, decode(bad).renewalMaterialRedacted)
        }
    }

    @Test
    fun theCredentialIsInNoStringFormOfTheDecodedResult() {
        val result = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"format":"mso_mdoc","credential":"secret-credential"}]}""",
        ) as JsonObject
        val decoded = FlowCompleteResult.decode(result)!!
        assertTrue(!decoded.toString().contains("secret-credential"))
        assertTrue(!decoded.credentials.toString().contains("secret-credential"))
    }

    @Test
    fun aSignSubFlowDecodesTheBlindEncryptionMembers() {
        val codec = WmpCodec()
        val issuance = codec.json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"action":"generate_proof","nonce":"n","audience":"a","credential_response_encryption":{"alg":"ECDH-ES","enc":"A256GCM","required":true}}""",
            ),
        )
        assertEquals("ECDH-ES", issuance.credentialResponseEncryption!!.alg)
        assertEquals(true, issuance.credentialResponseEncryption!!.required)
        val decrypt = codec.json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement("""{"action":"decrypt_credential_response","jwe":"a.b.c.d.e","deferred":true}"""),
        )
        assertEquals("a.b.c.d.e", decrypt.jwe)
        assertEquals(true, decrypt.deferred)
        val vp = codec.json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"action":"sign_presentation","nonce":"n","audience":"v","state":"st","response_encryption":{"jwk":{"kty":"EC","kid":"k1"},"alg":"ECDH-ES","enc":"A128GCM"}}""",
            ),
        )
        assertEquals("st", vp.state)
        assertEquals("A128GCM", vp.responseEncryption!!.enc)
    }

    @Test
    fun aSignSubFlowDecodesTheVerifiedRequest() {
        val codec = WmpCodec()
        val p = codec.json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"action":"sign_presentation","nonce":"n","audience":"admin","verified_request":{"client_id":"x509_san_dns:v.example",""" +
                    """"response_uri":"https://v.example/r","signed":true,"signature_verification":"verified","extra":1}}""",
            ),
        )
        assertEquals("x509_san_dns:v.example", p.verifiedRequest!!.clientId)
        assertEquals(true, p.verifiedRequest!!.signed)
        assertNull(codec.json.decodeFromJsonElement(SignSubFlowParams.serializer(), buildSignPayload()).verifiedRequest)
    }

    @Test
    fun aSignResultNeverCarriesAResponseJweTogetherWithAVpToken() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SignSubFlowResult(responseJwe = "a.b.c.d.e", vpToken = "t") }
    }

    @Test
    fun aSignResultWithAnErrorCannotCarryAResponseJwe() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SignSubFlowResult(responseJwe = "h.k.i.c.t", error = "nope") }
    }

    @Test
    fun handleCancelTellsTheConfiguredCancelCallbackTheFlowId() = runBlocking {
        val cancelled = mutableListOf<String>()
        val profile = OpenID4xProfile(OpenID4xConfig(onCancel = { cancelled += it }))
        profile.init(FakePeerContext())
        profile.handleCancel(FlowCancelParams(wmp = WmpMeta(), flowId = "f-cancel", reason = "user"))
        assertEquals(listOf("f-cancel"), cancelled)
        // No callback configured: still fine.
        OpenID4xProfile().handleCancel(FlowCancelParams(wmp = WmpMeta(), flowId = "f2"))
    }

    @Test
    fun handleCompleteCallsOnComplete() = runBlocking {
        var capturedFlowId: String? = null
        var capturedResult: JsonObject? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onComplete = { flowId, result ->
                    capturedFlowId = flowId
                    capturedResult = result
                }
            )
        )
        profile.init(FakePeerContext())

        val result = buildJsonObject { put("status", JsonPrimitive("ok")) }
        profile.handleComplete(FlowCompleteParams(wmp = WmpMeta(), flowId = "f5", result = result))

        assertEquals("f5", capturedFlowId)
        assertEquals(result, capturedResult)
    }

    @Test
    fun handleErrorCallsOnError() = runBlocking {
        var capturedCode: String? = null
        var capturedMessage: String? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onError = { _, code, message ->
                    capturedCode = code
                    capturedMessage = message
                }
            )
        )
        profile.init(FakePeerContext())

        profile.handleError(
            FlowErrorParams(wmp = WmpMeta(), flowId = "f6", code = "ISSUER_ERROR", message = "rejected")
        )

        assertEquals("ISSUER_ERROR", capturedCode)
        assertEquals("rejected", capturedMessage)
    }

    @Test
    fun handleActionAlwaysAccepts() = runBlocking {
        val profile = OpenID4xProfile()
        profile.init(FakePeerContext())

        val result = profile.handleAction(
            FlowActionParams(wmp = WmpMeta(), flowId = "f10", action = OID4Action.ACCEPT_OFFER)
        )

        assertTrue(result.accepted)
        assertEquals("f10", result.flowId)
    }

    @Test
    fun aSignSubFlowIsAnsweredWithFlowCompleteOnTheSubFlowId() = runBlocking {
        var capturedFlowId: String? = null
        var capturedParams: SignSubFlowParams? = null
        val (profile, ctx) = attached(
            OpenID4xConfig(
                onSignRequest = { flowId, params ->
                    capturedFlowId = flowId
                    capturedParams = params
                    SignSubFlowResult(proofs = listOf(ProofObject(jwt = "jwt-token")))
                },
            ),
        )

        val ack = profile.startFlow(signStart(subFlowId = "sub-1", parent = "f1"))

        assertEquals("sub-1", ack.flowId)
        assertEquals(OID4FlowTypes.SIGN, ack.flowType)
        // The wallet's per-flow state is keyed by the PARENT flow it started, not the engine's sub-flow id.
        assertEquals("f1", capturedFlowId)
        assertEquals("abc123", capturedParams!!.nonce)
        val result = ctx.completedResult("sub-1")
        assertEquals("jwt-token", result["proofs"]!!.jsonArray[0].jsonObject["jwt"]!!.jsonPrimitive.content)
        // The engine unmarshals `result` into its SignResponseMessage and fills the ids itself.
        assertNull(result["action"])
        assertNull(result["flow_id"])
        assertTrue(
            "A sign answer is never a flow.action on the parent flow (it needs a message_id the wallet is never given)",
            ctx.notifications.none { it.first == WmpMethods.FLOW_ACTION },
        )
        // The answer is addressable by go-wmp's FlowCompleteParams.
        ctx.codec.json.decodeFromJsonElement(FlowCompleteParams.serializer(), ctx.sent(WmpMethods.FLOW_COMPLETE).single())
        Unit
    }

    @Test
    fun theSubFlowAcknowledgementDoesNotWaitForTheAnswer() = runBlocking {
        val gate = CompletableDeferred<Unit>()
        val (profile, ctx) = attached(
            OpenID4xConfig(onSignRequest = { _, _ -> gate.await(); SignSubFlowResult(vpToken = "late") }),
        )

        // The engine waits 30 s for this acknowledgement, not for the answer: a user prompt must not hold it up.
        val ack = withTimeout(2_000) { profile.startFlow(signStart()) }

        assertEquals("sub-1", ack.flowId)
        assertTrue("nothing is answered before the handler finishes", ctx.notifications.isEmpty())
        gate.complete(Unit)
        assertEquals(JsonPrimitive("late"), ctx.completedResult("sub-1")["vp_token"])
    }

    @Test
    fun closingTheProfileStopsASubFlowAnswerStillRunning() = runBlocking {
        val gate = CompletableDeferred<Unit>()
        val (profile, ctx) = attached(
            OpenID4xConfig(onSignRequest = { _, _ -> gate.await(); SignSubFlowResult(vpToken = "late") }),
        )
        withTimeout(2_000) { profile.startFlow(signStart()) }

        profile.close()
        gate.complete(Unit)

        assertTrue("a closed session answers nothing", ctx.notifications.isEmpty())
    }

    @Test
    fun aGeneratingProofProgressIsPlainProgressNotASignRequest() = runBlocking {
        var signed = false
        var progressed: String? = null
        val (profile, ctx) = attached(
            OpenID4xConfig(
                onSignRequest = { _, _ -> signed = true; SignSubFlowResult() },
                onProgress = { _, step, _ -> progressed = step },
            ),
        )

        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f1", step = VCIStep.GENERATING_PROOF, payload = buildSignPayload()),
        )

        assertTrue("the engine asks through a sign sub-flow, not a progress step", !signed)
        assertEquals(VCIStep.GENERATING_PROOF, progressed)
        assertTrue(ctx.notifications.isEmpty())
    }

    @Test
    fun aMatchSubFlowIsAnsweredWithFlowCompleteOnTheSubFlowId() = runBlocking {
        var capturedFlowId: String? = null
        var capturedPayload: JsonObject? = null
        val (profile, ctx) = attached(
            OpenID4xConfig(
                onMatchRequest = { flowId, payload ->
                    capturedFlowId = flowId
                    capturedPayload = payload
                    MatchResult(matches = listOf(CredentialMatch(credentialId = "cred-1", credentialQueryId = "q1")))
                },
            ),
        )

        val ack = profile.startFlow(matchStart(subFlowId = "sub-2", parent = "f2"))

        assertEquals(OID4FlowTypes.MATCH, ack.flowType)
        assertEquals("f2", capturedFlowId)
        assertNotNull(capturedPayload!!["dcql_query"])
        val result = ctx.completedResult("sub-2")
        // The engine's MatchResponseMessage: `matches` with credential_id / credential_query_id.
        val match = result["matches"]!!.jsonArray.single().jsonObject
        assertEquals(JsonPrimitive("cred-1"), match["credential_id"])
        assertEquals(JsonPrimitive("q1"), match["credential_query_id"])
        assertTrue(ctx.notifications.none { it.first == WmpMethods.FLOW_ACTION })
    }

    @Test
    fun emptyMatchSetIsAlsoReportedAsCredentialsMatchedWithItsReason() = runBlocking {
        val reason = "This wallet holds no credential matching the request"
        val (profile, ctx) = attached(
            OpenID4xConfig(onMatchRequest = { _, _ -> MatchResult(matches = emptyList(), noMatchReason = reason) }),
        )

        profile.startFlow(matchStart(subFlowId = "sub-2", parent = "f-nomatch"))

        assertEquals(JsonPrimitive(reason), ctx.completedResult("sub-2")["no_match_reason"])
        // credentials_matched is an action on the PARENT flow; go-wmp's FlowActionParams carries its members under
        // `params` (methods.go:184-189), which is where the engine takes its payload from (wmphandler.go FlowAction).
        val action = ctx.sent(WmpMethods.FLOW_ACTION).single()
        assertEquals(JsonPrimitive(OID4Action.CREDENTIALS_MATCHED), action["action"])
        assertEquals(JsonPrimitive("f-nomatch"), action["flow_id"])
        val members = action["params"]!!.jsonObject
        assertEquals(JsonPrimitive(reason), members["no_match_reason"])
        assertEquals(0, members["matches"]!!.jsonArray.size)
        assertNull("members are not flat next to `action`", action["no_match_reason"])
    }

    @Test
    fun aNonEmptyMatchSetIsNotReportedAsCredentialsMatched() = runBlocking {
        val (profile, ctx) = attached(
            OpenID4xConfig(onMatchRequest = { _, _ -> MatchResult(matches = listOf(CredentialMatch(credentialId = "cred-1"))) }),
        )

        profile.startFlow(matchStart())

        assertTrue(
            "A wallet with something to offer must not report an empty match set",
            ctx.sent(WmpMethods.FLOW_ACTION).none { it["action"] == JsonPrimitive(OID4Action.CREDENTIALS_MATCHED) },
        )
    }

    @Test
    fun trustResultCarriesItsMembersUnderParams() = runBlocking {
        var capturedFlowId: String? = null
        val (profile, ctx) = attached(
            OpenID4xConfig(
                onTrustEvaluation = { flowId, _ ->
                    capturedFlowId = flowId
                    TrustResult(trusted = true, framework = "EUCS")
                },
            ),
        )

        // oid4vci.go:1574-1577 (issuer) / oid4vp.go ~1266 (verifier): step + `trust_evaluation_required` + `request`.
        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(), flowId = "f3", step = VCIStep.EVALUATING_TRUST,
                payload = buildJsonObject {
                    put("trust_evaluation_required", JsonPrimitive(true))
                    put("request", buildJsonObject { put("subject_id", JsonPrimitive("https://issuer.example")) })
                },
            ),
        )

        assertEquals("f3", capturedFlowId)
        val action = ctx.sent(WmpMethods.FLOW_ACTION).single()
        assertEquals(JsonPrimitive("trust_result"), action["action"])
        assertEquals(JsonPrimitive("f3"), action["flow_id"])
        val members = action["params"]!!.jsonObject
        assertEquals(JsonPrimitive(true), members["trusted"])
        assertEquals(JsonPrimitive("EUCS"), members["framework"])
        assertNull("members are not flat next to `action`: the engine would see an empty payload", action["trusted"])
    }

    @Test
    fun informationalTrustProgressIsNotAnswered() = runBlocking {
        var evaluated = false
        var progressed = false
        val (profile, ctx) = attached(
            OpenID4xConfig(
                onTrustEvaluation = { _, _ -> evaluated = true; TrustResult(trusted = true) },
                onProgress = { _, _, _ -> progressed = true },
            ),
        )

        // oid4vci.go:1443: the same step is also sent as a plain message, which wants no answer.
        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(), flowId = "f3", step = VCIStep.EVALUATING_TRUST,
                payload = buildJsonObject { put("message", JsonPrimitive("Evaluating issuer trust")) },
            ),
        )

        assertTrue("an unrequested trust_result could satisfy the engine's later wait with a stale answer", !evaluated)
        assertTrue(progressed)
        assertTrue(ctx.notifications.isEmpty())
    }

    @Test
    fun aVerifierTrustRequestIsAnswered() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig(onTrustEvaluation = { _, _ -> TrustResult(trusted = false, reason = "no") }))

        // oid4vp.go ~1266: the verifier's request is the `evaluating_verifier_trust` step, not `evaluating_trust`.
        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(), flowId = "f3", step = VPStep.EVALUATING_VERIFIER_TRUST,
                payload = buildJsonObject {
                    put("trust_evaluation_required", JsonPrimitive(true))
                    put("request", buildJsonObject {})
                },
            ),
        )

        assertEquals(JsonPrimitive(false), ctx.sent(WmpMethods.FLOW_ACTION).single()["params"]!!.jsonObject["trusted"])
    }

    @Test
    fun theBlindEncryptionAnswersAreMembersOfTheSubFlowResult() = runBlocking {
        val jwk = buildJsonObject { put("kty", JsonPrimitive("EC")) }
        val (profile, ctx) = attached(
            OpenID4xConfig(
                onSignRequest = { _, _ ->
                    SignSubFlowResult(credentialResponseEncryptionJwk = jwk, responseJwe = "h.k.i.c.t")
                },
            ),
        )
        profile.startFlow(signStart())
        val result = ctx.completedResult("sub-1")
        assertEquals(jwk, result["credential_response_encryption_jwk"])
        assertEquals(JsonPrimitive("h.k.i.c.t"), result["response_jwe"])
        assertNull(result["vp_token"])
    }

    @Test
    fun aDecryptAnswerCarriesExactlyOneOfCountTransactionIdOrError() = runBlocking {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SignSubFlowResult(credentialCount = 1, transactionId = "tx") }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SignSubFlowResult(credentialCount = 1, error = "x") }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SignSubFlowResult(transactionId = "tx", error = "x") }

        val (counted, countedCtx) = attached(OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(credentialCount = 3) }))
        counted.startFlow(signStart())
        val count = countedCtx.completedResult("sub-1")
        assertEquals(JsonPrimitive(3), count["credential_count"])
        assertNull(count["transaction_id"])

        val (deferred, deferredCtx) = attached(OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(transactionId = "tx-1", interval = 5) }))
        deferred.startFlow(signStart())
        val pending = deferredCtx.completedResult("sub-1")
        assertEquals(JsonPrimitive("tx-1"), pending["transaction_id"])
        assertEquals(JsonPrimitive(5), pending["interval"])
        assertNull(pending["credential_count"])
    }

    @Test
    fun aFailedDecryptionAnswersWithAnErrorMemberAlone() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(error = "could not be decrypted") }))
        profile.startFlow(signStart())
        val result = ctx.completedResult("sub-1")
        assertEquals(JsonPrimitive("could not be decrypted"), result["error"])
        assertNull(result["response_jwe"])
    }

    @Test
    fun aRefusedSignRequestIsAFlowErrorNeverAResultCarryingAResponseJwe() = runBlocking {
        val (profile, ctx) = attached(
            OpenID4xConfig(onSignRequest = { _, _ -> throw org.siros.sdk.credentials.WalletException("the user declined") }),
        )

        profile.startFlow(signStart())

        assertTrue(ctx.sent(WmpMethods.FLOW_COMPLETE).isEmpty())
        val error = ctx.sent(WmpMethods.FLOW_ERROR).single()
        assertEquals(JsonPrimitive("sub-1"), error["flow_id"])
        assertTrue(ctx.notifications.none { (_, params) -> params?.toString()?.contains("response_jwe") == true })
    }

    @Test
    fun aSignRefusalIsAFlowErrorWithReasonRejected() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig(onSignRequest = { _, _ -> throw SignRefusedException("jarm audience is empty") }))

        profile.startFlow(signStart())

        // go-wallet-backend#472: wmp.flow.error with data.reason "rejected" on the sub-flow ends RequestSign and
        // posts access_denied. The wallet-local reason is never put on the wire.
        assertTrue(ctx.sent(WmpMethods.FLOW_COMPLETE).isEmpty())
        val error = ctx.sent(WmpMethods.FLOW_ERROR).single()
        assertEquals(JsonPrimitive("sub-1"), error["flow_id"])
        assertEquals(JsonPrimitive("rejected"), error["data"]!!.jsonObject["reason"])
        assertTrue(!error.toString().contains("jarm audience"))
    }

    @Test
    fun anOrdinarySignResultCarriesNoBlindEncryptionMembers() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(proofs = listOf(ProofObject(jwt = "t"))) }))
        profile.startFlow(signStart())
        val result = ctx.completedResult("sub-1")
        for (member in listOf("credential_response_encryption_jwk", "transaction_id", "interval", "response_jwe", "error", "credential_count")) {
            assertNull(member, result[member])
        }
    }

    @Test
    fun aSignHandlerFailureIsAFlowErrorWithANumericCodeAndNoReasonText() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig(onSignRequest = { _, _ -> throw RuntimeException("key unavailable: secret-key-id-42") }))

        profile.startFlow(signStart())

        val error = ctx.sent(WmpMethods.FLOW_ERROR).single()
        assertEquals(JsonPrimitive("sub-1"), error["flow_id"])
        // go-wmp's FlowErrorParams.Code is an int (methods.go:207-213): a string code does not decode there.
        assertEquals(JsonPrimitive(-31006), error["code"])
        assertTrue("a sign failure's text can name keys; it stays local", !error.toString().contains("secret-key-id-42"))
    }

    @Test
    fun refusedTransactionDataIsAFlowErrorTheEngineReadsAsUnsupportedTransactionData() = runBlocking {
        val (profile, ctx) = attached(
            OpenID4xConfig(
                onSignRequest = { _, _ ->
                    throw org.siros.sdk.credentials.TransactionDataError(
                        org.siros.sdk.credentials.TransactionDataReason.DISABLED,
                        "refused",
                    )
                },
            ),
        )

        profile.startFlow(signStart(subFlowId = "sub-8"))

        val error = ctx.sent(WmpMethods.FLOW_ERROR).single()
        assertEquals(JsonPrimitive("sub-8"), error["flow_id"])
        // wmphandler.go FlowError L2118: code == wmp.ErrCapabilityNotSupported (-31005) => ErrCodeUnsupportedTransactionData.
        assertEquals(JsonPrimitive(-31005), error["code"])
        assertEquals(JsonPrimitive("disabled"), error["message"])
        assertEquals(JsonPrimitive("invalid_transaction_data"), error["data"]!!.jsonObject["verifier_error"])
    }

    @Test
    fun aSignSubFlowWithoutAParentFlowIsAFlowError() = runBlocking {
        var called = false
        val (profile, ctx) = attached(OpenID4xConfig(onSignRequest = { _, _ -> called = true; SignSubFlowResult() }))

        profile.startFlow(signStart(parent = null))

        assertTrue(!called)
        assertEquals(JsonPrimitive("sub-1"), ctx.sent(WmpMethods.FLOW_ERROR).single()["flow_id"])
    }

    @Test
    fun aMatchSubFlowWithoutAParentFlowIsAFlowError() = runBlocking {
        var called = false
        val (profile, ctx) = attached(OpenID4xConfig(onMatchRequest = { _, _ -> called = true; MatchResult(matches = emptyList()) }))

        profile.startFlow(matchStart(parent = null))

        assertTrue(!called)
        assertEquals(JsonPrimitive("sub-2"), ctx.sent(WmpMethods.FLOW_ERROR).single()["flow_id"])
    }

    @Test
    fun aMatchHandlerFailureIsAFlowErrorOnTheSubFlow() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig(onMatchRequest = { _, _ -> throw RuntimeException("store unavailable") }))

        profile.startFlow(matchStart())

        assertTrue(ctx.sent(WmpMethods.FLOW_COMPLETE).isEmpty())
        val error = ctx.sent(WmpMethods.FLOW_ERROR).single()
        assertEquals(JsonPrimitive("sub-2"), error["flow_id"])
        assertEquals(JsonPrimitive(-31006), error["code"])
    }

    @Test
    fun trustHandlerExceptionSendsTrustedFalse() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig(onTrustEvaluation = { _, _ -> throw RuntimeException("trust store unavailable") }))

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(), flowId = "f8", step = VCIStep.EVALUATING_TRUST,
                payload = buildJsonObject { put("trust_evaluation_required", JsonPrimitive(true)) },
            ),
        )

        val action = ctx.sent(WmpMethods.FLOW_ACTION).single()
        assertEquals(JsonPrimitive("trust_result"), action["action"])
        val members = action["params"]!!.jsonObject
        assertEquals(JsonPrimitive(false), members["trusted"])
        assertEquals(JsonPrimitive("trust store unavailable"), members["reason"])
    }

    @Test
    fun noNotificationSentWhenPeerNotInitialized() = runBlocking {
        // Profile never had init() called -> all send helpers are no-ops.
        val profile = OpenID4xProfile(OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(proofs = listOf(ProofObject(jwt = "t"))) }))
        profile.subFlowScope = CoroutineScope(Dispatchers.Unconfined)

        profile.startFlow(signStart())
        // Passes as long as nothing throws.
        Unit
    }

    @Test
    fun withoutCallbacksTheEngineIsToldItsSubFlowsAreUnsupported() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig())

        profile.startFlow(signStart(subFlowId = "s"))
        profile.startFlow(matchStart(subFlowId = "m"))
        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(), flowId = "f11", step = VCIStep.EVALUATING_TRUST,
                payload = buildJsonObject { put("trust_evaluation_required", JsonPrimitive(true)) },
            ),
        )
        profile.handleComplete(FlowCompleteParams(wmp = WmpMeta(), flowId = "f11"))
        profile.handleError(FlowErrorParams(wmp = WmpMeta(), flowId = "f11"))
        profile.handleCancel(FlowCancelParams(wmp = WmpMeta(), flowId = "f11"))

        // An unanswered sub-flow would leave the engine waiting out its three-minute sign timeout.
        val errors = ctx.sent(WmpMethods.FLOW_ERROR)
        assertEquals(listOf(JsonPrimitive("s"), JsonPrimitive("m")), errors.map { it["flow_id"] })
        assertTrue(errors.all { it["code"] == JsonPrimitive(-31005) })
        assertTrue(ctx.notifications.none { it.first != WmpMethods.FLOW_ERROR })
    }

    @Test
    fun profileHasCorrectNameAndCapabilities() {
        val profile = OpenID4xProfile()
        assertEquals("openid4x", profile.name)
        assertTrue(profile.capabilities.contains("oid4vci"))
        assertTrue(profile.capabilities.contains("oid4vp"))
        assertTrue(profile.flowTypes.contains(OID4FlowTypes.OID4VCI))
        assertTrue(profile.flowTypes.contains(OID4FlowTypes.OID4VP))
        // The engine's sub-flow types (go-wmp FlowTypeSign = "sign", the engine's literal "match").
        assertTrue(profile.flowTypes.contains("sign"))
        assertTrue(profile.flowTypes.contains("match"))
    }

    @Test
    fun aSignResultIncludesTheVpToken() = runBlocking {
        val (profile, ctx) = attached(OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(vpToken = "vp-token-value") }))
        profile.startFlow(signStart())
        val result = ctx.completedResult("sub-1")
        assertEquals(JsonPrimitive("vp-token-value"), result["vp_token"])
        assertNull(result["proofs"])
    }

    @Test
    fun aFlowErrorWithTheEnginesIntegerCodeDecodes() {
        val codec = WmpCodec()
        // wmphandler.go SendJSON FlowErrorMessage: Code is mapErrorCode(...), an int (-31006 for most engine errors).
        val params = codec.json.decodeFromJsonElement(
            FlowErrorParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"wmp":{"version":"0.1"},"flow_id":"f1","code":-31006,"message":"Credential issuance failed"}""",
            ),
        )
        assertEquals("-31006", params.code)
        assertEquals("Credential issuance failed", params.message)
        // A string code (what older peers and tests send) still reads.
        assertEquals(
            "ERR",
            codec.json.decodeFromJsonElement(
                FlowErrorParams.serializer(),
                kotlinx.serialization.json.Json.parseToJsonElement("""{"flow_id":"f1","code":"ERR"}"""),
            ).code,
        )
    }

    @Test
    fun aNumericFlowErrorCodeIsWrittenAsAJsonNumber() {
        val codec = WmpCodec()
        val written = codec.encodeParams(FlowErrorParams(wmp = WmpMeta(), flowId = "f1", code = "-31005", message = "m"))
        assertEquals(JsonPrimitive(-31005), written["code"])
        assertEquals(
            JsonPrimitive("ERR"),
            codec.encodeParams(FlowErrorParams(wmp = WmpMeta(), flowId = "f1", code = "ERR"))["code"],
        )
    }
}
