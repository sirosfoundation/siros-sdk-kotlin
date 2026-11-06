package org.siros.sdk.transport.wmp.openid4x

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.transport.wmp.FakeTransport
import org.siros.sdk.transport.wmp.WmpCodec
import org.siros.sdk.transport.wmp.WmpPeer
import org.siros.sdk.transport.wmp.WmpSession
import org.siros.sdk.transport.wmp.WmpSessionConfig

/**
 * siros-wallet-core's typed asks (engine-ports' `Host` vocabulary), driven by the frames the
 * engine sends: each ask arrives as a `wmp.flow.start` with a `<parent>::<type>::<seq>` child id
 * and its params struct, is acknowledged, and is answered with `wmp.flow.complete` carrying the
 * ask's own result struct on the child's id - or with the structured NEGATIVE the engine relays
 * correctly (a consent decline, a named sign-stage refusal), which is never a bare flow error.
 *
 * The dialect fork is exercised too: the same `sign`/`match` flow types carry go-wmp's params
 * (an `action` member, a `parent_flow_id`) or the Rust engine's (bare `SignParams`, `flow_id`),
 * and the profile must route each to its dialect's handler and answer shape.
 */
class OpenID4xTypedAskTest {

    private val codec = WmpCodec()

    private fun CoroutineScope.connected(transport: FakeTransport, peer: WmpPeer) {
        val job = launch { peer.connect("token") }
        runBlocking {
            withTimeout(5_000) { while (transport.sentMessages.isEmpty()) delay(10) }
            val createReq = codec.decodeRequest(transport.sentMessages.last())
            transport.receiveFromServer(
                """{"jsonrpc":"2.0","id":"${createReq.id}","result":{"wmp":{"version":"0.1","session_id":"s1"},"resumption_token":"r"}}"""
                    .toByteArray(),
            )
            job.join()
        }
    }

    private suspend fun FakeTransport.awaitSent(predicate: (JsonObject) -> Boolean): JsonObject = withTimeout(5_000) {
        while (true) {
            sentMessages.map { Json.parseToJsonElement(String(it)).jsonObject }.firstOrNull(predicate)?.let { return@withTimeout it }
            delay(10)
        }
        @Suppress("UNREACHABLE_CODE") error("unreachable")
    }

    private fun engineAsk(childId: String, type: String, params: String) =
        """{"jsonrpc":"2.0","id":"call-1","method":"wmp.flow.start","params":{"wmp":{"version":"0.1","session_id":"s1"},"flow_type":"$type","flow_id":"$childId","params":$params}}"""

    /** One ask in, and the wmp.flow.complete answering THAT child, as a pair of (child id, result object). */
    private suspend fun FakeTransport.driveAsk(childId: String, rawFrame: String): Pair<String, JsonObject> {
        receiveFromServer(rawFrame.toByteArray())
        val complete = awaitSent {
            it["method"] == JsonPrimitive("wmp.flow.complete") &&
                (it["params"] as? JsonObject)?.get("flow_id") == JsonPrimitive(childId)
        }
        val params = complete["params"]!!.jsonObject
        return (params["flow_id"] as JsonPrimitive).content to params["result"]!!.jsonObject
    }

    // ── sign: the dialect fork ────────────────────────────────────────────────────

    @Test
    fun aBareSignAskWithoutAnActionMemberIsAnsweredWithTheSignatureByteArray() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onProofSign = { parent, params ->
                        assertEquals("parent-1", parent)
                        // Vec<u8> on the wire: the byte values, signed by the named key.
                        assertEquals(listOf(104, 101, 108, 108, 111), params.toSign)
                        assertEquals("kid-9", params.keyId)
                        assertEquals("ES256", params.algorithm)
                        byteArrayOf(4, 3, 2, 1)
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (childId, result) = transport.driveAsk(
            "parent-1::sign::1",
            engineAsk(
                "parent-1::sign::1", "sign",
                """{"flow_id":"parent-1","to_sign":[104,101,108,108,111],"key_id":"kid-9","algorithm":"ES256"}""",
            ),
        )
        assertEquals("parent-1::sign::1", childId)
        assertEquals(
            kotlinx.serialization.json.buildJsonArray {
                add(JsonPrimitive(4)); add(JsonPrimitive(3)); add(JsonPrimitive(2)); add(JsonPrimitive(1))
            },
            result["signature"],
        )
        peer.close()
    }

    @Test
    fun aSignAskStillCarryingAnActionMemberRoutesToTheGoWmpHandler() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        var proofSignSawIt = false
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onSignRequest = { parent, params ->
                        assertEquals("parent-1", parent)
                        assertEquals("generate_proof", params.action)
                        SignSubFlowResult(proofs = listOf(ProofObject(jwt = "p")))
                    },
                    onProofSign = { _, _ -> proofSignSawIt = true; ByteArray(0) },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "child-1",
            engineAsk(
                "child-1", "sign",
                """{"action":"generate_proof","nonce":"n","audience":"a","parent_flow_id":"parent-1"}""",
            ),
        )
        assertEquals(JsonPrimitive("p"), result["proofs"]!!.jsonArray.single().jsonObject["jwt"])
        assertTrue("the bare-sign handler must not see a go-wmp ask", !proofSignSawIt)
        peer.close()
    }

    @Test
    fun aBareSignAskWithoutAHandlerIsARefusalNotASilentTimeout() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(OpenID4xProfile(OpenID4xConfig()))
        connected(transport, peer)

        transport.receiveFromServer(
            engineAsk("p::sign::1", "sign", """{"flow_id":"p","to_sign":[1],"key_id":null,"algorithm":"ES256"}""").toByteArray(),
        )
        val error = transport.awaitSent { it["method"] == JsonPrimitive("wmp.flow.error") }
        val params = error["params"]!!.jsonObject
        assertEquals(JsonPrimitive("p::sign::1"), params["flow_id"])
        assertEquals(JsonPrimitive(-31005), params["code"])
        peer.close()
    }

    // ── signing_key ───────────────────────────────────────────────────────────────

    @Test
    fun aSigningKeyAskIsAnsweredWithTheJwkAndNoKeyAsAnEmptyObject() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onSigningKey = { parent, keyId ->
                        when (keyId) {
                            "kid-9" -> {
                                assertEquals("p-1", parent)
                                EngineSigningKeyResult(
                                    jwk = kotlinx.serialization.json.buildJsonObject {
                                        put("kty", JsonPrimitive("EC"))
                                        put("kid", JsonPrimitive("kid-9"))
                                    },
                                )
                            }
                            else -> EngineSigningKeyResult(jwk = null)
                        }
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (_, withKey) = transport.driveAsk(
            "p-1::signing_key::1",
            engineAsk("p-1::signing_key::1", "signing_key", """{"flow_id":"p-1","key_id":"kid-9"}"""),
        )
        assertEquals(JsonPrimitive("kid-9"), withKey["jwk"]!!.jsonObject["kid"])

        val (_, noKey) = transport.driveAsk(
            "p-1::signing_key::2",
            engineAsk("p-1::signing_key::2", "signing_key", """{"flow_id":"p-1","key_id":"missing"}"""),
        )
        assertNull(noKey["jwk"])
        assertTrue("the no-key answer is the empty object the engine reads as a bare proof header", noKey.isEmpty())
        peer.close()
    }

    // ── consent ──────────────────────────────────────────────────────────────────

    @Test
    fun aConsentDeclineIsTheResultFalseNeverAFlowError() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onConsent = { parent, params ->
                        assertEquals("p-2", parent)
                        assertEquals("scope-x", params.purpose)
                        assertEquals(listOf("given_name"), params.requestedClaims)
                        false
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p-2::consent::1",
            engineAsk(
                "p-2::consent::1", "consent",
                """{"flow_id":"p-2","purpose":"scope-x","requested_claims":["given_name"],"transaction_data":[]}""",
            ),
        )
        assertEquals(JsonPrimitive(false), result["consented"])
        assertTrue(
            "a decline is the verifier-facing access_denied, never a generic flow error",
            transport.sentMessages.none { String(it).contains("wmp.flow.error") },
        )
        peer.close()
    }

    @Test
    fun aConsentAskWithNoConsentUiBehindTheWalletDeclines() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(OpenID4xProfile(OpenID4xConfig()))
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p::consent::1",
            engineAsk("p::consent::1", "consent", """{"flow_id":"p","purpose":"s","requested_claims":[],"transaction_data":[]}"""),
        )
        assertEquals(JsonPrimitive(false), result["consented"])
        peer.close()
    }

    // ── tx_code ───────────────────────────────────────────────────────────────────

    @Test
    fun aTxCodeAskIsAnsweredWithTheCodeInTheObjectForm() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onTxCode = { parent ->
                        assertEquals("p-3", parent)
                        "1234"
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p-3::tx_code::1",
            engineAsk("p-3::tx_code::1", "tx_code", """{"flow_id":"p-3"}"""),
        )
        assertEquals(JsonPrimitive("1234"), result["tx_code"])
        peer.close()
    }

    // ── authorization ─────────────────────────────────────────────────────────────

    @Test
    fun anAuthorizationAskHandsTheUrlOverAndAnswersWithAnyResult() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onAuthorization = { parent, url ->
                        assertEquals("p-4", parent)
                        assertEquals("https://as.example/authorize?state=s", url)
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p-4::authorization::1",
            engineAsk("p-4::authorization::1", "authorization", """{"flow_id":"p-4","url":"https://as.example/authorize?state=s"}"""),
        )
        assertTrue("the engine ignores the result; the empty object is the canonical answer", result.isEmpty())
        peer.close()
    }

    // ── presentation ─────────────────────────────────────────────────────────────

    private fun vpParamsJson() =
        """{"flow_id":"p-5","audience":"verifier","nonce":"n1","selections":[{"credential_query_id":"q1","credential_id":"7","disclosed_claims":["given_name"]}],"response_uri":"https://v/r","verifier_jwk_thumbprint":"","verifier_session_id":"","transaction_data":[],"selection_handle":null}"""

    @Test
    fun aPresentationAskIsAnsweredWithTheVpToken() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onVpRequest = { parent, params ->
                        assertEquals("p-5", parent)
                        assertEquals("verifier", params.audience)
                        assertEquals("n1", params.nonce)
                        assertEquals(1, params.selections.size)
                        assertEquals("7", params.selections.single().credentialId)
                        EngineVpResult(vpToken = "tok.a~b")
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p-5::presentation::1",
            engineAsk("p-5::presentation::1", "presentation", vpParamsJson()),
        )
        assertEquals(JsonPrimitive("tok.a~b"), result["vp_token"])
        peer.close()
    }

    @Test
    fun aUserDeclineAtTheSignStageIsTheStructuredSignRefused() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onVpRequest = { _, _ -> throw SignRefusedException("no") },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p-5::presentation::1",
            engineAsk("p-5::presentation::1", "presentation", vpParamsJson()),
        )
        assertEquals(
            JsonPrimitive("SIGN_REFUSED"),
            result["refusal"]!!.jsonObject["code"],
        )
        assertTrue(
            "the refusal is the result, never a flow error the engine would read as a generic refusal",
            transport.sentMessages.none { String(it).contains("wmp.flow.error") },
        )
        peer.close()
    }

    @Test
    fun aTransactionDataRefusalNamesUnsupportedTransactionData() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onVpRequest = { _, _ ->
                        throw TransactionDataError(TransactionDataReason.UNSUPPORTED_FORMAT, "an mdoc cannot carry transaction_data")
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p-5::presentation::1",
            engineAsk("p-5::presentation::1", "presentation", vpParamsJson()),
        )
        assertEquals(
            JsonPrimitive("UNSUPPORTED_TRANSACTION_DATA"),
            result["refusal"]!!.jsonObject["code"],
        )
        peer.close()
    }

    // ── dpop_proof ───────────────────────────────────────────────────────────────

    @Test
    fun aDpopProofAskIsAnsweredWithTheProofAndUnavailableAsTheEmptyString() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onDpopProof = { parent, params ->
                        assertEquals("p-6", parent)
                        assertEquals("POST", params.htm)
                        assertEquals("https://as.example/token", params.htu)
                        if (params.keyId == "dpop-1") EngineDpopProofResult(proof = "proof.jwt") else EngineDpopProofResult(proof = null)
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (_, withProof) = transport.driveAsk(
            "p-6::dpop_proof::1",
            engineAsk(
                "p-6::dpop_proof::1", "dpop_proof",
                """{"flow_id":"p-6","key_id":"dpop-1","htm":"POST","htu":"https://as.example/token","access_token":"","nonce":""}""",
            ),
        )
        assertEquals(JsonPrimitive("proof.jwt"), withProof["proof"])

        val (_, unavailable) = transport.driveAsk(
            "p-6::dpop_proof::2",
            engineAsk(
                "p-6::dpop_proof::2", "dpop_proof",
                """{"flow_id":"p-6","key_id":null,"htm":"POST","htu":"https://as.example/token","access_token":"","nonce":""}""",
            ),
        )
        assertEquals(JsonPrimitive(""), unavailable["proof"])
        peer.close()
    }

    // ── attestation ──────────────────────────────────────────────────────────────

    @Test
    fun anAttestationAskIsAnsweredWithWiaAndPopAndNoneAsTheEmptyObject() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onAttestation = { parent, params ->
                        assertEquals("p-7", parent)
                        assertEquals("https://as.example/token", params.audience)
                        assertEquals("client-1", params.clientId)
                        EngineAttestationResult(wia = "wia.jwt", pop = "pop.jwt")
                    },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p-7::attestation::1",
            engineAsk(
                "p-7::attestation::1", "attestation",
                """{"flow_id":"p-7","audience":"https://as.example/token","client_id":"client-1","challenge":""}""",
            ),
        )
        assertEquals(JsonPrimitive("wia.jwt"), result["wia"])
        assertEquals(JsonPrimitive("pop.jwt"), result["pop"])
        peer.close()
    }

    // ── match: the dialect fork ───────────────────────────────────────────────────

    @Test
    fun aMatchAskWithoutParentFlowIdIsAnsweredWithFullSelections() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onMatchRequest = { parent, payload ->
                        assertEquals("p-8", parent)
                        assertTrue(payload!!.containsKey("dcql_query"))
                        MatchResult(
                            matches = listOf(
                                CredentialMatch(credentialId = "7", credentialQueryId = "q1", disclosedClaims = listOf("given_name")),
                            ),
                        )
                    },
                ),
            ),
        )
        connected(transport, peer)

        // engine-ports MatchParams: flow_id (the parent), dcql_query, scope, verifier, transaction_data.
        val (_, result) = transport.driveAsk(
            "p-8::match::1",
            engineAsk(
                "p-8::match::1", "match",
                """{"flow_id":"p-8","dcql_query":{"credentials":[]},"scope":"","verifier":{"name":"V","client_id":"v"},"transaction_data":[]}""",
            ),
        )
        val selection = result["selections"]!!.jsonArray.single().jsonObject
        assertEquals(JsonPrimitive("q1"), selection["credential_query_id"])
        assertEquals(JsonPrimitive("7"), selection["credential_id"])
        assertEquals(JsonPrimitive("given_name"), selection["disclosed_claims"]!!.jsonArray.single())
        assertTrue(
            "the Rust engine ends the flow itself on empty selections; no credentials_matched action exists in its dialect",
            transport.sentMessages.none { String(it).contains("wmp.flow.action") },
        )
        peer.close()
    }

    @Test
    fun anEmptySelectionsMatchAnswerCarriesTheEmptyArrayAndNoReason() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onMatchRequest = { _, _ -> MatchResult(matches = emptyList()) },
                ),
            ),
        )
        connected(transport, peer)

        val (_, result) = transport.driveAsk(
            "p::match::1",
            engineAsk("p::match::1", "match", """{"flow_id":"p","dcql_query":{"credentials":[]},"verifier":{"name":"V","client_id":"v"}}"""),
        )
        assertEquals(0, result["selections"]!!.jsonArray.size)
        assertNull(result["no_match_reason"])
        peer.close()
    }

    // ── the child-id parent fallback ──────────────────────────────────────────────

    @Test
    fun theParentComesFromTheChildIdPrefixWhenTheParamsCarryNoFlowId() = runBlocking {
        val transport = FakeTransport()
        val peer = WmpPeer(WmpSession(transport, config = WmpSessionConfig(requestTimeoutMs = 5_000)))
        peer.use(
            OpenID4xProfile(
                OpenID4xConfig(
                    onTxCode = { parent ->
                        assertEquals("flow-abc", parent)
                        "9999"
                    },
                ),
            ),
        )
        connected(transport, peer)

        // A tx_code ask whose params lost their flow_id member: the child id's own
        // `<parent>::<type>::<seq>` shape still names the parent.
        val (_, result) = transport.driveAsk(
            "flow-abc::tx_code::1",
            """{"jsonrpc":"2.0","id":"call-9","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"tx_code","flow_id":"flow-abc::tx_code::1"}}""",
        )
        assertEquals(JsonPrimitive("9999"), result["tx_code"])
        peer.close()
    }
}
