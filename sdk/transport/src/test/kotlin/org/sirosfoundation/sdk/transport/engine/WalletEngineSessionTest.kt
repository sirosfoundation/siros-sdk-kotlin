package org.sirosfoundation.sdk.transport.engine

import app.cash.turbine.test
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class WalletEngineSessionTest {

    private val client = mockk<OkHttpClient>()
    private val webSocket = mockk<WebSocket>(relaxed = true)
    private val response = mockk<Response>(relaxed = true)

    private lateinit var request: Request
    private lateinit var listener: WebSocketListener

    @Before
    fun setUp() {
        val requestSlot = slot<Request>()
        val listenerSlot = slot<WebSocketListener>()
        every { client.newWebSocket(capture(requestSlot), capture(listenerSlot)) } answers {
            request = requestSlot.captured
            listener = listenerSlot.captured
            webSocket
        }
    }

    @Test
    fun connect_builds_websocket_request_and_sends_handshake_on_open() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )

        session.connect("app-token")
        listener.onOpen(webSocket, response)

        assertEquals(WalletEngineSession.State.CONNECTING, session.state.value)
        assertEquals("/api/v2/wallet", request.url.encodedPath)
        assertEquals("tenant-42", request.url.queryParameter("tenant_id"))
        assertEquals("wmp.v1", request.header("Sec-WebSocket-Protocol"))
        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"handshake\"") &&
                    text.contains("\"app_token\":\"app-token\"")
            })
        }
    }

    @Test
    fun handshake_complete_message_transitions_connected_and_emits_raw_message() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.messages().test {
            listener.onMessage(
                webSocket,
                """{"type":"handshake_complete","session_id":"session-123"}""",
            )

            val message = awaitItem()
            assertEquals(MessageTypes.HANDSHAKE_COMPLETE, message.type)
            assertEquals(WalletEngineSession.State.CONNECTED, session.state.value)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_progress_message_emits_to_progress_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowProgress().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_progress","flow_id":"flow-1","step":"issuing","payload":{"percent":50}}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertEquals("issuing", message.step)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_complete_message_emits_to_completion_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowComplete().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_complete","flow_id":"flow-1","redirect_uri":"https://wallet.example.com/callback"}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertEquals("https://wallet.example.com/callback", message.redirectUri)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_complete_parses_credential_notification_id() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowComplete().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_complete","flow_id":"flow-1","credentials":""" +
                    """[{"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1",""" +
                    """"notification_id":"notif-xyz"}]}""",
            )

            val message = awaitItem()
            assertEquals("notif-xyz", message.credentials?.first()?.notificationId)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_error_message_emits_to_error_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.flowErrors().test {
            listener.onMessage(
                webSocket,
                """{"type":"flow_error","flow_id":"flow-1","step":"authorize","error":{"code":"invalid_request","message":"missing parameter"}}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertEquals("authorize", message.step)
            assertEquals("invalid_request", message.error.code)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun sign_request_message_emits_to_sign_requests_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.signRequests().test {
            listener.onMessage(
                webSocket,
                """{"type":"sign_request","flow_id":"flow-1","action":"proof","params":{"audience":"aud","nonce":"nonce","proof_type":"jwt"}}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertEquals("proof", message.action)
            assertEquals("aud", message.params.audience)
            assertEquals("jwt", message.params.proofType)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun match_request_message_emits_to_match_requests_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.matchRequests().test {
            listener.onMessage(
                webSocket,
                """{"type":"match_request","flow_id":"flow-1","dcql_query":{"credentials":[{"id":"q-1"}]}}""",
            )

            val message = awaitItem()
            assertEquals("flow-1", message.flowId)
            assertTrue(message.dcqlQuery.toString().contains("q-1"))
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun push_message_emits_to_push_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.pushMessages().test {
            listener.onMessage(
                webSocket,
                """{"type":"push","push_type":"issuance_complete","credentials":[{"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1"}]}""",
            )

            val message = awaitItem()
            assertEquals("issuance_complete", message.pushType)
            assertEquals("jwt-token", message.credentials?.single()?.credential)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun error_message_transitions_session_to_failed() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.messages().test {
            listener.onMessage(
                webSocket,
                """{"type":"error","code":"bad_request","message":"invalid flow"}""",
            )

            val message = awaitItem()
            assertEquals(MessageTypes.ERROR, message.type)
            assertEquals(WalletEngineSession.State.FAILED, session.state.value)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun send_trust_result_serializes_flow_action_payload() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendTrustResult("flow-77", true, "verified")

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"flow_action\"") &&
                    text.contains("\"flow_id\":\"flow-77\"") &&
                    text.contains("\"action\":\"trust_result\"") &&
                    text.contains("\"trusted\":true") &&
                    text.contains("\"reason\":\"verified\"")
            })
        }
    }

    @Test
    fun send_credential_notification_serializes_message() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendCredentialNotification(
            flowId = "flow-77",
            notificationId = "notif-abc",
            event = CredentialNotificationEvent.ACCEPTED,
            eventDescription = "stored",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"credential_notification\"") &&
                    text.contains("\"flow_id\":\"flow-77\"") &&
                    text.contains("\"notification_id\":\"notif-abc\"") &&
                    text.contains("\"event\":\"credential_accepted\"") &&
                    text.contains("\"event_description\":\"stored\"")
            })
        }
    }

    @Test
    fun send_credential_notification_is_no_op_when_not_connected() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        // Never connected: webSocket is null, so the send must be dropped.
        assertTrue(!session.isConnected)

        session.sendCredentialNotification(
            flowId = "flow-77",
            notificationId = "notif-abc",
            event = CredentialNotificationEvent.ACCEPTED,
        )

        verify(exactly = 0) { webSocket.send(any<String>()) }
    }

    @Test
    fun notification_ack_message_emits_to_notification_acks_flow() = runTest {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.notificationAcks().test {
            listener.onMessage(
                webSocket,
                """{"type":"notification_ack","flow_id":"flow-77","notification_id":"notif-abc","status":"forwarded"}""",
            )

            val ack = awaitItem()
            assertEquals("flow-77", ack.flowId)
            assertEquals("notif-abc", ack.notificationId)
            assertEquals("forwarded", ack.status)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun start_issuance_serializes_flow_start_message() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.startIssuance(
            offer = "offer-json",
            credentialOfferUri = "https://issuer.example.com/offer",
            redirectUri = "app://callback",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"flow_start\"") &&
                    text.contains("\"protocol\":\"oid4vci\"") &&
                    text.contains("\"offer\":\"offer-json\"") &&
                    text.contains("\"credential_offer_uri\":\"https://issuer.example.com/offer\"") &&
                    text.contains("\"redirect_uri\":\"app://callback\"")
            })
        }
    }

    @Test
    fun start_presentation_serializes_flow_start_message() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.startPresentation(
            requestUri = "https://verifier.example.com/request",
            requestUriRef = "urn:request:1",
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"flow_start\"") &&
                    text.contains("\"protocol\":\"oid4vp\"") &&
                    text.contains("\"request_uri\":\"https://verifier.example.com/request\"") &&
                    text.contains("\"request_uri_ref\":\"urn:request:1\"")
            })
        }
    }

    @Test
    fun send_sign_response_serializes_all_proof_fields() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendSignResponse(
            flowId = "flow-77",
            proofJwt = "proof-jwt",
            vpToken = "vp-token",
            proofs = listOf(ProofObject(proofType = "jwt", jwt = "nested-proof")),
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"sign_response\"") &&
                    text.contains("\"flow_id\":\"flow-77\"") &&
                    text.contains("\"proof_jwt\":\"proof-jwt\"") &&
                    text.contains("\"vp_token\":\"vp-token\"") &&
                    text.contains("\"proof_type\":\"jwt\"") &&
                    text.contains("\"jwt\":\"nested-proof\"")
            })
        }
    }

    @Test
    fun send_match_response_serializes_selected_credentials() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.sendMatchResponse(
            flowId = "flow-88",
            matches = listOf(
                CredentialMatch(
                    credentialQueryId = "query-1",
                    credentialId = "cred-1",
                    format = "dc+sd-jwt",
                    vct = "urn:eu:pid:1",
                    availableClaims = listOf("given_name", "family_name"),
                )
            ),
        )

        verify(exactly = 1) {
            webSocket.send(match<String> { text ->
                text.contains("\"type\":\"match_response\"") &&
                    text.contains("\"flow_id\":\"flow-88\"") &&
                    text.contains("\"credential_query_id\":\"query-1\"") &&
                    text.contains("\"credential_id\":\"cred-1\"") &&
                    text.contains("\"available_claims\":[\"given_name\",\"family_name\"]")
            })
        }
    }

    @Test
    fun disconnect_closes_socket_and_resets_state() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )
        session.connect("app-token")

        session.disconnect()

        verify(exactly = 1) { webSocket.close(1000, "client disconnect") }
        assertEquals(WalletEngineSession.State.DISCONNECTED, session.state.value)
    }

    @Test
    fun outbound_messages_require_active_connection() {
        val session = WalletEngineSession(
            baseUrl = "https://wallet.example.com",
            tenantId = "tenant-42",
            client = client,
        )

        assertThrows(IllegalStateException::class.java) {
            session.startIssuance(offer = "offer-json")
        }
        assertThrows(IllegalStateException::class.java) {
            session.sendSignResponse(flowId = "flow-1", proofJwt = "jwt")
        }
        assertThrows(IllegalStateException::class.java) {
            session.sendMatchResponse(
                flowId = "flow-1",
                matches = listOf(CredentialMatch(credentialId = "cred-1", format = "dc+sd-jwt")),
            )
        }
    }
}