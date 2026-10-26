// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.interfaces.ECPrivateKey
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.keystore.MdocDeviceResponseBuilder

/** The client against a local verifier (MockWebServer) that signs its request objects with an x5c certificate. */
class OpenId4VpClientTest {

    private val host = "community.example"
    private val clientId = "x509_san_dns:$host"
    private val server = MockWebServer()

    private val signing: HeldCertificate = HeldCertificate.Builder().ecdsa256().addSubjectAlternativeName(host).build()
    private val encryptionKey: ECKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION)
        .algorithm(com.nimbusds.jose.JWEAlgorithm.ECDH_ES).keyID("k1").generate()

    /** The verifier's request: its payload (with the posted wallet_nonce), how it is signed, and its answer at request_uri. */
    private var payload: (walletNonce: String?) -> JsonObject = { nonce -> requestPayload(nonce) }
    private var sign: (JsonObject) -> String = { signed(it) }
    private var requestAnswer: ((String) -> MockResponse)? = null
    private var responseAnswer: MockResponse = MockResponse().setBody("""{"redirect_uri":"https://$host/done"}""").setHeader("content-type", "application/json")
    private val posted = mutableListOf<RecordedRequest>()

    @Before
    fun start() {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                posted += request
                return when (request.path) {
                    "/request" -> {
                        val form = form(request.body.clone().readUtf8())
                        val jws = sign(payload(form["wallet_nonce"]))
                        requestAnswer?.invoke(jws) ?: MockResponse().setBody(jws).setHeader("content-type", "application/oauth-authz-req+jwt")
                    }
                    "/response" -> responseAnswer
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
        server.start()
    }

    @After
    fun stop() = server.shutdown()

    private val serverHost get() = server.url("/").host
    private val requestUri get() = server.url("/request").toString()
    private val responseUri get() = server.url("/response").toString()

    private fun qr(method: String? = "post", id: String = clientId) =
        "openid4vp://?client_id=${enc(id)}&request_uri=${enc(requestUri)}" + (method?.let { "&request_uri_method=$it" } ?: "")

    private fun client(policy: VerifierTrustPolicy = AllowedHostsTrustPolicy(setOf(serverHost))) =
        OpenId4VpClient(policy, allowHttp = true)

    private val metadata = WalletMetadata.circuitZk(
        listOf(CircuitZkCircuit("longfellow-nymauth", "nymauth-longfellow-mdoc-v1", setOf("eu.europa.ec.eudi.nym_auth.1"), aliases = setOf("urn:circuits:longfellow:nym_auth:v1"), proofSystem = "longfellow-libzk-v1")),
    )

    private fun requestPayload(walletNonce: String?, edit: MutableMap<String, kotlinx.serialization.json.JsonElement>.() -> Unit = {}): JsonObject {
        val base = buildJsonObject {
            put("aud", "https://self-issued.me/v2")
            put("iat", System.currentTimeMillis() / 1000)
            walletNonce?.let { put("wallet_nonce", it) }
            put("response_type", "vp_token")
            put("response_mode", "direct_post.jwt")
            put("response_uri", responseUri)
            put("client_id", clientId)
            put("nonce", "n-123")
            put("state", "s-456")
            put(
                "dcql_query",
                buildJsonObject {
                    put(
                        "credentials",
                        buildJsonArray {
                            add(buildJsonObject { put("id", "nym_attestation"); put("format", "zkp_req") })
                            add(buildJsonObject { put("id", "other"); put("format", "mso_mdoc") })
                        },
                    )
                },
            )
            put(
                "client_metadata",
                buildJsonObject {
                    put("client_name", "Community")
                    put("jwks", buildJsonObject { put("keys", JsonArray(listOf(Json.parseToJsonElement(encryptionKey.toPublicJWK().toJSONString())))) })
                },
            )
        }
        return JsonObject(base.toMutableMap().apply(edit))
    }

    private fun signed(p: JsonObject, cert: HeldCertificate = signing, alg: JWSAlgorithm = JWSAlgorithm.ES256, chain: HeldCertificate = cert): String {
        val header = JWSHeader.Builder(alg).type(JOSEObjectType("oauth-authz-req+jwt"))
            .x509CertChain(listOf(Base64.encode(chain.certificate.encoded))).build()
        val obj = JWSObject(header, Payload(p.toString()))
        obj.sign(if (alg == JWSAlgorithm.ES256) ECDSASigner(cert.keyPair.private as ECPrivateKey) else MACSigner(ByteArray(32) { 7 }))
        return obj.serialize()
    }

    private fun fetch(c: OpenId4VpClient = client(), uri: String = qr()) = runBlocking { c.fetchRequest(uri, metadata) }

    private fun untrusted(reason: UntrustedReason, c: OpenId4VpClient = client(), uri: String = qr()) {
        val e = assertThrows(OpenId4VpException.Untrusted::class.java) { fetch(c, uri) }
        assertEquals(reason, e.reason)
    }

    private fun unsupported(edit: MutableMap<String, kotlinx.serialization.json.JsonElement>.() -> Unit) {
        payload = { nonce -> requestPayload(nonce, edit) }
        assertThrows(OpenId4VpException.Unsupported::class.java) { fetch() }
    }

    // ---------------- the request URI ----------------

    @Test
    fun `parses a request by reference`() {
        val u = AuthorizationRequestUri.parse("openid4vp://?client_id=x509_san_dns%3Acommunity.example&request_uri=https%3A%2F%2Fa.b%2Fr%2F1&request_uri_method=post")
        assertEquals(clientId, u.clientId)
        assertEquals("https://a.b/r/1", u.requestUri)
        assertEquals(AuthorizationRequestUri.RequestUriMethod.POST, u.requestUriMethod)
        assertEquals(AuthorizationRequestUri.RequestUriMethod.GET, AuthorizationRequestUri.parse("OPENID4VP://?client_id=a&request_uri=b").requestUriMethod)
    }

    @Test
    fun `refuses what is not a request by reference`() {
        for (bad in listOf(
            "https://community.example/?client_id=a&request_uri=b",
            "openid4vp://",
            "openid4vp://?request_uri=b",
            "openid4vp://?client_id=a",
            "openid4vp://?client_id=a&request_uri=b&request_uri_method=put",
            "openid4vp://?client_id=a&client_id=c&request_uri=b",
            "openid4vp://?client_id=a&request=eyJ",
            "openid4vp://?client_id=a&request_uri=b&dcql_query=%7B%7D",
        )) {
            assertThrows(bad, OpenId4VpException.InvalidRequestUri::class.java) { AuthorizationRequestUri.parse(bad) }
        }
    }

    // ---------------- fetching and verifying ----------------

    @Test
    fun `posts wallet_metadata and a fresh wallet_nonce, and returns the checked request`() {
        val r = fetch()
        val form = form(posted.single().body.clone().readUtf8())
        assertEquals("POST", posted.single().method)
        assertEquals(metadata, Json.parseToJsonElement(form.getValue("wallet_metadata")))
        assertTrue(form.getValue("wallet_nonce").length >= 22)
        assertEquals(clientId, r.clientId)
        assertEquals(host, r.verifierHost)
        assertEquals("Community", r.clientName)
        assertEquals(responseUri, r.responseUri)
        assertEquals("n-123", r.nonce)
        assertEquals("s-456", r.state)
        assertEquals("ECDH-ES", r.responseEncryptionAlg)
        assertEquals("A128GCM", r.responseEncryptionEnc)
        assertEquals(listOf("nym_attestation"), r.circuitZkQueries.map { it["id"]!!.jsonPrimitive.content })
        assertEquals(2, r.credentialQueries.size)
        assertEquals(signing.certificate, r.certificateChain.single())
    }

    @Test
    fun `two fetches post two different wallet nonces`() {
        fetch()
        fetch()
        val nonces = posted.map { form(it.body.clone().readUtf8()).getValue("wallet_nonce") }
        assertEquals(2, nonces.toSet().size)
    }

    @Test
    fun `a GET request sends nothing and needs no wallet_nonce`() {
        val r = fetch(uri = qr(method = null))
        assertEquals("GET", posted.single().method)
        assertEquals(0L, posted.single().bodySize)
        assertEquals(clientId, r.clientId)
    }

    @Test
    fun `the session transcript is the redirect handover over the encryption key's thumbprint`() {
        val r = fetch()
        val thumbprint = encryptionKey.toPublicJWK().computeThumbprint().toString()
        assertEquals(thumbprint, r.responseEncryptionJwkThumbprint)
        assertArrayEquals(
            MdocDeviceResponseBuilder.buildCircuitZkRedirectSessionTranscript(clientId, "n-123", responseUri, thumbprint),
            r.sessionTranscript(),
        )
    }

    @Test
    fun `A256GCM when the verifier lists only it`() {
        payload = { nonce ->
            requestPayload(nonce) {
                val m = (this["client_metadata"] as JsonObject).toMutableMap()
                m["encrypted_response_enc_values_supported"] = JsonArray(listOf(JsonPrimitive("A256GCM")))
                this["client_metadata"] = JsonObject(m)
            }
        }
        assertEquals("A256GCM", fetch().responseEncryptionEnc)
    }

    @Test
    fun `refuses a request not signed by the verifier its client_id names`() {
        val other = HeldCertificate.Builder().ecdsa256().addSubjectAlternativeName("other.example").build()
        sign = { p -> signed(p, other) }
        // other.example's own certificate, for a request whose payload names community.example.
        untrusted(UntrustedReason.CLIENT_ID_MISMATCH, uri = qr(id = "x509_san_dns:other.example"))
        // community.example named, other.example's certificate.
        untrusted(UntrustedReason.SAN_MISMATCH)
        sign = { p -> signed(p).let { it.substring(0, it.lastIndexOf('.') + 1) + signed(requestPayload("x")).substringAfterLast('.') } }
        untrusted(UntrustedReason.SIGNATURE_INVALID)
        sign = { p -> signed(p, alg = JWSAlgorithm.HS256) }
        untrusted(UntrustedReason.UNSUPPORTED_ALGORITHM)
        sign = { p -> "eyJhbGciOiJub25lIn0." + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(p.toString().toByteArray()) + "." }
        untrusted(UntrustedReason.UNSIGNED)
        sign = { p ->
            val obj = JWSObject(JWSHeader.Builder(JWSAlgorithm.ES256).build(), Payload(p.toString()))
            obj.sign(ECDSASigner(signing.keyPair.private as ECPrivateKey))
            obj.serialize()
        }
        untrusted(UntrustedReason.NO_CERTIFICATE)
        val past = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(10)
        val expired = HeldCertificate.Builder().ecdsa256().addSubjectAlternativeName(host).validityInterval(past, past + 1000).build()
        sign = { p -> signed(p, expired) }
        untrusted(UntrustedReason.CERTIFICATE_INVALID)
        // A leaf without a P-256 key.
        val rsa = HeldCertificate.Builder().rsa2048().addSubjectAlternativeName(host).build()
        sign = { p -> signed(p, chain = rsa) }
        untrusted(UntrustedReason.CERTIFICATE_INVALID)
    }

    @Test
    fun `refuses a replayed or substituted request, an expired one, and a client_id scheme it cannot verify`() {
        payload = { _ -> requestPayload("someone-else's-nonce") }
        untrusted(UntrustedReason.WALLET_NONCE_MISMATCH)
        payload = { nonce -> requestPayload(nonce) { this["exp"] = JsonPrimitive(System.currentTimeMillis() / 1000 - 3600) } }
        untrusted(UntrustedReason.EXPIRED)
        payload = { nonce -> requestPayload(nonce) { this["exp"] = JsonPrimitive("soon") } }
        untrusted(UntrustedReason.MALFORMED)
        payload = { nonce -> requestPayload(nonce) { this["client_id"] = JsonPrimitive("redirect_uri:https://$host/cb") } }
        untrusted(UntrustedReason.UNSUPPORTED_CLIENT_ID_SCHEME, uri = qr(id = "redirect_uri:https://$host/cb"))
    }

    @Test
    fun `the trust policy decides after the signature, and sees where the response would go`() {
        var seen: VerifierIdentity? = null
        untrusted(UntrustedReason.NOT_TRUSTED, client(VerifierTrustPolicy { seen = it; false }))
        assertEquals(clientId, seen!!.clientId)
        assertEquals(requestUri, seen!!.requestUri)
        assertEquals(responseUri, seen!!.responseUri)
        assertEquals(signing.certificate, seen!!.certificateChain.single())
        untrusted(UntrustedReason.NOT_TRUSTED, client(AllowedHostsTrustPolicy(setOf("zkp-demo-verifier.fly.dev"))))
        // A response_uri elsewhere than the allowed hosts is not trusted either.
        payload = { nonce -> requestPayload(nonce) { this["response_uri"] = JsonPrimitive("https://elsewhere.example/r") } }
        untrusted(UntrustedReason.NOT_TRUSTED)
    }

    @Test
    fun `refuses a signed request that asks for what this client does not do`() {
        unsupported { this["response_mode"] = JsonPrimitive("direct_post") }
        unsupported { this["response_type"] = JsonPrimitive("code") }
        unsupported { remove("nonce") }
        unsupported { this["state"] = JsonPrimitive(5) }
        unsupported { this["response_uri"] = JsonPrimitive("ftp://$serverHost/r") }
        unsupported { this["transaction_data"] = JsonArray(listOf(JsonPrimitive("x"))) }
        unsupported { this["presentation_definition"] = JsonObject(emptyMap()) }
        unsupported { this["dcql_query"] = buildJsonObject { put("credentials", JsonArray(emptyList())) } }
        unsupported { this["client_metadata"] = buildJsonObject { put("client_name", "no keys") } }
        unsupported {
            val m = (this["client_metadata"] as JsonObject).toMutableMap()
            m["encrypted_response_enc_values_supported"] = JsonArray(listOf(JsonPrimitive("A192GCM")))
            this["client_metadata"] = JsonObject(m)
        }
        // A private key is not a key to encrypt to.
        unsupported {
            this["client_metadata"] = buildJsonObject {
                put("jwks", buildJsonObject { put("keys", JsonArray(listOf(Json.parseToJsonElement(encryptionKey.toJSONString())))) })
            }
        }
        // A point that is not on P-256.
        unsupported {
            val k = Json.parseToJsonElement(encryptionKey.toPublicJWK().toJSONString()).jsonObject.toMutableMap()
            k["y"] = k["x"]!!
            this["client_metadata"] = buildJsonObject { put("jwks", buildJsonObject { put("keys", JsonArray(listOf(JsonObject(k)))) }) }
        }
    }

    @Test
    fun `an error at request_uri is reported with the verifier's code, and redirects are not followed`() {
        requestAnswer = { MockResponse().setResponseCode(410).setBody("""{"statusCode":410,"data":{"error":"already_used"}}""") }
        val gone = assertThrows(OpenId4VpException.RequestUnavailable::class.java) { fetch() }
        assertEquals(410, gone.status)
        assertTrue(gone.expired)
        assertEquals("already_used", gone.code)
        requestAnswer = { MockResponse().setResponseCode(302).setHeader("Location", "https://elsewhere.example/") }
        val moved = assertThrows(OpenId4VpException.RequestUnavailable::class.java) { fetch() }
        assertEquals(302, moved.status)
        requestAnswer = { MockResponse().setResponseCode(400).setBody("""{"error":"<script>"}""") }
        assertNull(assertThrows(OpenId4VpException.RequestUnavailable::class.java) { fetch() }.code)
    }

    @Test
    fun `refuses http unless allowed`() {
        val e = assertThrows(OpenId4VpException.InvalidRequestUri::class.java) {
            runBlocking { OpenId4VpClient(AllowedHostsTrustPolicy(setOf(serverHost))).fetchRequest(qr(), metadata) }
        }
        assertTrue(e.message!!.contains("https"))
        assertTrue(posted.isEmpty())
    }

    // ---------------- responding ----------------

    private fun decryptResponse(): Pair<JWEObject, JsonObject> {
        val response = posted.last { it.path == "/response" }
        val jwe = JWEObject.parse(form(response.body.clone().readUtf8()).getValue("response"))
        jwe.decrypt(ECDHDecrypter(encryptionKey))
        return jwe to Json.parseToJsonElement(jwe.payload.toString()).jsonObject
    }

    @Test
    fun `posts the presentation encrypted to the verifier's key, with state, and returns the redirect`() {
        val c = client()
        val r = fetch(c)
        val vpToken = buildJsonObject { put("nym_attestation", buildJsonArray { add(JsonPrimitive("b64-presentation")) }) }
        val result = runBlocking { c.sendPresentation(r, vpToken) }
        assertEquals("https://$host/done", result.redirectUri)
        val (jwe, claims) = decryptResponse()
        assertEquals("ECDH-ES", jwe.header.algorithm.name)
        assertEquals("A128GCM", jwe.header.encryptionMethod.name)
        assertEquals("k1", jwe.header.keyID)
        assertEquals(vpToken, claims["vp_token"])
        assertEquals("s-456", claims["state"]!!.jsonPrimitive.content)
        assertEquals(clientId, claims["aud"]!!.jsonPrimitive.content)
        assertFalse(claims.containsKey("error"))
    }

    @Test
    fun `posts an error encrypted too, with no description`() {
        val c = client()
        val r = fetch(c)
        responseAnswer = MockResponse().setBody("{}")
        assertNull(runBlocking { c.sendError(r, OpenId4VpClient.ERROR_ACCESS_DENIED) }.redirectUri)
        val (_, claims) = decryptResponse()
        assertEquals("access_denied", claims["error"]!!.jsonPrimitive.content)
        assertEquals("s-456", claims["state"]!!.jsonPrimitive.content)
        assertFalse(claims.containsKey("vp_token"))
        assertFalse(claims.containsKey("error_description"))
        assertThrows(IllegalArgumentException::class.java) { runBlocking { c.sendError(r, "Access Denied!") } }
    }

    @Test
    fun `a refused response is reported with the verifier's code`() {
        val c = client()
        val r = fetch(c)
        responseAnswer = MockResponse().setResponseCode(400).setBody("""{"data":{"error":"state_mismatch"}}""")
        val e = assertThrows(OpenId4VpException.ResponseRejected::class.java) {
            runBlocking { c.sendPresentation(r, JsonObject(emptyMap())) }
        }
        assertEquals(400, e.status)
        assertEquals("state_mismatch", e.code)
    }

    // ---------------- wallet metadata ----------------

    @Test
    fun `wallet metadata offers the circuits' ids and proof systems and the response encryption`() {
        val zk = metadata["vp_formats_supported"]!!.jsonObject["zkp_req"]!!.jsonObject
        assertEquals(listOf("longfellow-libzk-v1"), zk["proof_system_values"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(
            listOf("nymauth-longfellow-mdoc-v1", "urn:circuits:longfellow:nym_auth:v1"),
            zk["system_id_values"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
        assertEquals(listOf("ECDH-ES"), metadata["authorization_encryption_alg_values_supported"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertFalse(WalletMetadata.circuitZk(emptyList())["vp_formats_supported"]!!.jsonObject.containsKey("zkp_req"))
    }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    private fun form(body: String): Map<String, String> = body.split('&').filter { it.isNotEmpty() }.associate {
        URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('=', ""), "UTF-8")
    }
}
