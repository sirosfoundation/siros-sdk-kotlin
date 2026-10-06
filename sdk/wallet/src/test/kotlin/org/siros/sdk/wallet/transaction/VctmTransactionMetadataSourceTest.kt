package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.VctmFetcher
import org.siros.sdk.wallet.transaction.TransactionTestFixtures.credential
import java.security.MessageDigest
import java.util.Base64

class VctmTransactionMetadataSourceTest {
    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer().apply { start() } }
    @After fun tearDown() { server.shutdown() }

    private val vctmJson = """{"vct":"https://pay.example.com/card","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{}}"""

    private fun sri(text: String) =
        "sha256-" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(text.toByteArray()))

    private fun source(
        vctmBody: String? = vctmJson,
        https: Boolean = false,
    ) = VctmTransactionMetadataSource(
        vctmFetcher = VctmFetcher(httpGet = { vctmBody }),
        registryUrl = "https://wallet.example.com/registry",
        httpClient = OkHttpClient(),
        allowInsecureHttp = !https,
    )

    private fun cred(extra: String = "") =
        credential(claims = """{"vct":"https://pay.example.com/card"$extra}""")

    // ── type metadata ──────────────────────────────────────────────

    @Test
    fun `resolves the type metadata of the credential's vct`() = runBlocking {
        val meta = source().typeMetadata(cred())

        assertEquals("urn:eu:europa:ec:eudi:sua:sca", meta!!["category"]!!.toString().trim('"'))
    }

    @Test
    fun `no metadata, wrong vct, or a credential without vct yields nothing`() = runBlocking {
        assertNull(source(vctmBody = null).typeMetadata(cred()))
        assertNull(source(vctmBody = """{"vct":"https://other.example/type"}""").typeMetadata(cred()))
        assertNull(source().typeMetadata(credential(claims = """{"iss":"x"}""")))
        assertNull(source().typeMetadata(credential(claims = "not json")))
    }

    @Test
    fun `a vct#integrity pin is enforced against what was resolved`() = runBlocking {
        assertNotNull(source().typeMetadata(cred(""","vct#integrity":"${sri(vctmJson)}"""")))
        assertNull(source().typeMetadata(cred(""","vct#integrity":"${sri("something else")}"""")))
        assertNull(source().typeMetadata(cred(""","vct#integrity":"garbage"""")))
    }

    // ── referenced documents ───────────────────────────────────────

    @Test
    fun `fetches a document without sending the wallet's credentials`() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"type":"object"}"""))

        val body = source().document(server.url("/schema.json").toString())

        assertEquals("""{"type":"object"}""", body)
        val req = server.takeRequest()
        assertNull(req.getHeader("Authorization"))
        assertNull(req.getHeader("X-Tenant-ID"))
    }

    @Test
    fun `an error status, an oversized body or a non-https URL gives nothing`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(404).setBody("nope"))
        assertNull(source().document(server.url("/a").toString()))

        server.enqueue(MockResponse().setBody("x".repeat((VctmTransactionMetadataSource.MAX_DOCUMENT_BYTES + 1).toInt())))
        assertNull(source().document(server.url("/b").toString()))

        server.enqueue(MockResponse().setBody("{}"))
        assertNull("http is refused unless a test allows it", source(https = true).document(server.url("/c").toString()))
        assertEquals("the refused URL was never requested", 2, server.requestCount)

        assertNull(source().document("not a url"))
    }

    @Test
    fun `a document exactly at the size limit is accepted`() = runBlocking {
        val body = "x".repeat(VctmTransactionMetadataSource.MAX_DOCUMENT_BYTES.toInt())
        server.enqueue(MockResponse().setBody(body))

        assertEquals(body.length, source().document(server.url("/edge").toString())!!.length)
    }

    @Test
    fun `an unreachable host gives nothing`() = runBlocking {
        val url = server.url("/gone").toString()
        server.shutdown()

        assertNull(source().document(url))
    }
}
