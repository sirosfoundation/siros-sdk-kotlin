package org.siros.sdk.credentials.interop

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class CredentialStatusTest {

    private val now = Instant.parse("2026-06-01T12:00:00Z").toEpochMilli()

    private fun claims(json: String) = Json.parseToJsonElement(json) as JsonObject

    // ── the validity window ─────────────────────────────────────────

    @Test
    fun `VCDM properties are preferred over the JWT claims`() {
        // A VCDM credential's own validFrom/validUntil are authoritative; the
        // enveloping JWT's exp may be shorter and is not the credential's.
        val window = CredentialValidity.extract(
            claims(
                """{"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z",
                    "nbf":1,"exp":2}""",
            ),
        )
        assertEquals(Instant.parse("2026-01-01T00:00:00Z"), window.validFrom)
        assertEquals(Instant.parse("2027-01-01T00:00:00Z"), window.validUntil)
    }

    @Test
    fun `nbf and exp stand in when the VCDM properties are absent`() {
        val window = CredentialValidity.extract("""{"nbf":1700000000,"exp":1800000000,"iat":1700000000}""".let(::claims))
        assertEquals(Instant.ofEpochSecond(1700000000), window.validFrom)
        assertEquals(Instant.ofEpochSecond(1800000000), window.validUntil)
        assertEquals(Instant.ofEpochSecond(1700000000), window.signed)
    }

    @Test
    fun `a timestamp with an offset rather than Z still parses`() {
        val window = CredentialValidity.extract(claims("""{"validUntil":"2027-01-01T00:00:00+02:00"}"""))
        assertEquals(Instant.parse("2026-12-31T22:00:00Z"), window.validUntil)
    }

    @Test
    fun `an unparseable timestamp is ignored rather than failing the credential`() {
        val window = CredentialValidity.extract(claims("""{"validUntil":"whenever"}"""))
        assertNull(window.validUntil)
    }

    @Test
    fun `no bounds means valid indefinitely`() {
        assertEquals(
            CredentialStatus.VALID,
            CredentialValidity.check(CredentialValidity.extract(claims("{}")), nowMillis = now),
        )
    }

    @Test
    fun `a credential past validUntil is expired`() {
        val window = CredentialValidity.extract(claims("""{"validUntil":"2026-05-01T00:00:00Z"}"""))
        assertEquals(CredentialStatus.EXPIRED, CredentialValidity.check(window, nowMillis = now))
    }

    @Test
    fun `a credential before validFrom is not yet valid`() {
        val window = CredentialValidity.extract(claims("""{"validFrom":"2026-07-01T00:00:00Z"}"""))
        assertEquals(CredentialStatus.NOT_YET_VALID, CredentialValidity.check(window, nowMillis = now))
    }

    @Test
    fun `clock tolerance covers skew at both edges of the window`() {
        val justExpired = CredentialValidity.extract(claims("""{"validUntil":"2026-06-01T11:59:30Z"}"""))
        assertEquals(CredentialStatus.EXPIRED, CredentialValidity.check(justExpired, 0, now))
        assertEquals(CredentialStatus.VALID, CredentialValidity.check(justExpired, 60, now))

        val justStarted = CredentialValidity.extract(claims("""{"validFrom":"2026-06-01T12:00:30Z"}"""))
        assertEquals(CredentialStatus.NOT_YET_VALID, CredentialValidity.check(justStarted, 0, now))
        assertEquals(CredentialStatus.VALID, CredentialValidity.check(justStarted, 60, now))
    }

    @Test
    fun `expiry is reported ahead of not-yet-valid when a window is inverted`() {
        // A malformed window should still name one reason, deterministically.
        val window = ValidityWindow(
            validFrom = Instant.parse("2027-01-01T00:00:00Z"),
            validUntil = Instant.parse("2026-01-01T00:00:00Z"),
        )
        assertEquals(CredentialStatus.EXPIRED, CredentialValidity.check(window, nowMillis = now))
    }

    // ── the whole algorithm ─────────────────────────────────────────

    @Test
    fun `the validity window short-circuits the status list`() = runBlocking {
        // An expired credential is expired whether or not the issuer's status
        // endpoint answers, and saying so needs no network.
        val evaluator = CredentialStatusEvaluator(
            statusListClient = TokenStatusListClient(
                httpGet = { _, _ -> throw AssertionError("the status list must not be fetched") },
            ),
            nowMillis = { now },
        )
        val status = evaluator.evaluate(
            claims("""{"validUntil":"2026-01-01T00:00:00Z","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}"""),
        )
        assertEquals(CredentialStatus.EXPIRED, status)
    }

    @Test
    fun `a credential with no status reference is valid`() = runBlocking {
        val evaluator = CredentialStatusEvaluator(nowMillis = { now })
        assertEquals(CredentialStatus.VALID, evaluator.evaluate(claims("""{"iss":"https://issuer.example"}""")))
    }

    @Test
    fun `an unreachable status list leaves the credential usable`() = runBlocking {
        // Hiding a credential because the issuer's status endpoint is down
        // would make the wallet unusable offline. This is deliberate.
        val evaluator = CredentialStatusEvaluator(
            statusListClient = TokenStatusListClient(httpGet = { _, _ -> null }),
            nowMillis = { now },
        )
        val status = evaluator.evaluate(
            claims("""{"iss":"https://issuer.example","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}"""),
        )
        assertEquals(CredentialStatus.VALID, status)
    }

    @Test
    fun `a status list that is not a typed Status List Token is not trusted`() = runBlocking {
        val evaluator = CredentialStatusEvaluator(
            statusListClient = TokenStatusListClient(httpGet = { _, _ -> "not-a-jws" }),
            nowMillis = { now },
        )
        assertEquals(
            CredentialStatus.VALID,
            evaluator.evaluate(
                claims("""{"iss":"https://issuer.example","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}"""),
            ),
        )
    }

    @Test
    fun `only VALID is usable`() {
        assertTrue(CredentialStatus.VALID.isUsable)
        assertFalse(CredentialStatus.EXPIRED.isUsable)
        assertFalse(CredentialStatus.NOT_YET_VALID.isUsable)
        assertFalse(CredentialStatus.REVOKED.isUsable)
        assertFalse(CredentialStatus.SUSPENDED.isUsable)
    }
}
