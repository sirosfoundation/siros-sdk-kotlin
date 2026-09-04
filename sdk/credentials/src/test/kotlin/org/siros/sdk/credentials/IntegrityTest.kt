package org.siros.sdk.credentials

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * Subresource-integrity digests as SD-JWT VC Type Metadata uses them.
 *
 * The failure that matters here is a false pass: a digest that cannot be
 * parsed, or is computed with an algorithm we do not implement, must not be
 * reported as matching.
 */
class IntegrityTest {

    private val content = """{"vct":"urn:eudi:pid:1"}""".toByteArray()

    private fun sri(algorithm: String, jcaName: String): String {
        val digest = MessageDigest.getInstance(jcaName).digest(content)
        return "$algorithm-" + Base64.getEncoder().encodeToString(digest)
    }

    @Test
    fun matchesACorrectSha256Digest() {
        assertTrue(Integrity.matches(content, sri("sha256", "SHA-256")))
    }

    @Test
    fun matchesSha384AndSha512() {
        assertTrue(Integrity.matches(content, sri("sha384", "SHA-384")))
        assertTrue(Integrity.matches(content, sri("sha512", "SHA-512")))
    }

    @Test
    fun rejectsADigestOfDifferentContent() {
        assertFalse(Integrity.matches("something else".toByteArray(), sri("sha256", "SHA-256")))
    }

    @Test
    fun rejectsAnAlgorithmItCannotCompute() {
        // Not "true because we could not check": an unknown algorithm is a
        // digest that did not pass.
        assertFalse(Integrity.matches(content, "md5-" + Base64.getEncoder().encodeToString(content)))
    }

    @Test
    fun rejectsMalformedValues() {
        assertFalse(Integrity.matches(content, "no-dash-separator-here".let { "" }))
        assertFalse(Integrity.matches(content, "sha256"))
        assertFalse(Integrity.matches(content, "sha256-not!base64"))
        assertFalse(Integrity.matches(content, "-" + Base64.getEncoder().encodeToString(content)))
    }

    @Test
    fun acceptsAnyOfSeveralSpaceSeparatedDigests() {
        // SRI permits a list, strongest first; any one matching is a match.
        val value = "sha512-AAAA " + sri("sha256", "SHA-256")
        assertTrue(Integrity.matches(content, value))
    }

    @Test
    fun toleratesTheUrlSafeAlphabet() {
        // Standard base64 is what the spec says, but a digest that is correct
        // and merely spelled with -_ should not be reported as a mismatch.
        val digest = MessageDigest.getInstance("SHA-256").digest(content)
        val urlSafe = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        assertTrue(Integrity.matches(content, "sha256-$urlSafe"))
    }
}
