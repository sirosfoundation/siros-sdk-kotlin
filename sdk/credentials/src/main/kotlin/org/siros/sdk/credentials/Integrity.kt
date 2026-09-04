package org.siros.sdk.credentials

import timber.log.Timber
import java.security.MessageDigest
import java.util.Base64

/**
 * Subresource-integrity digests, as SD-JWT VC Type Metadata uses them.
 *
 * The `vct#integrity`, `schema_uri#integrity`, `extends#integrity` and
 * `uri#integrity` members all carry a W3C SRI string: an algorithm name, a
 * dash, and the base64 digest of the resource's bytes — `sha256-47DEQpj8...`.
 *
 * These exist so the *issuer* can pin what a credential type means. Without
 * checking them, whoever serves the type metadata decides how a credential is
 * displayed and which claims it is understood to carry, independently of the
 * issuer who vouched for it.
 */
object Integrity {

    /** Algorithms SRI defines. Nothing weaker is accepted. */
    private val algorithms = mapOf(
        "sha256" to "SHA-256",
        "sha384" to "SHA-384",
        "sha512" to "SHA-512",
    )

    /**
     * Whether [content] matches [expected].
     *
     * An unparseable or unknown-algorithm value returns false rather than
     * true: a digest that cannot be checked is not a digest that passed, and
     * the caller decides what "cannot check" should mean.
     */
    fun matches(content: ByteArray, expected: String): Boolean {
        val trimmed = expected.trim()
        // SRI permits several space-separated digests, strongest first. Any one
        // matching is a match.
        if (trimmed.contains(' ')) {
            return trimmed.split(' ').filter { it.isNotBlank() }.any { matches(content, it) }
        }
        val dash = trimmed.indexOf('-')
        if (dash <= 0) {
            Timber.w("Integrity value is not <algorithm>-<digest>")
            return false
        }
        val algorithm = algorithms[trimmed.substring(0, dash).lowercase()]
        if (algorithm == null) {
            Timber.w("Unsupported integrity algorithm in '${trimmed.substring(0, dash)}'")
            return false
        }
        val expectedDigest = try {
            // SRI is standard base64, but tolerate the URL-safe alphabet:
            // rejecting a correct digest over its encoding would be a worse
            // failure than accepting either spelling of the same bytes.
            decodeBase64(trimmed.substring(dash + 1))
        } catch (e: IllegalArgumentException) {
            Timber.w(e, "Integrity digest is not base64")
            return false
        }
        val actual = MessageDigest.getInstance(algorithm).digest(content)
        return MessageDigest.isEqual(actual, expectedDigest)
    }

    private fun decodeBase64(value: String): ByteArray = try {
        Base64.getDecoder().decode(value)
    } catch (e: IllegalArgumentException) {
        Base64.getUrlDecoder().decode(value.replace('+', '-').replace('/', '_'))
    }
}
