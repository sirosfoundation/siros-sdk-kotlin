package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeepLinkClassifierTest {

    private val redirectScheme = "siros-sample"

    @Test
    fun `credential offer scheme`() {
        val result = classifyDeepLink("openid-credential-offer://?credential_offer=%7B%7D", redirectScheme)
        assertTrue(result is DeepLinkType.CredentialOffer)
    }

    @Test
    fun `credential offer via query param`() {
        val result = classifyDeepLink(
            "https://wallet.example.com/offer?credential_offer_uri=https://issuer.example.com/offer/123",
            redirectScheme,
        )
        assertTrue(result is DeepLinkType.CredentialOffer)
    }

    @Test
    fun `presentation request via openid4vp scheme`() {
        val result = classifyDeepLink("openid4vp://?request_uri=https://verifier.example.com/request/abc", redirectScheme)
        assertTrue(result is DeepLinkType.PresentationRequest)
    }

    @Test
    fun `presentation request via haip scheme`() {
        val result = classifyDeepLink("haip://?request_uri=https://verifier.example.com/req", redirectScheme)
        assertTrue(result is DeepLinkType.PresentationRequest)
    }

    @Test
    fun `presentation request via request_uri query param`() {
        val result = classifyDeepLink(
            "https://wallet.example.com/present?request_uri=https://verifier.example.com/req",
            redirectScheme,
        )
        assertTrue(result is DeepLinkType.PresentationRequest)
    }

    @Test
    fun `presentation request via client_id only`() {
        // Unsigned-request-object cross-device link: the verifier passes the
        // request params directly rather than by reference (no request_uri).
        val result = classifyDeepLink(
            "https://wallet.example.com/present?client_id=https://verifier.example.com&response_uri=https://verifier.example.com/cb",
            redirectScheme,
        )
        assertTrue(result is DeepLinkType.PresentationRequest)
    }

    @Test
    fun `auth callback requires matching scheme and host`() {
        val result = classifyDeepLink("siros-sample://callback?code=abc&state=xyz", redirectScheme)
        assertTrue(result is DeepLinkType.AuthCallback)
        val callback = result as DeepLinkType.AuthCallback
        assertEquals("abc", callback.code)
        assertEquals("xyz", callback.state)
    }

    @Test
    fun `auth callback with wrong scheme is unknown`() {
        val result = classifyDeepLink("other-scheme://callback?code=abc&state=xyz", redirectScheme)
        assertTrue(result is DeepLinkType.Unknown)
    }

    @Test
    fun `auth callback missing code or state is unknown`() {
        val result = classifyDeepLink("siros-sample://callback?code=abc", redirectScheme)
        assertTrue(result is DeepLinkType.Unknown)
    }

    @Test
    fun `unknown link`() {
        val result = classifyDeepLink("https://example.com/", redirectScheme)
        assertTrue(result is DeepLinkType.Unknown)
    }

    @Test
    fun `empty string is unknown`() {
        val result = classifyDeepLink("", redirectScheme)
        assertTrue(result is DeepLinkType.Unknown)
    }

    @Test
    fun `malformed uri is unknown`() {
        val result = classifyDeepLink("not a uri at all with spaces", redirectScheme)
        assertTrue(result is DeepLinkType.Unknown)
    }
}
