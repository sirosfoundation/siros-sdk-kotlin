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
    fun `presentation request via mdoc-openid4vp scheme`() {
        // ISO 18013-7 Annex B's mdoc-specific scheme - same wire shape as
        // plain openid4vp.
        val result = classifyDeepLink("mdoc-openid4vp://?request_uri=https://verifier.example.com/request/abc", redirectScheme)
        assertTrue(result is DeepLinkType.PresentationRequest)
    }

    @Test
    fun `presentation request via haip scheme`() {
        val result = classifyDeepLink("haip://?request_uri=https://verifier.example.com/req", redirectScheme)
        assertTrue(result is DeepLinkType.PresentationRequest)
    }

    @Test
    fun `presentation request via haip-vp scheme`() {
        // HAIP 1.0 final replaced the earlier drafts' single "haip" scheme
        // with separate haip-vp (presentation) / haip-vci (issuance) schemes.
        val result = classifyDeepLink("haip-vp://?request_uri=https://verifier.example.com/req", redirectScheme)
        assertTrue(result is DeepLinkType.PresentationRequest)
    }

    @Test
    fun `credential offer via haip-vci scheme`() {
        val result = classifyDeepLink("haip-vci://?credential_offer=%7B%7D", redirectScheme)
        assertTrue(result is DeepLinkType.CredentialOffer)
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

    /**
     * Presentation-during-issuance: an issuer that will not issue until the
     * holder presents something (a company credential authorised by a PID)
     * sends the OpenID4VP request to the redirect_uri the wallet gave it,
     * which is the same callback the authorization code arrives on.
     *
     * The regression: this was classified Unknown and dropped, and the
     * issuance sat at the authorization step until it timed out. Seen on a
     * device as "Ignoring non-wallet URI: siros-sample://callback".
     */
    @Test
    fun `presentation request delivered to the oauth callback is recognised`() {
        val result = classifyDeepLink(
            "siros-sample://callback?client_id=x509_san_dns%3Aissuer.example" +
                "&request_uri=https%3A%2F%2Fissuer.example%2Fverification%2Frequest-object%3Fid%3Dabc",
            redirectScheme,
        )
        assertTrue(result is DeepLinkType.PresentationRequest)
        val uri = (result as DeepLinkType.PresentationRequest).uri
        // Normalised to the wallet-scheme form the presentation flow parses.
        assertTrue(uri.startsWith("openid4vp://?"))
        assertTrue(uri.contains("request_uri="))
        assertTrue(uri.contains("client_id="))
    }

    @Test
    fun `an authorization code on the callback is still an auth callback`() {
        // The new branch must not shadow the ordinary case, including when a
        // client_id rides along with the code.
        val result = classifyDeepLink(
            "siros-sample://callback?code=abc&state=xyz&client_id=e2e-test-client",
            redirectScheme,
        )
        assertTrue(result is DeepLinkType.AuthCallback)
        assertEquals("abc", (result as DeepLinkType.AuthCallback).code)
    }

    @Test
    fun `a bare callback with neither code nor request is still unknown`() {
        val result = classifyDeepLink("siros-sample://callback", redirectScheme)
        assertEquals(DeepLinkType.Unknown, result)
    }

    /**
     * A same-device offer chooser hands an offer to an installed wallet by
     * its registered redirect URI, so the offer arrives on the same callback
     * as an authorization code would. It was classified Unknown, and an app
     * that treats anything it cannot place as a presentation sent it down the
     * wrong flow entirely.
     */
    @Test
    fun `credential offer on the wallet callback is an offer`() {
        val result = classifyDeepLink(
            "$redirectScheme://callback?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%7D",
            redirectScheme,
        )
        assertTrue(result is DeepLinkType.CredentialOffer)
    }

    @Test
    fun `credential offer by reference on the wallet callback is an offer`() {
        val result = classifyDeepLink(
            "$redirectScheme://callback?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1",
            redirectScheme,
        )
        assertTrue(result is DeepLinkType.CredentialOffer)
    }
}
