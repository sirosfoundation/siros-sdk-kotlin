package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.URLEncoder

class IssuanceStartTest {

    private val offerJson = """{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}"""
    private val encoded = URLEncoder.encode(offerJson, "UTF-8")

    @Test
    fun `inline offer is unpacked whatever the scheme`() {
        for (scheme in listOf("openid-credential-offer", "haip-vci", "OPENID-CREDENTIAL-OFFER", "https")) {
            assertEquals(scheme, IssuanceStart.Offer(offerJson), resolveIssuanceStart("$scheme://?credential_offer=$encoded"))
        }
    }

    @Test
    fun `offer by reference is fetched whatever the scheme`() {
        for (scheme in listOf("openid-credential-offer", "haip-vci", "https")) {
            assertEquals(
                scheme,
                IssuanceStart.CredentialOfferUri("https://issuer.example/offers/1"),
                resolveIssuanceStart("$scheme://issuer.example/wallet?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F1"),
            )
        }
    }

    @Test
    fun `a plain https uri is the offer uri itself`() {
        assertEquals(IssuanceStart.CredentialOfferUri("https://issuer.example/offers/1"), resolveIssuanceStart("https://issuer.example/offers/1"))
    }

    @Test
    fun `anything else is left for the engine`() {
        assertEquals(IssuanceStart.Offer(offerJson), resolveIssuanceStart(offerJson))
        assertEquals(IssuanceStart.Offer("openid-credential-offer://"), resolveIssuanceStart("openid-credential-offer://"))
    }

    @Test
    fun `credential_offer wins over credential_offer_uri`() {
        assertEquals(IssuanceStart.Offer("{}"), resolveIssuanceStart("haip-vci://?credential_offer_uri=https%3A%2F%2Fx&credential_offer=%7B%7D"))
    }
}
