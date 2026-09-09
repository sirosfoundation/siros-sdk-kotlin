// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * How a credential-offer URI handed to [SirosWallet.startIssuance] reaches
 * the engine. Pure, so the mapping is testable without a connection.
 *
 * The engine's own `startIssuance(offer)` strips the `credential_offer` query
 * parameter for exactly one scheme, lowercase `openid-credential-offer`.
 * Every other carrier of an offer - `haip-vci://`, an issuer's `https://`
 * wallet-redirect page, an upper-cased scheme from a QR code - has to be
 * unpacked here, or the whole URI is sent as if it were the offer JSON and
 * issuance fails on the engine side. So the query parameters decide first,
 * regardless of scheme; what remains is either a fetchable `https://` offer
 * URI or something the engine is trusted to interpret itself.
 */
sealed class IssuanceStart {
    /** `engine.startIssuance(offer = …)`: inline offer JSON, or a URI the engine unpacks. */
    data class Offer(val offer: String) : IssuanceStart()

    /** `engine.startIssuance(credentialOfferUri = …)`: the engine fetches it. */
    data class CredentialOfferUri(val uri: String) : IssuanceStart()
}

fun resolveIssuanceStart(offerUri: String): IssuanceStart {
    val uri = try {
        java.net.URI(offerUri)
    } catch (_: Exception) {
        null
    }
    val params = parseQueryParams(uri?.rawQuery)
    params["credential_offer"]?.let { return IssuanceStart.Offer(it) }
    params["credential_offer_uri"]?.let { return IssuanceStart.CredentialOfferUri(it) }
    return when (uri?.scheme?.lowercase()) {
        "https", "http" -> IssuanceStart.CredentialOfferUri(offerUri)
        else -> IssuanceStart.Offer(offerUri)
    }
}
