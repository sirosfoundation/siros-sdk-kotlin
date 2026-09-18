// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

/**
 * How a credential-offer URI handed to [SirosWallet.startIssuance] reaches
 * the engine. Pure, so the mapping is testable without a connection.
 *
 * The engine's own `startIssuance(offer)` strips the `credential_offer` query
 * parameter for exactly one scheme, lowercase `openid-credential-offer`, and
 * historically only when it was written with an authority (`://`).
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
    val params = parseQueryParams(rawQueryOf(uri))
    params["credential_offer"]?.let { return IssuanceStart.Offer(it) }
    params["credential_offer_uri"]?.let { return IssuanceStart.CredentialOfferUri(it) }
    return when (uri?.scheme?.lowercase()) {
        "https", "http" -> IssuanceStart.CredentialOfferUri(offerUri)
        else -> IssuanceStart.Offer(offerUri)
    }
}

/**
 * The raw query of [uri], including for a URI with no authority component.
 *
 * A credential offer's authority is empty, and RFC 3986 lets it be left out,
 * so both of these are offers an issuer may hand over:
 *
 *     openid-credential-offer://?credential_offer=...
 *     openid-credential-offer:?credential_offer=...
 *
 * [java.net.URI] calls the second one *opaque* - its scheme-specific part
 * does not begin with `/` - and an opaque URI reports no query at all, so
 * [java.net.URI.getRawQuery] answers null and every parameter is invisible.
 * The offer then travels to the engine as the whole URI string rather than
 * as the JSON it contains, and issuance fails there on the first character.
 *
 * So for an opaque URI the query is taken from the scheme-specific part by
 * hand. Returned raw, because callers percent-decode per parameter.
 */
private fun rawQueryOf(uri: java.net.URI?): String? {
    if (uri == null) return null
    uri.rawQuery?.let { return it }
    if (!uri.isOpaque) return null
    val ssp = uri.rawSchemeSpecificPart ?: return null
    val start = ssp.indexOf('?')
    if (start < 0) return null
    return ssp.substring(start + 1).substringBefore('#')
}
