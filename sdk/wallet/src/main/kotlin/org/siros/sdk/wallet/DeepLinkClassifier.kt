// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.net.Uri

/**
 * Classification of an incoming deep link URI.
 *
 * Host apps should call [classifyDeepLink] to determine how to handle an
 * incoming URI rather than performing their own string matching.
 */
sealed class DeepLinkType {
    /** OAuth authorization callback with code and state parameters. */
    data class AuthCallback(val code: String, val state: String) : DeepLinkType()

    /** OID4VCI credential offer (issuance flow). */
    data class CredentialOffer(val uri: String) : DeepLinkType()

    /** OID4VP presentation request. */
    data class PresentationRequest(val uri: String) : DeepLinkType()

    /** URI does not match any known wallet protocol. */
    object Unknown : DeepLinkType()
}

/**
 * Classify a deep link URI for wallet protocol routing.
 *
 * Validates and categorizes incoming URIs using proper scheme/host/parameter
 * parsing rather than substring matching, preventing overly permissive
 * acceptance of attacker-controlled URLs.
 *
 * @param uri The incoming Android [Uri].
 * @param redirectScheme The custom scheme configured for OAuth callbacks.
 * @return A [DeepLinkType] indicating how the URI should be handled.
 */
fun classifyDeepLink(uri: Uri, redirectScheme: String): DeepLinkType {
    return classifyDeepLink(uri.toString(), redirectScheme)
}

/**
 * Classify a deep link URI string for wallet protocol routing.
 *
 * This overload accepts a plain string and uses [java.net.URI] for parsing,
 * making it usable in unit tests without Robolectric.
 *
 * @param uriString The incoming URI string.
 * @param redirectScheme The custom scheme configured for OAuth callbacks.
 * @return A [DeepLinkType] indicating how the URI should be handled.
 */
fun classifyDeepLink(uriString: String, redirectScheme: String): DeepLinkType {
    val jUri = try {
        java.net.URI(uriString)
    } catch (_: Exception) {
        return DeepLinkType.Unknown
    }

    val scheme = jUri.scheme?.lowercase() ?: return DeepLinkType.Unknown

    // 1. OAuth callback: custom-scheme://callback?code=...&state=...
    if (scheme == redirectScheme.lowercase() && jUri.host == "callback") {
        val params = parseQueryParams(jUri.rawQuery)
        val code = params["code"]
        val state = params["state"]
        return if (code != null && state != null) {
            DeepLinkType.AuthCallback(code = code, state = state)
        } else {
            DeepLinkType.Unknown
        }
    }

    // 2. OID4VCI: openid-credential-offer://...
    if (scheme == "openid-credential-offer") {
        return DeepLinkType.CredentialOffer(uri = uriString)
    }

    // 3. OID4VP: openid4vp://...
    if (scheme == "openid4vp") {
        return DeepLinkType.PresentationRequest(uri = uriString)
    }

    // 4. HAIP: haip://...
    if (scheme == "haip") {
        return DeepLinkType.PresentationRequest(uri = uriString)
    }

    // 5. HTTPS with OID4VCI/OID4VP query parameters
    if (scheme == "https" || scheme == "http") {
        val params = parseQueryParams(jUri.rawQuery)
        if (params.containsKey("credential_offer_uri") ||
            params.containsKey("credential_offer")
        ) {
            return DeepLinkType.CredentialOffer(uri = uriString)
        }
        if (params.containsKey("request_uri") ||
            params.containsKey("client_id")
        ) {
            return DeepLinkType.PresentationRequest(uri = uriString)
        }
    }

    return DeepLinkType.Unknown
}

internal fun parseQueryParams(query: String?): Map<String, String> {
    if (query.isNullOrEmpty()) return emptyMap()
    return query.split("&").associate { param ->
        val parts = param.split("=", limit = 2)
        val key = java.net.URLDecoder.decode(parts[0], "UTF-8")
        val value = if (parts.size > 1) java.net.URLDecoder.decode(parts[1], "UTF-8") else ""
        key to value
    }
}
