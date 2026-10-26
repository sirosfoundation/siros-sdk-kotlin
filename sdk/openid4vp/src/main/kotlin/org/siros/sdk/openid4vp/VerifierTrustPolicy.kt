// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.openid4vp

import java.net.URI
import java.security.cert.X509Certificate

/**
 * What the wallet knows about a verifier once its request object verified: the `client_id` the certificate's SAN matched,
 * where the request came from and where the response would go, and the signing chain (leaf first, NOT validated against a
 * trust anchor: a policy that needs that validates it).
 */
class VerifierIdentity(
    val clientId: String,
    val requestUri: String,
    val responseUri: String,
    val certificateChain: List<X509Certificate>,
) {
    override fun toString() = "VerifierIdentity($clientId)"
}

/**
 * Whether the wallet may answer a verifier at all. Asked once per request, after the request object's signature and its
 * `client_id` binding checked out and before anything is shown or proved. There is no default: the host decides (a trust
 * list, a PKI anchor, or, for a demo, [AllowedHostsTrustPolicy]).
 */
fun interface VerifierTrustPolicy {
    fun trusts(verifier: VerifierIdentity): Boolean
}

/**
 * A demo policy: trusts a verifier when both its `request_uri` and its `response_uri` are on one of [hosts] (exact host
 * names, case-insensitive). It does not look at the certificate beyond what the client already checked (the `client_id`
 * host is a dNSName SAN of the self-presented leaf), so it answers "is this the demo site I set up", not "is this a
 * trusted relying party".
 */
class AllowedHostsTrustPolicy(hosts: Collection<String>) : VerifierTrustPolicy {
    private val hosts: Set<String> = hosts.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()

    override fun trusts(verifier: VerifierIdentity): Boolean = host(verifier.requestUri) in hosts && host(verifier.responseUri) in hosts

    private fun host(url: String): String? = try {
        URI(url).host?.lowercase()
    } catch (e: Exception) {
        null
    }
}
