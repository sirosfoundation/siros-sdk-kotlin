// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.siros.sdk.credentials.VerifierIdTypes
import org.siros.sdk.wallet.dcapi.DCAPIRequest

/**
 * What a [VerifierIdSource] may read: only authenticated inputs. The request
 * has had its signature verified (client id, `x5c` chain, `verifier_info`);
 * [trust] is the policy decision, including its response context; [origin] is
 * what the platform attested for the caller.
 */
class VerifierIdContext(
    val request: DCAPIRequest,
    val trust: TrustResult,
    val origin: String,
)

/**
 * Produces the opaque `verifier_id` string for one `verifier_id_type`. The
 * wallet does not know how verifiers are named: adding a source is
 * registering an implementation.
 */
interface VerifierIdSource {
    /** The `verifier_id_type` this source can produce. */
    val type: String

    /** The identifier for [context], or null to decline (the next registered source is tried). */
    suspend fun resolve(context: VerifierIdContext): String?
}

/**
 * The configured sources. For a type, the sources registered for it are tried
 * in configured order and the first non-null identifier wins. It is also the
 * [VerifierIdTypes] the validator consults: a type is registered when at
 * least one source produces it.
 */
class VerifierIdRegistry(private val sources: List<VerifierIdSource>) : VerifierIdTypes {
    override fun isRegistered(type: String): Boolean = sources.any { it.type == type }

    /** The identifier for [type], or null if no source produces one. A source that throws is skipped. */
    suspend fun resolve(type: String, context: VerifierIdContext): String? {
        for (source in sources) {
            if (source.type != type) continue
            val id = try {
                source.resolve(context)
            } catch (e: Exception) {
                null
            }
            if (id != null) return id
        }
        return null
    }
}

/**
 * Type `x509_san_dns`: the request's client identifier must be
 * `x509_san_dns:<dns name>` and the DNS name must equal a `dNSName` Subject
 * Alternative Name of the request's `x5c` leaf certificate (compared
 * case-insensitively, no wildcard matching). The result is the client
 * identifier string as received. Any other prefix, including `x509_hash`,
 * and any request without an `x5c` chain are declined.
 */
class X509SanDnsSource : VerifierIdSource {
    override val type = "x509_san_dns"

    override suspend fun resolve(context: VerifierIdContext): String? {
        val clientId = context.request.clientId ?: return null
        if (!clientId.startsWith(PREFIX)) return null
        val dns = clientId.removePrefix(PREFIX)
        if (dns.isEmpty()) return null
        val leaf = context.request.keyMaterial?.x5c?.firstOrNull() ?: return null
        val cert = try {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(leaf))) as X509Certificate
        } catch (e: Exception) {
            return null
        }
        val sans = try {
            cert.subjectAlternativeNames
        } catch (e: Exception) {
            null
        } ?: return null
        val listed = sans.any { it.size >= 2 && it[0] == SAN_DNS_NAME && (it[1] as? String)?.equals(dns, ignoreCase = true) == true }
        return if (listed) clientId else null
    }

    private companion object {
        const val PREFIX = "x509_san_dns:"
        const val SAN_DNS_NAME = 2
    }
}

/**
 * Reads the identifier from the policy decision point's response: the
 * trust response's `context.verifier_ids[<type>]`. Declines when the
 * context, the `verifier_ids` member or the type is absent.
 */
class AuthZENSource(override val type: String) : VerifierIdSource {
    override suspend fun resolve(context: VerifierIdContext): String? {
        val ids = context.trust.context?.get("verifier_ids") as? JsonObject ?: return null
        return (ids[type] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotEmpty() }
    }
}
