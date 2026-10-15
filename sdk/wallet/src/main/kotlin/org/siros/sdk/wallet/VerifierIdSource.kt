// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
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
 * registering an implementation. A registered source is consulted only when
 * its [type] is in the wallet's supported-type list, after the default
 * [AuthZENSource] for that type.
 */
interface VerifierIdSource {
    /** The `verifier_id_type` this source can produce. */
    val type: String

    /** The identifier for [context], or null to decline (the next registered source is tried). */
    suspend fun resolve(context: VerifierIdContext): String?
}

/**
 * Resolves the opaque `verifier_id` for a pseudonym from the wallet's ORDERED
 * [supportedTypes] (see [VerifierIdTypeOrder]; the trust framework agrees the
 * type, the request does not choose it).
 *
 * For each type in order, the identifier is looked up in:
 *  1. the policy decision point's answer, [AuthZENSource] (the default source,
 *     built implicitly for every supported type), then
 *  2. any [extraSources] registered for that type, in the order given (for
 *     example the optional local [X509SanDnsSource]).
 * The first non-null identifier wins, and the first type that yields one ends
 * the search. A type for which nothing resolves (absent, or conflicting
 * DISTINCT values) is skipped and the next type is tried.
 *
 * Fail closed: with no supported type, or when no type resolves, the result is
 * null and the caller refuses. The type a request names is not an input.
 */
class VerifierIdRegistry(
    supportedTypes: List<String> = VerifierIdTypeOrder.DEFAULT,
    private val extraSources: List<VerifierIdSource> = emptyList(),
) {
    /** The supported types, in priority order. */
    val supportedTypes: List<String> = VerifierIdTypeOrder.require(supportedTypes).toList()

    /** The identifier of the first supported type that resolves, or null. A source that throws is skipped. */
    suspend fun resolve(context: VerifierIdContext): String? {
        for (type in supportedTypes) {
            for (source in sourcesFor(type)) {
                val id = try {
                    source.resolve(context)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    null
                }
                if (id != null) return id
            }
        }
        return null
    }

    private fun sourcesFor(type: String): List<VerifierIdSource> =
        listOf<VerifierIdSource>(AuthZENSource(type)) + extraSources.filter { it.type == type }
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
 * Reads the identifier from the policy decision point's response. go-trust
 * (#203) returns `context.verifier_ids` as a LIST of objects
 * `{"verifier_id_type": ..., "verifier_id": ..., "basis": ...}` (`basis` is
 * informational and ignored here). The wallet does not narrow the PDP's answer
 * (no `context.verifier_id_type` is sent), so the list may hold every type the
 * PDP knows. Among the entries whose `verifier_id_type`
 * equals [type], duplicates of one value are one identifier; if several DISTINCT
 * values exist the source declines rather than choose, because the value is
 * hashed into a pseudonym and a guess would be a different pseudonym. Malformed
 * entries and empty `verifier_id`s are ignored. Declines when the context, the
 * member (not a list) or a matching entry is absent. Type names are opaque and
 * must match what the PDP returns: go-trust (PR #204) currently emits `semantic`,
 * `dns`, `uri`, `did` and `oidf_entity`, so the default `x509_san_dns` finds nothing
 * there until the names are aligned (open item; nothing is mapped here). Also not
 * [X509SanDnsSource]'s value: that source returns the `x509_san_dns:` client id as received.
 */
class AuthZENSource(override val type: String) : VerifierIdSource {
    override suspend fun resolve(context: VerifierIdContext): String? {
        val ids = context.trust.context?.get("verifier_ids") as? JsonArray ?: return null
        return ids.asSequence()
            .mapNotNull { it as? JsonObject }
            .filter { (it["verifier_id_type"] as? JsonPrimitive)?.takeIf { p -> p.isString }?.contentOrNull == type }
            .mapNotNull { (it["verifier_id"] as? JsonPrimitive)?.takeIf { p -> p.isString }?.contentOrNull?.takeIf { v -> v.isNotEmpty() } }
            .distinct().toList().singleOrNull()
    }
}

/**
 * The wallet's default `circuit_zk` validator: the rulebook rules with every `verifier_id_type` accepted
 * structurally. The wallet picks the type itself from [WalletConfig.circuitZkVerifierIdTypes], so the type
 * a request names is neither a selection input nor a reason to refuse.
 */
internal fun defaultCircuitZkValidator(circuits: org.siros.sdk.credentials.CircuitZkCircuitSource?): org.siros.sdk.credentials.CircuitZkRequestValidator =
    org.siros.sdk.credentials.RulebookCircuitZkValidator(
        verifierIdTypes = org.siros.sdk.credentials.VerifierIdTypes { true },
        circuits = circuits,
    )
