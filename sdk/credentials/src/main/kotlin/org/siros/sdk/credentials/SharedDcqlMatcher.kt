// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonObject
import timber.log.Timber
import uniffi.siros_dc_matcher_ffi.FfiClaim
import uniffi.siros_dc_matcher_ffi.FfiCredential
import uniffi.siros_dc_matcher_ffi.SirosBlobBuilder
import uniffi.siros_dc_matcher_ffi.matchDcql as ffiMatchDcql

/**
 * DCQL matching by the shared Rust engine, the same one the OS credential
 * picker runs.
 *
 * [CredentialMatcher] implements a subset of DCQL: it filters on format and
 * type metadata, and does not check that a credential actually has the claims
 * a verifier asked for. OpenID4VP 1.0 §6.4.1 requires that check - a
 * credential missing a requested claim "MUST NOT" be returned - so today a
 * user can be offered a credential, consent, and have the presentation fail to
 * satisfy the verifier. `claim_sets` and `values` are missing too, and the
 * Swift SDK implements a slightly different subset again.
 *
 * This exists to retire all three implementations in favour of one that is
 * tested against the specification's own examples.
 *
 * ## Not yet trusted
 *
 * [CredentialMatcher] still decides the result. This runs alongside it and
 * reports where the two disagree, because the change it brings is not
 * cosmetic: enforcing §6.4.1 *narrows* what a wallet offers, correctly, and a
 * user whose credential stops appearing deserves that to be one deliberate
 * change rather than a side effect of another. Switching over is a separate
 * step, once the disagreements on real requests are understood.
 */
internal object SharedDcqlMatcher {

    /**
     * Credential ids the shared engine matches per credential query, or `null`
     * if it could not run.
     *
     * `null` is not "nothing matched". The native library may be missing for
     * this ABI, or the engine may reject a request this SDK would have
     * accepted - both mean "no answer", and a caller must not read that as an
     * empty match.
     */
    fun candidatesByQuery(
        dcqlQuery: JsonObject,
        credentials: List<StoredCredential>,
    ): Map<String, List<Long>>? {
        return try {
            // `use`: the builder holds a native handle, and matching runs on every
            // presentation.
            val blob = SirosBlobBuilder().use { builder ->
                credentials.forEach { builder.addCredential(toFfi(it)) }
                builder.build()
            }
            val outcome = ffiMatchDcql(blob, dcqlQuery.toString())
            // `matches`, not `combinations`. The engine bounds how many
            // combinations it returns, because the count is a product of the
            // per-query candidate counts — so reconstructing per-query
            // candidates from them would omit credentials that do qualify, and
            // this result is used to *filter*. An omission there is a
            // credential silently missing from what the user is offered, which
            // is the exact failure this component is prone to.
            //
            // `matches` is the engine's own per-query candidates, complete and
            // uncapped, so `dropped` no longer bears on this answer at all.
            outcome.matches.associate { queryMatch ->
                queryMatch.queryId to queryMatch.credentials
                    .mapNotNull { it.credentialId.toLongOrNull() }
                    .distinct()
            }
        } catch (e: Throwable) {
            // Deliberately broad. This is the first call into a native library
            // on the presentation path, and an UnsatisfiedLinkError from a
            // packaging mistake is an Error rather than an Exception -
            // catching only Exception would let it escape and take a
            // presentation down for a decision that has a fallback.
            Timber.w(e, "Shared DCQL engine unavailable; keeping the built-in matcher's answer")
            null
        }
    }

    /**
     * Report where the two implementations disagree, for one credential query.
     *
     * Logged rather than thrown. The shared engine decides now, so a
     * disagreement is not a fault - it is almost always the engine correctly
     * declining a credential that lacks a claim the verifier asked for, which
     * the built-in matcher never checked (OID4VP 1.0 §6.4.1). Recorded because
     * "my credential stopped appearing" is a support question, and this is the
     * line that answers it.
     */
    fun reportDifference(queryId: String, builtIn: List<Long>, shared: List<Long>) {
        val onlyBuiltIn = builtIn - shared.toSet()
        val onlyShared = shared - builtIn.toSet()
        if (onlyBuiltIn.isEmpty() && onlyShared.isEmpty()) return

        Timber.i(
            "DCQL query '%s': the shared engine declined %s that the built-in matcher would " +
                "have offered (most likely a requested claim the credential lacks, " +
                "OID4VP 1.0 §6.4.1), and offered %s it would not",
            queryId,
            onlyBuiltIn,
            onlyShared,
        )
    }

    private fun toFfi(cred: StoredCredential) = FfiCredential(
        id = cred.id.toString(),
        format = cred.format,
        // The real docType, from the credential's own MSO - not issuer
        // metadata, which is only populated when the issuer happens to expose
        // a SIROS-internal schema endpoint.
        doctype = CredentialUtils.parseMdocDocument(cred)?.docType ?: cred.metadata?.doctype,
        vct = cred.metadata?.vct,
        title = cred.metadata?.name ?: cred.format,
        subtitle = cred.metadata?.issuer?.name ?: "",
        iconId = null,
        claims = CredentialUtils.extractClaims(cred).map { claim ->
            FfiClaim(
                path = splitClaimKey(cred.format, claim.key),
                value = claim.value,
                display = claim.label,
                displayValue = null,
            )
        },
    )

    /**
     * Split a display-claim key into the path components DCQL matches against.
     *
     * mdoc element identifiers never contain dots while namespaces routinely
     * do, so the split is on the last one - `org.iso.18013.5.1.family_name` is
     * a namespace and an element, not five path components. JSON-based
     * credentials keep the key whole; theirs are not dotted paths.
     */
    internal fun splitClaimKey(format: String, key: String): List<String> =
        if (format.equals("mso_mdoc", ignoreCase = true) && key.contains('.')) {
            listOf(key.substringBeforeLast('.'), key.substringAfterLast('.'))
        } else {
            listOf(key)
        }
}
