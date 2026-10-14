// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.Json

/**
 * Claims the wallet never discloses, matches on, registers or displays: a data
 * table keyed by credential type (an mdoc `docType` or an SD-JWT `vct`) to the
 * protected claim paths of that type. Nothing in the logic is tied to a
 * particular type; a type with no entry is unaffected.
 *
 * A path is the DCQL claim path: `[namespace, element]` for an mdoc, the claim
 * name path for an SD-JWT. A protected path covers itself and everything below
 * it.
 */
class NonDisclosurePolicy(protectedPaths: Map<String, Set<List<String>>>) {
    private val protectedByType: Map<String, Set<List<String>>> = protectedPaths.mapValues { it.value.toSet() }

    /** The types this policy has an entry for. */
    val types: Set<String> get() = protectedByType.keys

    /** The protected paths of [type] (empty for a type without an entry). */
    fun protectedPaths(type: String?): Set<List<String>> = type?.let { protectedByType[it] }.orEmpty()

    /** Whether the claim at [path] of a credential of [type] is protected. */
    fun isProtected(type: String?, path: List<String>): Boolean =
        protectedPaths(type).any { p -> path.size >= p.size && path.subList(0, p.size) == p }

    /**
     * Whether asking for any of [requested] would reach a protected claim:
     * a protected path or something below it, or an ancestor of one (a whole
     * namespace, say).
     */
    fun requestsProtected(type: String?, requested: List<List<String>>): Boolean {
        val protectedHere = protectedPaths(type)
        if (protectedHere.isEmpty()) return false
        return requested.any { r ->
            protectedHere.any { p ->
                (r.size >= p.size && r.subList(0, p.size) == p) || (r.size < p.size && p.subList(0, r.size) == r)
            }
        }
    }

    /**
     * The policy protecting everything either policy protects (per type, the
     * union of the protected paths). Returns [this] or [other] when one already
     * covers the other, so a single policy is never copied.
     */
    fun union(other: NonDisclosurePolicy): NonDisclosurePolicy {
        if (other === this || other.protectedByType.isEmpty()) return this
        if (protectedByType.isEmpty()) return other
        val merged = (protectedByType.keys + other.protectedByType.keys).associateWith { t ->
            protectedByType[t].orEmpty() + other.protectedByType[t].orEmpty()
        }
        return when (merged) {
            protectedByType -> this
            other.protectedByType -> other
            else -> NonDisclosurePolicy(merged)
        }
    }

    companion object {
        /** The nym_auth document type, whose `ssc` and `psc` are seed commitments. */
        const val NYM_AUTH_DOCTYPE = "eu.europa.ec.eudi.nym_auth.1"

        /** The default data: the nym_auth doctype with `ssc` and `psc` (`birth_date` is not protected). */
        val DEFAULT = NonDisclosurePolicy(
            mapOf(
                NYM_AUTH_DOCTYPE to setOf(
                    listOf(NYM_AUTH_DOCTYPE, "ssc"),
                    listOf(NYM_AUTH_DOCTYPE, "psc"),
                ),
            ),
        )

        /** No protected claims anywhere. */
        val NONE = NonDisclosurePolicy(emptyMap())
    }
}

/**
 * A presentation would have disclosed a protected claim. The wallet refuses
 * it outright: stripping the claim would hand the verifier a presentation
 * that looks complete and is not. The message names no claim.
 */
class DisclosureRefusedException : SirosException(
    "A presentation would disclose a protected claim; refused",
    errorCode = "protected_claim_refused",
)

/**
 * The one guard behind every enforcement point: matching, the OS picker blob,
 * presentation building, display. It consults the policy in force.
 *
 * The enforcement points are stateless utilities, so the guard is process-wide,
 * but no wallet can weaken another: each `SirosWallet` [register]s its own
 * policy and the policy in force is the union of every live registration (what
 * any wallet protects is protected). A wallet configured with
 * [NonDisclosurePolicy.NONE] therefore only lifts the protection while no
 * other wallet in the process asks for it. Registrations are weak, and
 * [unregister] drops one explicitly.
 */
object CredentialDisclosureGuard {
    private val lock = Any()
    private val registrations = java.util.WeakHashMap<Any, NonDisclosurePolicy>()

    @Volatile
    private var inForce: NonDisclosurePolicy = NonDisclosurePolicy.DEFAULT

    /**
     * The policy in force. Reading returns the union of the registered policies
     * (the default while none is registered). Assigning replaces everything
     * registered with [value]: for apps and tests that manage the policy
     * themselves, not for wallets.
     */
    var policy: NonDisclosurePolicy
        get() = inForce
        set(value) = synchronized(lock) {
            registrations.clear()
            inForce = value
        }

    /** Registers [policy] for [owner] (replacing its earlier one); the policy in force is recomputed. */
    fun register(owner: Any, policy: NonDisclosurePolicy) = synchronized(lock) {
        registrations[owner] = policy
        recompute()
    }

    /** Drops [owner]'s registration. */
    fun unregister(owner: Any) = synchronized(lock) {
        if (registrations.remove(owner) != null) recompute()
    }

    private fun recompute() {
        inForce = registrations.values.reduceOrNull { a, b -> a.union(b) } ?: NonDisclosurePolicy.DEFAULT
    }

    private val json = Json { ignoreUnknownKeys = true }

    /** The type the policy is keyed by for [credential]: its mdoc `docType` or its SD-JWT `vct`. */
    fun typeOf(credential: StoredCredential): String? =
        if (credential.format.equals("mso_mdoc", ignoreCase = true)) {
            CredentialUtils.parseMdocDocument(credential)?.docType ?: credential.metadata?.doctype
        } else {
            CredentialUtils.vctOf(credential)
        }

    /** Whether the claim at [path] of [type] is protected. */
    fun isProtected(type: String?, path: List<String>): Boolean = policy.isProtected(type, path)

    /** Whether asking for [requested] of [credential] would reach a protected claim. */
    fun requestsProtected(credential: StoredCredential, requested: List<List<String>>): Boolean {
        if (policy.types.isEmpty()) return false
        return policy.requestsProtected(typeOf(credential), requested)
    }

    /**
     * Fail-closed check for an mdoc presentation about to disclose [disclosed]
     * (namespace to element identifiers).
     *
     * @throws DisclosureRefusedException if any of them is protected.
     */
    fun requireNoneProtected(docType: String, disclosed: Map<String, Collection<String>>) {
        for ((namespace, elements) in disclosed) {
            for (element in elements) {
                if (policy.isProtected(docType, listOf(namespace, element))) throw DisclosureRefusedException()
            }
        }
    }

    /**
     * Fail-closed check for an SD-JWT presentation about to carry
     * [selectedDisclosures] of the compact [credential].
     *
     * @throws DisclosureRefusedException if any disclosure names a protected claim.
     */
    fun requireNoneProtectedSdJwt(credential: String, selectedDisclosures: List<String>) {
        if (policy.types.isEmpty() || selectedDisclosures.isEmpty()) return
        val vct = try {
            val payload = credential.substringBefore('~').split('.').getOrNull(1) ?: return
            val obj = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8)) as? JsonObject
            (obj?.get("vct") as? JsonPrimitive)?.contentOrNull
        } catch (e: Exception) {
            null
        } ?: return
        if (policy.protectedPaths(vct).isEmpty()) return
        for (disclosure in selectedDisclosures) {
            val name = try {
                val array = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(disclosure), Charsets.UTF_8)) as? JsonArray
                (array?.getOrNull(1) as? JsonPrimitive)?.takeIf { it.isString }?.content
            } catch (e: Exception) {
                // Unreadable: it could be anything, so it is not sent.
                throw DisclosureRefusedException()
            }
            if (name != null && policy.isProtected(vct, listOf(name))) throw DisclosureRefusedException()
        }
    }
}
