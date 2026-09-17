// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials.diip

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URLDecoder
import java.util.Base64

/** A DID method this SDK knows by name. */
enum class DidMethod(val methodName: String) {
    /** `did:jwk` - the key itself, base64url-encoded into the identifier. Resolves offline. */
    JWK("jwk"),

    /** `did:web` - the DID document served over HTTPS from a domain the DID names. */
    WEB("web"),

    /**
     * `did:webvh` - `did:web` plus a verifiable, append-only history of the
     * document. A DIIP Future Direction, not yet required by any release.
     */
    WEBVH("webvh"),

    /**
     * `did:key` - the key encoded as a multicodec. Predates DIIP in this SDK
     * and in wallet-frontend; a wallet holding credentials bound to one keeps
     * working, but no DIIP version requires it.
     */
    KEY("key"),
    ;

    companion object {
        /** The method of a DID string, or null if it is not a DID or the method is unknown. */
        fun of(did: String): DidMethod? {
            if (!did.startsWith("did:")) return null
            val method = did.removePrefix("did:").substringBefore(':')
            return entries.firstOrNull { it.methodName == method }
        }
    }
}

/**
 * The subset of a DID document this SDK reads: the verification methods and
 * which relationships they take part in.
 *
 * DIIP names keys by relationship - an Issuer signs with a key from
 * `assertionMethod`, a Holder's `cnf.kid` points into `authentication` - so a
 * document is only useful here if it keeps that distinction.
 */
data class DidDocument(
    /** The DID this document describes. */
    val id: String,
    /** Verification methods by their full id (`<did>#<fragment>`). */
    val verificationMethods: Map<String, VerificationMethod>,
    /** Verification method ids in the `authentication` relationship. */
    val authentication: List<String> = emptyList(),
    /** Verification method ids in the `assertionMethod` relationship. */
    val assertionMethod: List<String> = emptyList(),
) {
    /**
     * The public JWK (as a JSON object) named by [kid] within [relationship].
     *
     * A null [kid] means "whichever key this relationship has", which is the
     * only thing a verifier can do when the credential or proof did not name
     * one - unambiguous for `did:jwk`, which has exactly one.
     */
    fun findPublicKey(kid: String?, relationship: DidRelationship): JsonObject? {
        val ids = when (relationship) {
            DidRelationship.AUTHENTICATION -> authentication
            DidRelationship.ASSERTION_METHOD -> assertionMethod
            DidRelationship.ANY -> verificationMethods.keys.toList()
        }
        val candidates = ids.ifEmpty {
            // A document that lists no relationship at all still resolves:
            // DID Core lets a method's verification methods be used for any
            // purpose unless the document narrows it.
            if (relationship == DidRelationship.ANY) emptyList() else verificationMethods.keys.toList()
        }
        val match = when {
            kid == null -> candidates.firstOrNull()
            // A `kid` may be the absolute DID URL or just the fragment.
            else -> candidates.firstOrNull { it == kid || it.substringAfter('#', "") == kid.substringAfter('#', kid) }
        } ?: return null
        return verificationMethods[match]?.publicKeyJwk
    }
}

/** Which verification relationship a key is being looked up for. */
enum class DidRelationship { AUTHENTICATION, ASSERTION_METHOD, ANY }

/** One verification method of a [DidDocument]. */
data class VerificationMethod(
    val id: String,
    val type: String,
    val controller: String,
    /** The public key as a JWK. Only `JsonWebKey2020`-shaped methods carry one. */
    val publicKeyJwk: JsonObject?,
)

/** What a resolution attempt produced. */
sealed class DidResolution {
    data class Resolved(val document: DidDocument) : DidResolution()

    /**
     * Resolution did not produce a document. This is a failure, never a
     * silently-empty success: a caller that cannot tell the two apart would
     * treat an unreachable issuer as an unsigned credential.
     */
    data class Failed(val did: String, val reason: String) : DidResolution()

    /** The document if resolution succeeded, else null. */
    val documentOrNull: DidDocument? get() = (this as? Resolved)?.document
}

/**
 * Resolves the DID methods DIIP requires.
 *
 * `did:jwk` resolves offline - the key *is* the identifier - so it needs no
 * network and cannot fail for connectivity reasons. `did:web` is an HTTPS
 * fetch. `did:webvh` is recognised but deliberately not resolved: see
 * [resolveWebvh].
 *
 * @param profile decides which methods are in scope; a method outside the
 *        profile still resolves if this SDK can, since DIIP explicitly does
 *        not forbid identifiers it does not require.
 * @param httpGet fetches a URL, returning the body or null. Injected so a
 *        host can supply its own client, pinning and caching - matching
 *        [org.siros.sdk.credentials.VctmFetcher].
 */
class DidResolver(
    private val profile: DiipProfile = DiipProfile.LATEST,
    private val httpGet: suspend (String) -> String?,
) {
    private val json = Json { ignoreUnknownKeys = true }

    /** Resolve any DID this SDK supports. */
    suspend fun resolve(did: String): DidResolution = when (DidMethod.of(did)) {
        DidMethod.JWK -> resolveDidJwk(did)
        DidMethod.WEB -> resolveWeb(did)
        DidMethod.WEBVH -> resolveWebvh(did)
        DidMethod.KEY -> DidResolution.Failed(did, "did:key resolution is not implemented")
        null -> DidResolution.Failed(did, "Not a DID, or an unsupported DID method: $did")
    }

    /** The methods [profile] requires a compliant wallet to resolve. */
    val requiredMethods: Set<DidMethod> get() = profile.resolvableDidMethods

    private suspend fun resolveWeb(did: String): DidResolution {
        val url = didWebToUrl(did) ?: return DidResolution.Failed(did, "Malformed did:web identifier")
        val body = runCatching { httpGet(url) }.getOrNull()
            ?: return DidResolution.Failed(did, "Could not fetch DID document from $url")
        val document = runCatching { parseDidDocument(json.parseToJsonElement(body).jsonObject) }.getOrNull()
            ?: return DidResolution.Failed(did, "DID document at $url is not a DID document")
        if (document.id != did) {
            // A document that names a different subject would let any domain
            // serve a document for any DID.
            return DidResolution.Failed(did, "DID document at $url declares id '${document.id}'")
        }
        return DidResolution.Resolved(document)
    }

    /**
     * `did:webvh` is not resolved.
     *
     * Its whole value over `did:web` is that the document's history is
     * verifiable: every log entry carries a Data Integrity proof and a hash
     * linking it to its predecessor, and a resolver that skips those checks
     * offers exactly the trust of `did:web` while looking like more. Failing
     * here is the safe default - a caller sees an unresolved DID rather than
     * an unverified document. The method is listed in [DiipProfile.V6]'s
     * [DiipProfile.resolvableDidMethods] so that gap is visible rather than
     * silent.
     */
    private fun resolveWebvh(did: String): DidResolution = DidResolution.Failed(
        did,
        "did:webvh resolution requires verifying the DID log's proof chain, which is not yet implemented",
    )

    companion object {
        /**
         * Map a `did:web` identifier to the URL its document is served from.
         *
         * `did:web:example.com` -> `https://example.com/.well-known/did.json`;
         * `did:web:example.com:a:b` -> `https://example.com/a/b/did.json`. A
         * port is percent-encoded in the DID (`example.com%3A8443`).
         */
        fun didWebToUrl(did: String): String? {
            if (!did.startsWith("did:web:")) return null
            val idPart = did.removePrefix("did:web:").substringBefore('#').substringBefore('?')
            if (idPart.isEmpty()) return null
            val segments = idPart.split(':').map { URLDecoder.decode(it, "UTF-8") }
            val host = segments.first()
            if (host.isEmpty()) return null
            val path = segments.drop(1)
            return if (path.isEmpty()) {
                "https://$host/.well-known/did.json"
            } else {
                "https://$host/${path.joinToString("/")}/did.json"
            }
        }
    }
}

/**
 * Build a `did:jwk` from a public JWK.
 *
 * The method-specific identifier is the base64url encoding of the JWK, so the
 * same key must always serialize identically: WebCrypto bookkeeping (`ext`,
 * `key_ops`) and any private key material are stripped, and members are
 * emitted in a fixed order.
 *
 * @see <a href="https://github.com/quartzjer/did-jwk/blob/main/spec.md">did:jwk</a>
 */
fun createDidJwk(publicKeyJwk: JsonObject): String {
    val canonical = canonicalPublicJwk(publicKeyJwk)
    val encoded = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(canonical.toString().toByteArray(Charsets.UTF_8))
    return "did:jwk:$encoded"
}

/** [createDidJwk] over a JWK given as a JSON string. */
fun createDidJwk(publicKeyJwkJson: String): String =
    createDidJwk(Json.parseToJsonElement(publicKeyJwkJson).jsonObject)

/**
 * The verification method id of a `did:jwk`'s only key.
 *
 * A did:jwk document has exactly one verification method, `#0`, which is why
 * DIIP can say "a `kid` from the `authentication` relationship" and a wallet
 * can produce it without resolving anything.
 */
fun didJwkKeyId(did: String): String = "$did#0"

/**
 * Resolve a `did:jwk` - no network, and no failure mode other than a
 * malformed identifier, since the key is the identifier.
 */
fun resolveDidJwk(did: String): DidResolution {
    if (!did.startsWith("did:jwk:")) return DidResolution.Failed(did, "Not a did:jwk")
    val encoded = did.removePrefix("did:jwk:").substringBefore('#').substringBefore('?')
    val jwk = runCatching {
        val decoded = Base64.getUrlDecoder().decode(encoded).toString(Charsets.UTF_8)
        Json.parseToJsonElement(decoded).jsonObject
    }.getOrNull() ?: return DidResolution.Failed(did, "did:jwk identifier is not a base64url-encoded JWK")

    val vmId = didJwkKeyId(did)
    val vm = VerificationMethod(
        id = vmId,
        type = "JsonWebKey2020",
        controller = did,
        publicKeyJwk = jwk,
    )
    return DidResolution.Resolved(
        DidDocument(
            id = did,
            verificationMethods = mapOf(vmId to vm),
            authentication = listOf(vmId),
            assertionMethod = listOf(vmId),
        ),
    )
}

/** Parse a DID document JSON object into the subset this SDK reads. */
fun parseDidDocument(root: JsonObject): DidDocument {
    val id = root["id"]?.jsonPrimitive?.contentOrNull ?: error("DID document has no id")
    val methods = LinkedHashMap<String, VerificationMethod>()

    fun absolute(ref: String) = if (ref.startsWith("#")) "$id$ref" else ref

    fun register(element: kotlinx.serialization.json.JsonElement): String? = when (element) {
        // A relationship entry is either a reference to a verification method
        // declared elsewhere in the document, or the method inlined.
        is JsonPrimitive -> element.contentOrNull?.let(::absolute)
        is JsonObject -> {
            val vmId = element["id"]?.jsonPrimitive?.contentOrNull?.let(::absolute)
            if (vmId == null) {
                null
            } else {
                methods[vmId] = VerificationMethod(
                    id = vmId,
                    type = element["type"]?.jsonPrimitive?.contentOrNull ?: "",
                    controller = element["controller"]?.jsonPrimitive?.contentOrNull ?: id,
                    publicKeyJwk = element["publicKeyJwk"] as? JsonObject,
                )
                vmId
            }
        }
        else -> null
    }

    (root["verificationMethod"] as? JsonArray)?.forEach { register(it) }

    fun relationship(name: String): List<String> =
        (root[name] as? JsonArray)?.mapNotNull { register(it) } ?: emptyList()

    return DidDocument(
        id = id,
        verificationMethods = methods,
        authentication = relationship("authentication"),
        assertionMethod = relationship("assertionMethod"),
    )
}

/**
 * Strip a JWK down to the members that identify the public key, in a fixed
 * order, so that the same key always yields the same `did:jwk`.
 *
 * `d` and the other private members must never reach a DID; `ext` and
 * `key_ops` are WebCrypto bookkeeping rather than part of the key.
 */
internal fun canonicalPublicJwk(jwk: JsonObject): JsonObject {
    val order = listOf("kty", "crv", "x", "y", "e", "n", "alg", "use")
    return buildJsonObject {
        for (member in order) {
            jwk[member]?.let { put(member, it) }
        }
    }
}

/**
 * The `kid` a credential's `cnf` claim binds it to.
 *
 * DIIP binds the Holder with a `cnf.kid` naming a verification method of
 * their DID document. Credentials predating that carry `cnf.jwk` and are
 * addressed by JWK thumbprint, which is what this SDK has always used as a
 * local key id. Returns null when the credential has no holder binding at all.
 */
fun resolveCnfKid(cnf: JsonObject?, thumbprintOf: (JsonObject) -> String): String? {
    cnf?.get("kid")?.jsonPrimitive?.contentOrNull?.let { return it }
    (cnf?.get("jwk") as? JsonObject)?.let { return thumbprintOf(it) }
    return null
}
