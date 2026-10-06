// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.wallet.TransactionConsentEntry
import org.siros.sdk.wallet.TransactionConsentField
import org.siros.sdk.wallet.TransactionConsentRequest

/**
 * Builds the consent model (contract section 5; EC TS12 v1.0.1 3.3) from a
 * validated request. Everything shown comes from the wallet's own decoding of
 * `raw` and from the type metadata, never from the orchestrator's hint.
 *
 * Fail closed (TS12 3.3.1): if a localised parameter name or the required
 * `affirmative_action_label` is not available, the transaction is refused.
 */
internal class TransactionDisplayBuilder(
    private val source: TransactionMetadataSource,
    private val locale: String,
) {
    suspend fun build(
        validated: ValidatedTransactionData,
        verifier: String?,
        requestSigned: Boolean?,
    ): TransactionConsentRequest {
        val entries = validated.entries.map { buildEntry(it) }
        val credentialName = validated.entries.firstOrNull()?.contexts?.firstOrNull()?.let { credentialName(it) }
        return TransactionConsentRequest(
            verifier = verifier,
            credentialName = credentialName,
            entries = entries,
            requestSigned = requestSigned,
            locale = locale,
        )
    }

    private suspend fun buildEntry(entry: ValidatedTransactionEntry): TransactionConsentEntry {
        val ctx = entry.contexts.first()
        val typeEntry = ctx.typeEntry
            ?: throw unavailable("The type metadata has no entry for '${entry.type}', so no localised labels exist")

        val claims = claimsOf(entry, ctx, typeEntry)
        val labels = uiLabelsOf(entry, ctx, typeEntry)

        val affirmative = labels.localized("affirmative_action_label")
            ?: throw unavailable("The required affirmative_action_label is not available")
        val fields = fieldsOf(entry.payload, claims)
        return TransactionConsentEntry(
            title = labels.localized("transaction_title"),
            typeName = TypeNames.of(entry.type),
            fields = fields,
            affirmativeLabel = affirmative,
            denialLabel = labels.localized("denial_action_label"),
            securityHint = labels.localized("security_hint"),
        )
    }

    // ── claim metadata (TS12 3.3.2) ────────────────────────────────

    private class Claim(val path: List<String>, val level: Int, val labels: List<Pair<String, String>>)

    private suspend fun claimsOf(entry: ValidatedTransactionEntry, ctx: ScaCredentialContext, typeEntry: JsonObject): List<Claim> {
        val inline = typeEntry["claims"]
        val uri = typeEntry["claims_uri"]
        if (inline != null && uri != null) throw unavailable("A transaction data type has both claims and claims_uri")
        val array: JsonElement = when {
            inline != null -> inline
            uri is JsonPrimitive && uri.isString -> parse(ReferencedDocuments.fetch(source, ctx.credential, entry.type, "claims_uri", uri.content))
            else -> throw unavailable("The type metadata gives no claim metadata")
        }
        val list = array as? JsonArray ?: throw unavailable("Claim metadata is not an array")
        return list.map { c ->
            val obj = c as? JsonObject ?: throw unavailable("A claim metadata entry is not an object")
            val path = (obj["path"] as? JsonArray)?.map {
                (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw unavailable("A claim path holds a non-string")
            } ?: throw unavailable("A claim metadata entry has no path")
            val level = when (val v = obj["visualisation"]) {
                null -> DEFAULT_LEVEL
                is JsonPrimitive -> v.intOrNull?.takeIf { it in 1..4 } ?: throw unavailable("visualisation must be 1 to 4")
                else -> throw unavailable("visualisation must be 1 to 4")
            }
            val labels = (obj["display"] as? JsonArray)?.mapNotNull { d ->
                val o = d as? JsonObject ?: return@mapNotNull null
                val tag = (o["lang"] ?: o["locale"])?.let { it as? JsonPrimitive }?.contentOrNull
                val label = (o["label"] as? JsonPrimitive)?.contentOrNull
                if (tag != null && !label.isNullOrEmpty()) tag to label else null
            }.orEmpty()
            Claim(path, level, labels)
        }
    }

    // ── UI elements catalogue (TS12 3.3.3) ─────────────────────────

    private class Catalogue(private val map: Map<String, List<Pair<String, String>>>, private val locale: String) {
        fun localized(key: String): String? = map[key]?.let { pick(it, locale) }
    }

    private suspend fun uiLabelsOf(entry: ValidatedTransactionEntry, ctx: ScaCredentialContext, typeEntry: JsonObject): Catalogue {
        val inline = typeEntry["ui_labels"]
        val uri = typeEntry["ui_labels_uri"]
        if (inline != null && uri != null) throw unavailable("A transaction data type has both ui_labels and ui_labels_uri")
        val doc: JsonElement = when {
            inline != null -> inline
            uri is JsonPrimitive && uri.isString -> parse(ReferencedDocuments.fetch(source, ctx.credential, entry.type, "ui_labels_uri", uri.content))
            else -> throw unavailable("The type metadata gives no UI labels")
        }
        val obj = doc as? JsonObject ?: throw unavailable("The UI labels catalogue is not an object")
        val map = obj.mapValues { (_, v) ->
            (v as? JsonArray)?.mapNotNull { item ->
                val o = item as? JsonObject ?: return@mapNotNull null
                val lang = (o["lang"] as? JsonPrimitive)?.contentOrNull
                val value = (o["value"] as? JsonPrimitive)?.contentOrNull
                if (lang != null && !value.isNullOrEmpty()) lang to value else null
            }.orEmpty()
        }
        return Catalogue(map, locale)
    }

    // ── fields ─────────────────────────────────────────────────────

    private fun fieldsOf(payload: JsonObject, claims: List<Claim>): List<TransactionConsentField> {
        val byPath = claims.associateBy { it.path }
        val out = mutableListOf<TransactionConsentField>()
        fun walk(path: List<String>, element: JsonElement) {
            if (element is JsonObject) {
                element.forEach { (k, v) -> walk(path + k, v) }
                return
            }
            val claim = byPath[listOf("payload") + path]
            val label = claim?.labels?.let { pick(it, locale) }
            val level = claim?.level ?: DEFAULT_LEVEL
            if (label == null) {
                // A value the issuer marked as omittable may go unlabelled; anything else must be shown, so it needs a name.
                if (claim != null && claim.level == 4) return
                throw unavailable("No localised name for parameter '${path.joinToString(".")}'")
            }
            out += TransactionConsentField(label, (element as? JsonPrimitive)?.content ?: element.toString(), level)
        }
        walk(emptyList(), payload)
        // Stable: level 1 first, payload order within a level.
        return out.sortedBy { it.level }
    }

    private fun credentialName(ctx: ScaCredentialContext): String? {
        val display = (ctx.metadata["display"] as? JsonArray)?.mapNotNull { d ->
            val o = d as? JsonObject ?: return@mapNotNull null
            val tag = (o["locale"] ?: o["lang"])?.let { it as? JsonPrimitive }?.contentOrNull
            val name = (o["name"] as? JsonPrimitive)?.contentOrNull
            if (tag != null && !name.isNullOrEmpty()) tag to name else null
        }.orEmpty()
        return pick(display, locale) ?: (ctx.metadata["name"] as? JsonPrimitive)?.contentOrNull
    }

    private fun parse(text: String): JsonElement = try {
        Json.parseToJsonElement(text)
    } catch (e: Exception) {
        throw TransactionDataError(TransactionDataReason.METADATA_UNAVAILABLE, "A referenced metadata document is not JSON", e)
    }

    private fun unavailable(why: String) = TransactionDataError(TransactionDataReason.METADATA_UNAVAILABLE, why)

    companion object {
        /** `visualisation` default (TS12 3.3.1). */
        const val DEFAULT_LEVEL = 3

        /**
         * The best entry of [options] (language tag to value) for [locale]:
         * the exact tag, then the same primary language, then English, then
         * the first listed. Tags compare case-insensitively.
         */
        fun pick(options: List<Pair<String, String>>, locale: String): String? {
            if (options.isEmpty()) return null
            val want = locale.lowercase().replace('_', '-')
            val lang = want.substringBefore('-')
            return options.firstOrNull { it.first.lowercase() == want }?.second
                ?: options.firstOrNull { it.first.lowercase().substringBefore('-') == lang }?.second
                ?: options.firstOrNull { it.first.lowercase().substringBefore('-') == "en" }?.second
                ?: options.first().second
        }
    }
}

/** The names EC TS12 5.3 gives the built-in types. */
internal object TypeNames {
    private val names = mapOf(
        "urn:eudi:sca:payment:1" to "Payment Confirmation",
        "urn:eudi:sca:login_risk_transaction:1" to "Login, Risk-based Authentication",
        "urn:eudi:sca:account_access:1" to "Payment Account Information Access",
        "urn:eudi:sca:emandate:1" to "E-mandate",
    )

    /** The 5.3 name of a built-in type, or [type] itself. */
    fun of(type: String): String = names[type] ?: type

    /** The 5.3 name of a built-in type, or `null`. */
    fun builtIn(type: String): String? = names[type]
}
