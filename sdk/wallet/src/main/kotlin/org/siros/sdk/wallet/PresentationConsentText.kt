// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.content.Context
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale
import org.siros.sdk.credentials.AgeForm
import org.siros.sdk.credentials.ConsentItem
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.credentials.PseudonymScope

/** The consent strings the SDK owns, one key per sentence; arguments are positional (see the string resources). */
enum class ConsentString(internal val res: Int) {
    TITLE(R.string.siros_consent_title),
    SHARE(R.string.siros_consent_share),
    CANCEL(R.string.siros_consent_cancel),
    VERIFIER_PROVE(R.string.siros_consent_verifier_prove),
    VERIFIER_SHARE(R.string.siros_consent_verifier_share),
    AGE_BETWEEN(R.string.siros_consent_age_between),
    AGE_AT_LEAST(R.string.siros_consent_age_at_least),
    AGE_AT_MOST(R.string.siros_consent_age_at_most),
    PSEUDONYM(R.string.siros_consent_pseudonym),
    PSEUDONYM_ISSUER_CAN_LINK(R.string.siros_consent_pseudonym_issuer),
    FOOTER(R.string.siros_consent_footer),
    CLAIM(R.string.siros_consent_claim),
    LEGACY_PSEUDONYM(R.string.siros_consent_legacy_pseudonym),
}

/** Resolves a [ConsentString] with its arguments. The wallet's implementation reads the SDK's string resources. */
fun interface ConsentStrings {
    fun get(key: ConsentString, vararg args: Any): String
}

/** One credential of the request as the user reads it. */
data class ConsentScreenEntry(
    /** The credential's display name, if known. */
    val credentialName: String?,
    /** The issuer's display name, if known. */
    val issuerName: String?,
    /** One sentence per item, in order. */
    val lines: List<String>,
)

/** The `verifier_id` for display: [shortened] for the screen, [full] on expand or long-press. Never altered otherwise. */
data class ConsentVerifierDetail(val shortened: String, val full: String)

/** The text of a [PresentationConsentRequest]. */
data class ConsentScreen(
    val title: String,
    /** "{name} is asking you to prove:" (or "share:" when a claim is disclosed). */
    val header: String,
    val entries: List<ConsentScreenEntry>,
    /** "No other personal data is shared." */
    val footer: String,
    /** The verifier id value, with no type label; null when the request uses none. */
    val verifierDetail: ConsentVerifierDetail?,
    val shareLabel: String,
    val cancelLabel: String,
)

/**
 * Turns a [PresentationConsentRequest] into the SDK's wording: hard-coded in the SDK's resources (default
 * locale, sv, fi, el, pt), parameterised per item and never concatenated. The trust framework and the
 * `verifier_id_type` never appear in it. Nothing here logs; callers must not log the result either.
 */
class PresentationConsentText(private val strings: ConsentStrings, private val locale: Locale = Locale.getDefault()) {

    /** Fails (throws) on an item this wording does not cover rather than showing a consent that omits it. */
    fun render(request: PresentationConsentRequest): ConsentScreen {
        val name = request.verifier.label
        val allItems = request.entries.flatMap { it.items }
        val disclosesClaims = allItems.any { it is ConsentItem.Claim || it is ConsentItem.LegacyPseudonym }
        return ConsentScreen(
            title = strings.get(ConsentString.TITLE),
            header = strings.get(if (disclosesClaims) ConsentString.VERIFIER_SHARE else ConsentString.VERIFIER_PROVE, name),
            entries = request.entries.map { e ->
                ConsentScreenEntry(e.credential.name, e.credential.issuer, e.items.map { line(it, name) })
            },
            footer = strings.get(ConsentString.FOOTER),
            verifierDetail = request.verifier.verifierId?.let { ConsentVerifierDetail(shortenMiddle(it), it) },
            shareLabel = strings.get(ConsentString.SHARE),
            cancelLabel = strings.get(ConsentString.CANCEL),
        )
    }

    private fun line(item: ConsentItem, verifierName: String): String = when (item) {
        is ConsentItem.AgeRange -> when (val form = item.form) {
            is AgeForm.Between -> strings.get(ConsentString.AGE_BETWEEN, date(form.from), date(form.to), form.minYears, form.maxYears)
            is AgeForm.AtLeast -> strings.get(ConsentString.AGE_AT_LEAST, form.years)
            is AgeForm.AtMost -> strings.get(ConsentString.AGE_AT_MOST, form.years)
        }
        is ConsentItem.Pseudonym -> {
            require(item.scope == PseudonymScope.PER_VERIFIER && !item.crossSite && item.verifierContext == null) { "unsupported pseudonym scope" }
            strings.get(if (item.remappableByIssuer) ConsentString.PSEUDONYM_ISSUER_CAN_LINK else ConsentString.PSEUDONYM, verifierName)
        }
        is ConsentItem.LegacyPseudonym -> strings.get(ConsentString.LEGACY_PSEUDONYM, verifierName)
        is ConsentItem.Claim -> strings.get(ConsentString.CLAIM, item.name)
    }

    /** The date as the user's locale writes it; the input is a validated RFC 3339 full-date. */
    private fun date(iso: String): String =
        DateTimeFormatter.ofLocalizedDate(FormatStyle.LONG).withLocale(locale).format(LocalDate.parse(iso))

    companion object {
        /** The longest `verifier_id` shown whole; a longer one keeps its start and end (a DID, an x509 SAN). */
        const val MAX_DETAIL_CODE_POINTS = 40
        private const val KEEP_CODE_POINTS = 18

        /** [id] with its middle replaced by an ellipsis when it is long. For display only: never use the result as the id. */
        fun shortenMiddle(id: String): String {
            val n = id.codePointCount(0, id.length)
            if (n <= MAX_DETAIL_CODE_POINTS) return id
            val head = id.substring(0, id.offsetByCodePoints(0, KEEP_CODE_POINTS))
            val tail = id.substring(id.offsetByCodePoints(0, n - KEEP_CODE_POINTS))
            return "$head…$tail"
        }

        /** The wording from [context]'s resources, in the locale it is running in. */
        fun forContext(context: Context): PresentationConsentText =
            PresentationConsentText(ConsentStrings { key, args -> context.getString(key.res, *args) }, context.resources.configuration.locales[0])
    }
}
