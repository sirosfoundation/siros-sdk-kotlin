// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.digitalcredentials.mdoc.MdocField
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtClaim
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtEntry
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialEntry
import androidx.credentials.registry.provider.digitalcredentials.EntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.FieldDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationEntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationFieldDisplayProperties
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.StoredCredential
import timber.log.Timber

/**
 * Builds the [DigitalCredentialEntry] list for the **stock** AndroidX matcher.
 *
 * Only used when a caller asks [SirosCredentialRegistry] for the stock path.
 * The SDK's own matcher does not need this: it reads the registered blob and
 * decides for itself, which is what lets it understand formats the stock
 * matcher refuses.
 *
 * Field/claim VALUES (not just labels) are included because the OS's own
 * matcher engine evaluates each incoming verifier's DCQL query against these
 * registered entries to decide which ones to even show in the picker -
 * unlike the in-app credential list, which is purely for display.
 */
internal object StockEntryBuilder {
    fun buildEntries(credentials: List<StoredCredential>): List<DigitalCredentialEntry> {
        return credentials.mapNotNull { cred ->
            try {
                when (cred.format) {
                    "mso_mdoc" -> buildMdocEntry(cred)
                    else -> buildSdJwtEntry(cred)
                }
            } catch (e: Exception) {
                Timber.w(e, "Failed to build DC API registry entry for credential ${cred.id}")
                null
            }
        }
    }

    /**
     * Split a [org.siros.sdk.credentials.DisplayClaim.key] ("$namespace.$elementIdentifier",
     * see [CredentialUtils.extractMdocClaims]) back into its namespace/identifier
     * parts. ISO mdoc namespaces are themselves dotted (e.g. "org.iso.18013.5.1"),
     * so splitting on the FIRST dot mis-parses namespace="org"/
     * identifier="iso.18013.5.1.family_name". elementIdentifier is always the
     * last segment (mdoc element identifiers never contain dots), so this
     * splits on the LAST dot instead.
     */
    internal fun splitMdocClaimKey(key: String): Pair<String, String> =
        key.substringBeforeLast(".") to key.substringAfterLast(".")

    private fun buildMdocEntry(cred: StoredCredential): MdocEntry {
        val fields = CredentialUtils.extractClaims(cred).map { claim ->
            val (namespace, identifier) = splitMdocClaimKey(claim.key)
            MdocField(
                namespace,
                identifier,
                claim.value,
                setOf(VerificationFieldDisplayProperties(claim.label, claim.value) as FieldDisplayProperties),
            )
        }
        // The real docType, parsed from the credential's own MSO - NOT
        // cred.metadata?.doctype, which only gets populated if this
        // credential's issuer happens to expose an MDDL schema endpoint at
        // the SIROS-internal `/type-metadata/<scope>` convention. A
        // standards-conformant third-party issuer (e.g. a real interop test
        // event's mDL) has no reason to implement that, so relying on it here
        // silently left every such credential with an empty docType - never
        // matchable by a verifier's DCQL request, even though the credential
        // itself and its claims were perfectly valid.
        val docType = CredentialUtils.parseMdocDocument(cred)?.docType ?: cred.metadata?.doctype ?: ""
        return MdocEntry(
            docType,
            fields,
            setOf(entryDisplayProperties(cred) as EntryDisplayProperties),
            // AndroidX's registry API requires a String id - stringify at
            // this boundary rather than changing the library's own type.
            cred.id.toString(),
        )
    }

    private fun buildSdJwtEntry(cred: StoredCredential): SdJwtEntry {
        val claims = CredentialUtils.extractClaims(cred).map { claim ->
            SdJwtClaim(
                path = listOf(claim.key),
                value = claim.value,
                fieldDisplayPropertySet = setOf(
                    VerificationFieldDisplayProperties(claim.label, claim.value) as FieldDisplayProperties
                ),
            )
        }
        return SdJwtEntry(
            verifiableCredentialType = cred.metadata?.vct ?: "",
            claims = claims,
            entryDisplayPropertySet = setOf(entryDisplayProperties(cred) as EntryDisplayProperties),
            // AndroidX's registry API requires a String id - stringify at
            // this boundary rather than changing the library's own type.
            id = cred.id.toString(),
        )
    }

    /**
     * [VerificationEntryDisplayProperties.icon] is a non-nullable [Bitmap] -
     * our stored credentials only have a remote/logo URL (fetching it would
     * require async I/O this synchronous entry-building pass can't do), so
     * this generates a flat placeholder in the credential's own card color
     * instead. Fetching/caching the real issuer logo bitmap is a reasonable
     * follow-up, not attempted here.
     */
    private fun entryDisplayProperties(cred: StoredCredential): VerificationEntryDisplayProperties {
        val color = try {
            Color.parseColor(cred.metadata?.backgroundColor ?: "#1A365D")
        } catch (_: Exception) {
            Color.parseColor("#1A365D")
        }
        val icon = Bitmap.createBitmap(32, 32, Bitmap.Config.ARGB_8888).also {
            Canvas(it).drawColor(color)
        }
        return VerificationEntryDisplayProperties(
            cred.metadata?.name ?: cred.format,
            cred.metadata?.issuer?.name,
            icon,
            null,
            null,
        )
    }
}
