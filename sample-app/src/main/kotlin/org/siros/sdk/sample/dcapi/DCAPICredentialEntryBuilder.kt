// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.dcapi

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
 * Builds the [DigitalCredentialEntry] list registered with the OS's Digital
 * Credentials API picker via [androidx.credentials.registry.provider.RegistryManager]
 * (see [DCAPIProviderRegistration]).
 *
 * Field/claim VALUES (not just labels) are included because the OS's own
 * matcher engine evaluates each incoming verifier's DCQL query against these
 * registered entries to decide which ones to even show in the picker -
 * unlike the in-app credential list, which is purely for display.
 */
object DCAPICredentialEntryBuilder {
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
        return MdocEntry(
            cred.metadata?.doctype ?: "",
            fields,
            setOf(entryDisplayProperties(cred) as EntryDisplayProperties),
            cred.id,
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
            id = cred.id,
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
