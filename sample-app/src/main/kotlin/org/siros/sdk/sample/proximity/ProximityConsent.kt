// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.proximity

import org.siros.sdk.credentials.StoredCredential

/**
 * One credential "type" as the user should see it: every [StoredCredential]
 * instance sharing a [StoredCredential.batchId] is the SAME credential from
 * a batch issuance (see `CredentialUtils.groupForDisplay`'s doc comment for
 * why - each instance is bound to its own device key purely for
 * unlinkability, not a distinct credential the user chose to hold multiple
 * of). The consent dialog must offer one choice per family, never one per
 * raw instance, or a 5-instance batch reads as "you have 5 driver's
 * licenses."
 */
data class CredentialFamily(
    /** The instance shown to the user for display (matches `groupForDisplay`'s convention of the `instanceId == 0` member). */
    val representative: StoredCredential,
    /** Every instance in this batch - [BlePeripheralServer]/[BleCentralClient] pick one of these to actually sign with once the family is approved. */
    val instances: List<StoredCredential>,
)

/** Groups credentials into one [CredentialFamily] per [StoredCredential.batchId]. */
fun groupIntoFamilies(credentials: List<StoredCredential>): List<CredentialFamily> {
    return credentials.groupBy { it.batchId }.values.map { members ->
        CredentialFamily(
            representative = members.firstOrNull { it.instanceId == 0 } ?: members.first(),
            instances = members,
        )
    }
}

/** The user's answer to a [RequestProximityConsent] prompt. */
sealed interface ProximityConsentResult {
    data class Approved(val family: CredentialFamily) : ProximityConsentResult
    data object Denied : ProximityConsentResult
}

/**
 * Asks the user to approve a proximity presentation before it's signed and
 * sent - shared by [BlePeripheralServer] and [BleCentralClient] so both BLE
 * roles go through the same UI, implemented by `ProximityEngagementScreen`
 * as a suspending bridge to a Compose consent dialog.
 *
 * @param docType the requested document type.
 * @param requestedClaims the flattened element identifiers the reader asked for.
 * @param matchingFamilies every credential family whose docType matches
 *   (never empty - callers only invoke this once at least one match exists;
 *   see [CredentialFamily] for why this is families, not raw instances),
 *   for the user to choose among if there's more than one (e.g. the same
 *   docType from two different issuers).
 */
typealias RequestProximityConsent = suspend (
    docType: String,
    requestedClaims: List<String>,
    matchingFamilies: List<CredentialFamily>,
) -> ProximityConsentResult
