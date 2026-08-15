// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Record of a credential presentation to a verifier.
 *
 * `id`/`credentialIds` are privatedata-spec-aligned (wallet-frontend's
 * `presentationId: number`/`usedCredentialIds: number[]`, see
 * [StoredCredential.id]) so [CredentialUtils.groupForDisplay]'s per-instance
 * usage counting matches the same identity space credentials use. The
 * remaining fields (`flowId`, `verifierName`, `credentialNames`,
 * `requestedClaims`, `success`) are Android-only UI enrichments with no
 * counterpart in wallet-frontend's `S.presentations[]` shape (which only has
 * `presentationId`, `transactionId`, `data`, `usedCredentialIds`,
 * `presentationTimestampSeconds`, `audience`) - like [StoredCredential]'s own
 * `metadata`/`issuedAt`/`expiresAt`, they are not persisted into the
 * encrypted container and are only ever populated for a record created
 * during the current process's lifetime, not one reloaded after unlock.
 */
@Serializable
data class PresentationRecord(
    /** A randomly-generated uint32-range identifier (see [StoredCredential.id]). */
    val id: Long,
    /** Flow ID from the engine. Empty for a record reloaded from the encrypted container. */
    @SerialName("flow_id") val flowId: String,
    /** Verifier name, if known. Not persisted - null after a reload. */
    @SerialName("verifier_name") val verifierName: String? = null,
    /** IDs ([StoredCredential.id]) of credentials that were presented. */
    @SerialName("credential_ids") val credentialIds: List<Long>,
    /** Credential names for display (resolved at presentation time). Not persisted - empty after a reload. */
    @SerialName("credential_names") val credentialNames: List<String> = emptyList(),
    /** Claim names that were requested/disclosed. Not persisted - empty after a reload. */
    @SerialName("requested_claims") val requestedClaims: List<String> = emptyList(),
    /** Unix epoch millis when the presentation occurred. */
    val timestamp: Long,
    /** Whether the presentation completed successfully. Assumed true for a reloaded record. */
    val success: Boolean = true,
    /**
     * True if presenting ANY of [credentialIds] this time was a
     * zero-knowledge proof (`"mso_mdoc_zk"`) rather than a raw claim
     * disclosure - lets history/UX distinguish the two, and lets
     * [CredentialConsumptionPolicy.CONSUME_NON_ZKP] be understood after the
     * fact. Defaults to false so an older reloaded record (or a format that
     * never involves ZK) doesn't need updating.
     */
    @SerialName("zk_proof") val zkProof: Boolean = false,
)
