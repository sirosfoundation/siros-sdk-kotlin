// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.credentials

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Record of a credential presentation to a verifier.
 */
@Serializable
data class PresentationRecord(
    val id: String,
    /** Flow ID from the engine. */
    @SerialName("flow_id") val flowId: String,
    /** Verifier name, if known. */
    @SerialName("verifier_name") val verifierName: String? = null,
    /** IDs of credentials that were presented. */
    @SerialName("credential_ids") val credentialIds: List<String>,
    /** Credential names for display (resolved at presentation time). */
    @SerialName("credential_names") val credentialNames: List<String> = emptyList(),
    /** Unix epoch millis when the presentation occurred. */
    val timestamp: Long,
    /** Whether the presentation completed successfully. */
    val success: Boolean = true,
)
