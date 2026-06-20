// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.credentials

/**
 * Certification information for the WSCD (CS-04 §7.1.3, Annex C §C.3.1).
 * Either the string "none" for uncertified devices, or a structured object
 * with scheme and assurance level.
 *
 * Placed in the credentials module so both `sdk:auth` and `sdk:keystore`
 * can reference these types without circular dependencies.
 */
sealed class CertificationInfo {
    /** No certification. */
    data object None : CertificationInfo()

    /** Certified under a specific scheme. */
    data class Certified(
        val scheme: String,
        val assuranceLevel: String,
    ) : CertificationInfo()

    /** Serialize to the JSON-compatible form expected by the backend. */
    fun toJsonValue(): Any = when (this) {
        is None -> "none"
        is Certified -> mapOf("scheme" to scheme, "assurance_level" to assuranceLevel)
    }
}

/** Security properties reported by a Signer for a given key. */
data class SignerSecurityProperties(
    /** Key storage security levels — ISO 18045 AVA_VAN scale values. */
    val keyStorage: List<String>,
    /** User authentication methods supported. */
    val userAuthentication: List<String> = emptyList(),
    /** Certification status of the key storage (CS-04 §7.1.3, Annex C §C.3.1). */
    val certification: CertificationInfo = CertificationInfo.None,
    /** Authentication Method Reference values from the last sign operation. */
    val amr: List<String> = emptyList(),
)
