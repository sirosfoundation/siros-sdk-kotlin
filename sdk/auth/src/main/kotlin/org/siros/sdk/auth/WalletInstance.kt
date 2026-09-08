package org.siros.sdk.auth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * One wallet installation as the backend sees it (go-wallet-backend
 * `domain.WalletInstance`): registered when the installation first obtains a
 * Wallet Instance Attestation and identified by the JWK thumbprint of its
 * instance key. Lifecycle (SID-AUTH-06): `active` → `suspended` is reversible
 * and only blocks; `revoked` is terminal; revoking the last non-revoked
 * instance deactivates the wallet and erases its data server-side.
 */
@Serializable
data class WalletInstance(
    val id: String,
    @SerialName("tenant_id") val tenantId: String = "",
    @SerialName("user_id") val userId: String? = null,
    val status: String,
    @SerialName("wscd_type") val wscdType: String = "",
    /**
     * base64url WebAuthn credential id of the passkey this instance logs in
     * with, when the client reported it at WIA generation. Lets an app match
     * an instance to a passkey; absent for instances attested by older SDKs.
     */
    @SerialName("credential_id") val credentialId: String? = null,
    @SerialName("attestation_source") val attestationSource: String = "",
    @SerialName("last_attested_at") val lastAttestedAt: String? = null,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null,
    @SerialName("status_reason") val statusReason: String? = null,
) {
    companion object {
        const val STATUS_ACTIVE = "active"
        const val STATUS_SUSPENDED = "suspended"
        const val STATUS_REVOKED = "revoked"
    }
}
