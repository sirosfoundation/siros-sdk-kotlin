// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * A passkey registered to an account — stores the credential ID and PRF salt
 * needed to re-derive the encryption key on login.
 *
 * Mirrors the frontend's `WebauthnPrfSaltInfo`.
 */
@Serializable
data class CachedPasskey(
    /** Base64url-encoded WebAuthn credential ID. */
    @SerialName("credential_id") val credentialId: String,
    /** Base64-encoded PRF salt used during registration. */
    @SerialName("prf_salt") val prfSalt: String,
    /** Optional user-assigned nickname (e.g. "My YubiKey"). */
    val nickname: String = "",
)

/**
 * A cached account entry that persists across logouts.
 *
 * Mirrors the frontend's `CachedUser`. The account registry stores an
 * array of these — they survive logout and allow the login screen to
 * show "Welcome back" with a list of known accounts.
 */
@Serializable
data class CachedAccount(
    /** User ID from the AS (UUID). */
    @SerialName("user_id") val userId: String,
    /** Tenant ID this account belongs to. */
    @SerialName("tenant_id") val tenantId: String,
    /** User's display name (set at registration). */
    @SerialName("display_name") val displayName: String,
    /** Backend URL this account was registered on. */
    @SerialName("backend_url") val backendUrl: String,
    /** Registered passkeys for this account. */
    val passkeys: List<CachedPasskey> = emptyList(),
    /** HKDF salt used for key derivation (base64). */
    @SerialName("hkdf_salt") val hkdfSalt: String = "",
    /** HKDF info string (base64). */
    @SerialName("hkdf_info") val hkdfInfo: String = "",
) {
    /** Unique account identifier: `tenantId:userId`. */
    val accountId: String get() = "$tenantId:$userId"

    /** True if this account has at least one passkey with a PRF salt. */
    val hasPrfKeys: Boolean get() = passkeys.any { it.prfSalt.isNotEmpty() }
}
