package org.siros.sdk.passkey

import kotlinx.serialization.Serializable

/**
 * Stored passkey metadata. Private keys are managed by the platform
 * (Android Keystore / Credential Manager) — we only store metadata
 * for credential listing and selection.
 */
@Serializable
data class PasskeyEntry(
    val credentialId: String,
    val rpId: String,
    val userHandle: String,
    val userName: String,
    val userDisplayName: String,
    val createdAt: Long,
)

/**
 * Persistent storage for passkey metadata.
 * The SDK provides a SharedPreferences-based default implementation.
 * SDK consumers can provide their own.
 */
interface PasskeyStore {
    suspend fun getAll(): List<PasskeyEntry>
    suspend fun getByRpId(rpId: String): List<PasskeyEntry>
    suspend fun save(entry: PasskeyEntry)
    suspend fun delete(credentialId: String)
    suspend fun clear()
}
