// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.Json
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.KeystoreManager
import timber.log.Timber

/**
 * [CredentialStore] backed by the PRF-encrypted keystore container.
 *
 * Credentials are serialised to JSON and stored inside the same JWE
 * envelope as the wallet's private keys. This matches the wallet-frontend
 * pattern where all sensitive data (keys + credentials) is encrypted
 * with the PRF-derived key and synchronised to the backend as `privateData`.
 *
 * Advantages:
 * - Credentials are bound to the user's passkey (PRF output)
 * - Single encrypted blob for cross-device sync via the backend
 * - Same security model as the wallet-frontend
 *
 * This is the default [CredentialStore] used by [SirosWallet].
 * Integrators can supply their own implementation via [WalletConfig.credentialStore].
 */
internal class KeystoreBackedCredentialStore(
    private val keystore: KeystoreManager,
    private val json: Json = Json { ignoreUnknownKeys = true },
) : CredentialStore {

    override suspend fun getAll(): List<StoredCredential> {
        if (!keystore.isUnlocked) return emptyList()
        return keystore.getAllCredentials().values.mapNotNull { raw ->
            try {
                json.decodeFromString(StoredCredential.serializer(), raw)
            } catch (e: Exception) {
                Timber.w(e, "Failed to deserialize credential")
                null
            }
        }
    }

    override suspend fun getById(id: Long): StoredCredential? {
        if (!keystore.isUnlocked) return null
        val raw = keystore.getCredential(id) ?: return null
        return try {
            json.decodeFromString(StoredCredential.serializer(), raw)
        } catch (e: Exception) {
            Timber.w(e, "Failed to deserialize credential $id")
            null
        }
    }

    override suspend fun save(credential: StoredCredential) {
        if (!keystore.isUnlocked) {
            Timber.w("Cannot save credential: keystore locked")
            return
        }
        val raw = json.encodeToString(StoredCredential.serializer(), credential)
        keystore.saveCredential(credential.id, raw)
    }

    override suspend fun update(credential: StoredCredential) {
        save(credential)
    }

    override suspend fun delete(id: Long) {
        if (!keystore.isUnlocked) return
        keystore.deleteCredential(id)
    }

    override suspend fun clear() {
        if (!keystore.isUnlocked) return
        keystore.clearCredentials()
    }
}
