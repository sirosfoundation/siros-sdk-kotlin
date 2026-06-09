package org.sirosfoundation.sdk.passkey

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer

/**
 * Encrypted SharedPreferences-backed passkey metadata store.
 *
 * All passkey metadata (credential IDs, RP IDs, user handles) is encrypted
 * at rest using AES-256-GCM with a key protected by the Android Keystore.
 */
class SharedPrefsPasskeyStore private constructor(
    private val prefs: SharedPreferences,
    private val json: Json,
) : PasskeyStore {

    /**
     * Creates a store backed by [EncryptedSharedPreferences].
     */
    constructor(
        context: Context,
        json: Json = Json { ignoreUnknownKeys = true },
    ) : this(
        prefs = EncryptedSharedPreferences.create(
            PREFS_NAME,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context.applicationContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        ),
        json = json,
    )

    /**
     * Creates a store backed by the supplied [SharedPreferences] (for testing).
     */
    internal constructor(
        prefs: SharedPreferences,
        json: Json = Json { ignoreUnknownKeys = true },
        @Suppress("UNUSED_PARAMETER") testOnly: Boolean = true,
    ) : this(prefs, json)

    override suspend fun getAll(): List<PasskeyEntry> {
        val raw = prefs.getString(KEY_ENTRIES, null) ?: return emptyList()
        return json.decodeFromString(ListSerializer(PasskeyEntry.serializer()), raw)
    }

    override suspend fun getByRpId(rpId: String): List<PasskeyEntry> {
        return getAll().filter { it.rpId == rpId }
    }

    override suspend fun save(entry: PasskeyEntry) {
        val entries = getAll().toMutableList()
        entries.removeAll { it.credentialId == entry.credentialId }
        entries.add(entry)
        persist(entries)
    }

    override suspend fun delete(credentialId: String) {
        val entries = getAll().toMutableList()
        entries.removeAll { it.credentialId == credentialId }
        persist(entries)
    }

    override suspend fun clear() {
        prefs.edit().remove(KEY_ENTRIES).apply()
    }

    private fun persist(entries: List<PasskeyEntry>) {
        val raw = json.encodeToString(ListSerializer(PasskeyEntry.serializer()), entries)
        prefs.edit().putString(KEY_ENTRIES, raw).apply()
    }

    companion object {
        private const val PREFS_NAME = "siros_passkeys"
        private const val KEY_ENTRIES = "entries"
    }
}
