package org.siros.sdk.passkey

import android.content.Context
import android.content.SharedPreferences
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer

/**
 * SharedPreferences-backed passkey metadata store.
 * Stores passkey entries as JSON in the app's private storage.
 */
class SharedPrefsPasskeyStore(
    context: Context,
    private val json: Json = Json { ignoreUnknownKeys = true },
) : PasskeyStore {

    private val prefs: SharedPreferences = context.getSharedPreferences(
        PREFS_NAME, Context.MODE_PRIVATE
    )

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
