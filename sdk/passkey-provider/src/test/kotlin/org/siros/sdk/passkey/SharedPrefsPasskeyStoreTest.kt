package org.siros.sdk.passkey

import android.content.SharedPreferences
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SharedPrefsPasskeyStoreTest {

    @Test
    fun getAll_returns_empty_when_store_is_uninitialized() = runBlocking {
        val (prefs, _) = mockSharedPreferences()
        val store = SharedPrefsPasskeyStore(prefs, testOnly = true)

        assertTrue(store.getAll().isEmpty())
    }

    @Test
    fun save_persists_and_replaces_existing_entries_by_credential_id() = runBlocking {
        val (prefs, values) = mockSharedPreferences()
        val store = SharedPrefsPasskeyStore(prefs, testOnly = true)

        store.save(passkeyEntry(credentialId = "cred-1", userDisplayName = "Alice"))
        store.save(passkeyEntry(credentialId = "cred-1", userDisplayName = "Bob"))

        val entries = store.getAll()
        assertEquals(1, entries.size)
        assertEquals("Bob", entries.single().userDisplayName)
        assertTrue(values.containsKey("entries"))
    }

    @Test
    fun getByRpId_filters_saved_entries() = runBlocking {
        val (prefs, _) = mockSharedPreferences()
        val store = SharedPrefsPasskeyStore(prefs, testOnly = true)
        store.save(passkeyEntry(credentialId = "cred-1", rpId = "issuer.example.com"))
        store.save(passkeyEntry(credentialId = "cred-2", rpId = "wallet.example.com"))

        val entries = store.getByRpId("issuer.example.com")

        assertEquals(listOf("cred-1"), entries.map { it.credentialId })
    }

    @Test
    fun delete_removes_matching_entry() = runBlocking {
        val (prefs, _) = mockSharedPreferences()
        val store = SharedPrefsPasskeyStore(prefs, testOnly = true)
        store.save(passkeyEntry(credentialId = "cred-1"))
        store.save(passkeyEntry(credentialId = "cred-2"))

        store.delete("cred-1")

        assertEquals(listOf("cred-2"), store.getAll().map { it.credentialId })
    }

    @Test
    fun clear_removes_all_entries() = runBlocking {
        val (prefs, values) = mockSharedPreferences()
        val store = SharedPrefsPasskeyStore(prefs, testOnly = true)
        store.save(passkeyEntry())

        store.clear()

        assertTrue(store.getAll().isEmpty())
        assertTrue("entries" !in values)
    }

    private fun passkeyEntry(
        credentialId: String = "cred-1",
        rpId: String = "issuer.example.com",
        userDisplayName: String = "Alice Example",
    ) = PasskeyEntry(
        credentialId = credentialId,
        rpId = rpId,
        userHandle = "user-handle-$credentialId",
        userName = "user-$credentialId",
        userDisplayName = userDisplayName,
        createdAt = 1_715_000_000L,
    )

    private fun mockSharedPreferences(): Pair<SharedPreferences, MutableMap<String, String?>> {
        val values = mutableMapOf<String, String?>()
        val editor = mockk<SharedPreferences.Editor>()
        val preferences = mockk<SharedPreferences>()

        every { preferences.getString(any(), any()) } answers {
            values[firstArg<String>()] ?: secondArg()
        }
        every { preferences.edit() } returns editor
        every { editor.putString(any(), any()) } answers {
            values[firstArg<String>()] = secondArg()
            editor
        }
        every { editor.remove(any()) } answers {
            values.remove(firstArg<String>())
            editor
        }
        every { editor.apply() } answers { }

        return preferences to values
    }
}
