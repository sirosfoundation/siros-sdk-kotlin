package org.siros.sdk.credentials

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryCredentialStoreTest {

    @Test
    fun save_and_get_by_id_return_stored_credential() = runBlocking {
        val store = InMemoryCredentialStore()
        val credential = storedCredential(id = 1L, raw = "raw-1")

        store.save(credential)

        assertEquals(listOf(credential), store.getAll())
        assertEquals(credential, store.getById(1L))
    }

    @Test
    fun update_replaces_existing_credential_contents() = runBlocking {
        val store = InMemoryCredentialStore()
        store.save(storedCredential(id = 1L, raw = "raw-1"))

        store.update(
            storedCredential(
                id = 1L,
                raw = "raw-2",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
            )
        )

        val updated = store.getById(1L)
        assertEquals("raw-2", updated?.raw)
        assertEquals("urn:eu:pid:1", updated?.metadata?.vct)
    }

    @Test
    fun delete_removes_matching_credential_only() = runBlocking {
        val store = InMemoryCredentialStore()
        store.save(storedCredential(id = 1L))
        store.save(storedCredential(id = 2L))

        store.delete(1L)

        assertNull(store.getById(1L))
        assertEquals(listOf(2L), store.getAll().map { it.id })
    }

    @Test
    fun clear_removes_all_credentials_and_missing_reads_stay_null() = runBlocking {
        val store = InMemoryCredentialStore()
        store.save(storedCredential(id = 1L))

        store.clear()

        assertTrue(store.getAll().isEmpty())
        assertNull(store.getById(1L))
        assertNull(store.getById(99L))
    }

    @Test
    fun notification_id_persists_through_store() = runBlocking {
        val store = InMemoryCredentialStore()
        store.save(storedCredential(id = 1L, notificationId = "notif-123"))

        assertEquals("notif-123", store.getById(1L)?.notificationId)
    }

    @Test
    fun notification_id_round_trips_through_json() {
        val json = Json { encodeDefaults = false }
        val cred = storedCredential(id = 1L, notificationId = "notif-456")

        val text = json.encodeToString(StoredCredential.serializer(), cred)
        assertTrue(text.contains("\"notification_id\":\"notif-456\""))

        val decoded = json.decodeFromString(StoredCredential.serializer(), text)
        assertEquals("notif-456", decoded.notificationId)
    }

    @Test
    fun notification_id_defaults_to_null_and_is_omitted() {
        val json = Json { encodeDefaults = false }
        val cred = storedCredential(id = 1L)
        assertNull(cred.notificationId)

        val text = json.encodeToString(StoredCredential.serializer(), cred)
        assertFalse(text.contains("notification_id"))
    }

    private fun storedCredential(
        id: Long,
        raw: String = "raw",
        metadata: CredentialMetadata? = null,
        notificationId: String? = null,
    ) = StoredCredential(
        id = id,
        format = CredentialFormat.DC_SD_JWT.value,
        raw = raw,
        metadata = metadata,
        notificationId = notificationId,
        batchId = id,
        instanceId = 0,
    )
}
