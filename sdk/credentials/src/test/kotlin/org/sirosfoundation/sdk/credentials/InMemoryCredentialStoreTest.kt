package org.sirosfoundation.sdk.credentials

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryCredentialStoreTest {

    @Test
    fun save_and_get_by_id_return_stored_credential() = runBlocking {
        val store = InMemoryCredentialStore()
        val credential = storedCredential(id = "cred-1", raw = "raw-1")

        store.save(credential)

        assertEquals(listOf(credential), store.getAll())
        assertEquals(credential, store.getById("cred-1"))
    }

    @Test
    fun update_replaces_existing_credential_contents() = runBlocking {
        val store = InMemoryCredentialStore()
        store.save(storedCredential(id = "cred-1", raw = "raw-1"))

        store.update(
            storedCredential(
                id = "cred-1",
                raw = "raw-2",
                metadata = CredentialMetadata(vct = "urn:eu:pid:1"),
            )
        )

        val updated = store.getById("cred-1")
        assertEquals("raw-2", updated?.raw)
        assertEquals("urn:eu:pid:1", updated?.metadata?.vct)
    }

    @Test
    fun delete_removes_matching_credential_only() = runBlocking {
        val store = InMemoryCredentialStore()
        store.save(storedCredential(id = "cred-1"))
        store.save(storedCredential(id = "cred-2"))

        store.delete("cred-1")

        assertNull(store.getById("cred-1"))
        assertEquals(listOf("cred-2"), store.getAll().map { it.id })
    }

    @Test
    fun clear_removes_all_credentials_and_missing_reads_stay_null() = runBlocking {
        val store = InMemoryCredentialStore()
        store.save(storedCredential(id = "cred-1"))

        store.clear()

        assertTrue(store.getAll().isEmpty())
        assertNull(store.getById("cred-1"))
        assertNull(store.getById("missing"))
    }

    private fun storedCredential(
        id: String,
        raw: String = "raw",
        metadata: CredentialMetadata? = null,
    ) = StoredCredential(
        id = id,
        format = CredentialFormat.DC_SD_JWT.value,
        raw = raw,
        metadata = metadata,
    )
}
