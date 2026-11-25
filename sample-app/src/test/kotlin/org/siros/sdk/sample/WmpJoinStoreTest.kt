package org.siros.sdk.sample

import org.junit.Assert.assertEquals
import org.junit.Test
import org.siros.sdk.wallet.WmpJoinRecord
import java.io.File

class WmpJoinStoreTest {
    @Test
    fun aJoinedGroupAndItsLatestTokenRoundTrip() {
        val dir = File(System.getProperty("java.io.tmpdir"), "wmp-join-store-test-${System.nanoTime()}")
        dir.mkdirs()
        try {
            val store = JsonFileWmpJoinStore(dir)
            val record = WmpJoinRecord(
                providerUrl = "https://relay.example.com",
                sendUrl = "https://relay.example.com/wmp",
                sseUrl = "https://relay.example.com/wmp/events",
                sessionId = "ses-group-1",
                resumptionToken = "token-1",
                groupId = "group-1",
                groupName = "Echo re-run",
            )
            store.save(record)

            // A resume rotates the token; the next restore must use the new one.
            store.save(record.copy(resumptionToken = "token-2"))
            val loaded = JsonFileWmpJoinStore(dir).load()
            assertEquals(1, loaded.size)
            assertEquals("token-2", loaded.single().resumptionToken)
            assertEquals("Echo re-run", loaded.single().groupName)
        } finally {
            dir.deleteRecursively()
        }
    }
}
