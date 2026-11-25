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
                asClientId = "client-from-the-original-join",
                asClientSecret = "client-secret",
            )
            store.save(record)

            // A resume rotates the token; the next restore must use the new one.
            store.save(record.copy(resumptionToken = "token-2"))
            val loaded = JsonFileWmpJoinStore(dir).load()
            assertEquals(1, loaded.size)
            assertEquals("token-2", loaded.single().resumptionToken)
            assertEquals("Echo re-run", loaded.single().groupName)
            assertEquals("client-from-the-original-join", loaded.single().asClientId)
            assertEquals("client-secret", loaded.single().asClientSecret)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aRecordFromBeforeClientPersistenceStillLoads() {
        val dir = File(System.getProperty("java.io.tmpdir"), "wmp-join-store-legacy-${System.nanoTime()}")
        dir.mkdirs()
        try {
            File(dir, "wmp-joins.json").writeText(
                """{"joins":[{"providerUrl":"https://sirosid-gdc-wmp-mcp.fly.dev","sendUrl":"https://sirosid-gdc-wmp-mcp.fly.dev/wmp","sseUrl":"https://sirosid-gdc-wmp-mcp.fly.dev/wmp/events","sessionId":"ses-89e292333cb81607734436da10c57784","resumptionToken":"stored-token","groupId":"ses-fedd4da1804e7cb6f26e5cdcd245de6c","groupName":"meadow-mirage"}]}""",
            )
            val record = JsonFileWmpJoinStore(dir).load().single()
            assertEquals("ses-89e292333cb81607734436da10c57784", record.sessionId)
            assertEquals("stored-token", record.resumptionToken)
            assertEquals(null, record.asClientId)
            assertEquals(null, record.asClientSecret)
        } finally {
            dir.deleteRecursively()
        }
    }
}
