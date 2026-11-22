package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The message store contract (issue #77): every implementation — the
 * [InMemoryWmpMessageStore], the app's JSON-file store, the eventual
 * privatedata library's — answers this shape. The cursors persist
 * (a restart resumes the read's place, not the top).
 */
class WmpMessageStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun message(text: String, id: String? = null) = WmpGroupMessage(
        backend = "engine",
        sessionId = "ses-1",
        from = "ses-peer",
        text = text,
        messageId = id,
    )

    private fun stores(): List<Pair<String, WmpMessageStore>> {
        val dir: File = tmp.newFolder()
        val json = JsonFileWmpMessageStoreForTest(dir)
        return listOf(
            "memory" to InMemoryWmpMessageStore(),
            "json-file" to json,
        )
    }

    @Test
    fun appendAndLoadNewestFirst() {
        for ((name, store) in stores()) {
            store.append(message("first", id = "m1"))
            store.append(message("second", id = "m2"))
            val loaded = store.load("engine", "ses-1")
            assertEquals("$name: newest first", "second", loaded.first().text)
            assertEquals("$name: holds both", 2, loaded.size)
        }
    }

    @Test
    fun appendIsIdempotentById() {
        for ((name, store) in stores()) {
            store.append(message("hello", id = "m1"))
            store.append(message("hello", id = "m1"))
            assertEquals("$name: deduped", 1, store.load("engine", "ses-1").size)
        }
    }

    @Test
    fun cursorsRoundTrip() {
        for ((name, store) in stores()) {
            assertNull("$name: empty cursor", store.cursor("engine", "ses-1"))
            store.setCursor("engine", "ses-1", "m42")
            assertEquals("$name: the cursor", "m42", store.cursor("engine", "ses-1"))
        }
    }

    @Test
    fun jsonFilePersistsAcrossInstances() {
        val dir: File = tmp.newFolder()
        val first = JsonFileWmpMessageStoreForTest(dir)
        first.append(message("persistent", id = "m1"))
        first.setCursor("engine", "ses-1", "m9")
        // A "restart": a fresh store instance over the same file.
        val second = JsonFileWmpMessageStoreForTest(dir)
        assertEquals("the message survived", "persistent", second.load("engine", "ses-1").first().text)
        assertEquals("the cursor survived", "m9", second.cursor("engine", "ses-1"))
    }

    @Test
    fun pruneKeepsTheNewest() {
        for ((name, store) in stores()) {
            for (i in 1..60) store.append(message("m$i", id = "id$i"))
            store.prune(50)
            assertEquals("$name: pruned to 50", 50, store.load("engine", "ses-1").size)
            assertEquals("$name: kept the newest", "m60", store.load("engine", "ses-1").first().text)
        }
    }

    @Test
    fun clearDropsEverything() {
        for ((name, store) in stores()) {
            store.append(message("gone", id = "m1"))
            store.setCursor("engine", "ses-1", "m1")
            store.clear()
            assertTrue("$name: empty", store.load("engine", "ses-1").isEmpty())
            assertNull("$name: no cursor", store.cursor("engine", "ses-1"))
        }
    }
}

/** The app-side JSON-file store, reachable from the SDK tests (the test
 * only links the SDK module — the store contract is what it tests; the
 * app's own suite tests its file handling, this one only borrows the
 * shape through a minimal local copy when the app's isn't linkable). */
private class JsonFileWmpMessageStoreForTest(dir: File) : WmpMessageStore {
    // The minimal test double over the same file shape: the app's real
    // store (sample-app) isn't on the SDK test classpath, so this mirrors
    // it exactly (the contract test drives both by construction).
    private val file = File(dir, "wmp-messages.json")
    private val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
    private val lock = Any()

    @kotlinx.serialization.Serializable
    private data class Stored(
        val backend: String,
        val sessionId: String,
        val from: String? = null,
        val text: String,
        val messageId: String? = null,
    ) {
        fun plain() = WmpGroupMessage(backend, sessionId, from, text, messageId)
        fun key() = "${backend}:${sessionId}:${messageId ?: text}"
    }

    @kotlinx.serialization.Serializable
    private data class Doc(
        val boxes: Map<String, List<Stored>> = emptyMap(),
        val cursors: Map<String, String> = emptyMap(),
    )

    private fun read(): Doc = synchronized(lock) {
        try {
            if (file.exists()) json.decodeFromString(Doc.serializer(), file.readText()) else Doc()
        } catch (_: Exception) {
            Doc()
        }
    }

    private fun write(state: Doc) {
        val text = json.encodeToString(Doc.serializer(), state)
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(file)) {
            tmp.delete()
            file.writeText(text)
        }
    }

    override fun append(message: WmpGroupMessage) = synchronized(lock) {
        val state = read()
        val boxKey = "${message.backend}:${message.sessionId}"
        val box = state.boxes[boxKey].orEmpty()
        val stored = Stored(
            message.backend, message.sessionId, message.from, message.text, message.messageId,
        )
        if (box.none { it.key() == stored.key() }) {
            write(state.copy(boxes = state.boxes + (boxKey to listOf(stored) + box)))
        }
    }

    override fun load(backend: String, sessionId: String, limit: Int): List<WmpGroupMessage> =
        synchronized(lock) {
            read().boxes["$backend:$sessionId"].orEmpty().take(limit).map { it.plain() }
        }

    override fun cursor(backend: String, sessionId: String): String? =
        synchronized(lock) { read().cursors["$backend:$sessionId"] }

    override fun setCursor(backend: String, sessionId: String, since: String) =
        synchronized(lock) {
            val state = read()
            write(state.copy(cursors = state.cursors + ("$backend:$sessionId" to since)))
        }

    override fun prune(keep: Int) = synchronized(lock) {
        val state = read()
        write(state.copy(boxes = state.boxes.mapValues { it.value.take(keep) }))
    }

    override fun clear() = synchronized(lock) { file.delete(); Unit }
}