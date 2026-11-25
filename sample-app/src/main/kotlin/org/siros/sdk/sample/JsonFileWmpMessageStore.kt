// Copyright 2026 SIROS Foundation. BSD-2-Clause License.
package org.siros.sdk.sample

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.siros.sdk.wallet.WmpGroupMessage
import org.siros.sdk.wallet.WmpMessageStore
import java.io.File

/**
 * Issue #77 — the sample's group message store: the inbox and the cursors
 * persisted to one JSON file (the wallet's own storage,
 * `filesDir/wmp-messages.json`).
 *
 * The SDK owns the seam ([WmpMessageStore]); the app owns its persistence
 * — this is the sample's (a real app would use its own database; the
 * privatedata library lands behind the same interface later).
 *
 * Atomic writes (tmp + rename) so a crash never tears the inbox; a
 * corrupt file answers empty (the next append rewrites it whole) —
 * never a crash. Thread-safe (a lock around the file).
 */
class JsonFileWmpMessageStore(dir: File) : WmpMessageStore {
    private val file = File(dir, "wmp-messages.json")
    private val json = Json { ignoreUnknownKeys = true }
    private val lock = Any()

    @Serializable
    private data class Stored(
        val backend: String,
        val sessionId: String,
        val from: String? = null,
        val text: String,
        val messageId: String? = null,
        // The direction flag (the trace's →/← marker): absent in records
        // written before it existed — `false` (inbound) is the correct
        // reading for those, so a plain default suffices.
        val outbound: Boolean = false,
    ) {
        fun plain() = WmpGroupMessage(backend, sessionId, from, text, messageId, outbound)
        fun key() = "${backend}:${sessionId}:${messageId ?: text}"
    }

    @Serializable
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
            message.outbound,
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