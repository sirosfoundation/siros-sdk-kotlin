// Copyright 2026 SIROS Foundation. BSD-2-Clause License.
package org.siros.sdk.sample

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.siros.sdk.wallet.WmpJoinRecord
import java.io.File

/**
 * The sample's joined-group persistence: one JSON map of provider URL to
 * session + resumption token. Groups restore by resuming these sessions,
 * never by re-consuming a spent invitation nonce.
 *
 * Atomic writes (tmp + rename); a corrupt file answers empty.
 */
class JsonFileWmpJoinStore(dir: File) {
    private val file = File(dir, "wmp-joins.json")
    private val json = Json { ignoreUnknownKeys = true }
    private val lock = Any()

    @Serializable
    private data class Stored(
        val providerUrl: String,
        val sendUrl: String,
        val sseUrl: String,
        val sessionId: String,
        val resumptionToken: String,
        val groupId: String? = null,
        val groupName: String? = null,
        val asClientId: String? = null,
        val asClientSecret: String? = null,
    ) {
        fun record() = WmpJoinRecord(
            providerUrl,
            sendUrl,
            sseUrl,
            sessionId,
            resumptionToken,
            groupId,
            groupName,
            asClientId,
            asClientSecret,
        )
    }

    @Serializable
    private data class Doc(val joins: List<Stored> = emptyList())

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

    fun load(): List<WmpJoinRecord> = synchronized(lock) {
        read().joins.map { it.record() }
    }

    fun save(record: WmpJoinRecord) = synchronized(lock) {
        val state = read()
        val stored = Stored(
            record.providerUrl,
            record.sendUrl,
            record.sseUrl,
            record.sessionId,
            record.resumptionToken,
            record.groupId,
            record.groupName,
            record.asClientId,
            record.asClientSecret,
        )
        write(state.copy(joins = state.joins.filter { it.providerUrl != record.providerUrl } + stored))
    }

    fun remove(providerUrl: String) = synchronized(lock) {
        val state = read()
        write(state.copy(joins = state.joins.filter { it.providerUrl != providerUrl }))
    }

    fun clear() = synchronized(lock) {
        file.delete()
        Unit
    }
}
