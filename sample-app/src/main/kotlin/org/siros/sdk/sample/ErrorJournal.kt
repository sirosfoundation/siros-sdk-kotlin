// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File

/**
 * One journaled event the user can revisit — an error or an informational
 * message (the journal covers both; the screen filters by [severity]).
 * [title] names the class of event, [summary] is the one-line text the
 * snackbar showed, and [details] is the technical trail (the exception, the
 * flow id) the user must CHOOSE to see — never shown by default. [contact]
 * and [context] are reserved for support routing (a help desk address, the
 * verifier/issuer the flow involved); they are null until a source provides
 * them, and the journal renders them only when present.
 */
@Serializable
data class ErrorJournalEntry(
    val id: Long,
    val timestamp: Long,
    val title: String,
    val summary: String,
    val severity: JournalSeverity = JournalSeverity.ERROR,
    val details: String? = null,
    val contact: String? = null,
    val context: String? = null,
)

/** A journal entry's class: a failure, or an informational message. */
@Serializable
enum class JournalSeverity { ERROR, INFO }

/**
 * The last N messages, newest first — the journal behind the "Recent
 * messages" menu row. Errors and info messages alike used to be a snackbar
 * and nothing else: they auto-dismissed in seconds and a no-match was
 * indistinguishable from any other failure, so the user could never read
 * what happened. The journal keeps them — **persisted across app restarts**
 * (a JSON file in the app's private storage; the ViewModel supplies the
 * [Context] on construction) — hard capped at [JOURNAL_MAX_LENGTH] (the
 * oldest entry falls out) — and the screen reveals the technical details
 * only on request, with severity filters (errors / info / all).
 *
 * The persistence is fail-soft: a corrupt or unreadable store starts an
 * empty journal (a write failure drops the persist, never the message —
 * the in-memory entry stands whatever the disk does).
 */
class ErrorJournal(private val store: File? = null) {
    private val _entries = MutableStateFlow<List<ErrorJournalEntry>>(load())

    /** The kept entries, newest first. */
    val entries: StateFlow<List<ErrorJournalEntry>> = _entries.asStateFlow()

    /**
     * One new entry. [cause], when the failure came from an exception, is
     * rendered into [ErrorJournalEntry.details] (its class, message and stack)
     * so the summary can stay human.
     */
    fun record(
        timestamp: Long = System.currentTimeMillis(),
        title: String,
        summary: String,
        severity: JournalSeverity = JournalSeverity.ERROR,
        details: String? = null,
        cause: Throwable? = null,
        contact: String? = null,
        context: String? = null,
    ) {
        val technical = buildList {
            details?.let { add(it) }
            cause?.let { c ->
                add("${c.javaClass.name}: ${c.message ?: "(no message)"}")
                c.stackTrace.take(STACK_FRAMES).forEach { add("  at $it") }
            }
        }.joinToString("\n").ifEmpty { null }
        val entry = ErrorJournalEntry(
            id = nextId(),
            timestamp = timestamp,
            title = title,
            summary = summary,
            severity = severity,
            details = technical,
            contact = contact,
            context = context,
        )
        _entries.value = (listOf(entry) + _entries.value).take(JOURNAL_MAX_LENGTH)
        persist()
    }

    /** Empties the journal (the journal screen's clear action). */
    fun clear() {
        _entries.value = emptyList()
        persist()
    }

    /** The persisted entries, or an empty list when nothing is readable. */
    private fun load(): List<ErrorJournalEntry> =
        store?.takeIf { it.isFile }?.let { file ->
            try {
                json.decodeFromString(ListSerializer(ErrorJournalEntry.serializer()), file.readText())
            } catch (e: Exception) {
                null // corrupt/unreadable: start empty, never crash on boot
            }
        }.orEmpty()

    /** Writes the current entries, fail-soft (a failure drops the persist, never the message). */
    private fun persist() {
        val file = store ?: return
        try {
            val text = json.encodeToString(ListSerializer(ErrorJournalEntry.serializer()), _entries.value)
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(text) // atomic-ish: write then rename, a crash never truncates the store
            if (!tmp.renameTo(file)) {
                tmp.copyTo(file, overwrite = true)
                tmp.delete()
            }
        } catch (e: Exception) {
            android.util.Log.w("ErrorJournal", "persisting the journal failed (${e.javaClass.simpleName}: ${e.message})")
        }
    }

    private var lastId = _entries.value.maxOfOrNull { it.id } ?: 0L
    private fun nextId(): Long = ++lastId

    private companion object {
        /** How many stack frames an entry's technical details carry. */
        const val STACK_FRAMES = 12

        /** The hard cap: the last 10 messages, the oldest falls out. */
        const val JOURNAL_MAX_LENGTH = 10

        /** The journal store's JSON codec: member defaults tolerated (an older store's missing fields). */
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    }
}