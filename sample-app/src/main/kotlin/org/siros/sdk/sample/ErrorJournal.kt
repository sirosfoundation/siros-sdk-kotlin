// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * One journaled failure the user can revisit. [title] names the class of event,
 * [summary] is the one-line text the snackbar showed, and [details] is the
 * technical trail (the exception, the flow id) the user must CHOOSE to see —
 * never shown by default. [contact] and [context] are reserved for support
 * routing (a help desk address, the verifier/issuer the flow involved); they
 * are null until a source provides them, and the journal renders them only
 * when present.
 */
data class ErrorJournalEntry(
    val id: Long,
    val timestamp: Long,
    val title: String,
    val summary: String,
    val details: String? = null,
    val contact: String? = null,
    val context: String? = null,
)

/**
 * The last N failures, newest first — the error journal behind the "Recent
 * errors" menu row. Errors used to be a snackbar and nothing else: they
 * auto-dismissed in seconds and a no-match was indistinguishable from any
 * other failure, so the user could never read what happened. The journal keeps
 * them (in memory for the session; the length is configurable, default
 * [DEFAULT_ERROR_JOURNAL_LENGTH]) and the screen reveals the technical details
 * only on request.
 *
 * @param maxLengthProvider read on every [record] so a settings change
 * applies to subsequent errors without rebuilding anything.
 */
class ErrorJournal(
    private val maxLengthProvider: () -> Int = { DEFAULT_ERROR_JOURNAL_LENGTH },
) {
    private val _entries = MutableStateFlow<List<ErrorJournalEntry>>(emptyList())

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
            details = technical,
            contact = contact,
            context = context,
        )
        _entries.value = (listOf(entry) + _entries.value).take(maxLengthProvider().coerceAtLeast(1))
    }

    /** Empties the journal (the journal screen's clear action). */
    fun clear() {
        _entries.value = emptyList()
    }

    private var lastId = 0L
    private fun nextId(): Long = ++lastId

    private companion object {
        /** How many stack frames an entry's technical details carry. */
        const val STACK_FRAMES = 12
    }
}

/** The default journal length, overridable in Settings. */
const val DEFAULT_ERROR_JOURNAL_LENGTH = 5

/** The Settings choices for the journal length. */
val ERROR_JOURNAL_LENGTH_CHOICES = listOf(3, 5, 10, 25)