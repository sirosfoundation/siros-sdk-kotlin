// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

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
enum class JournalSeverity { ERROR, INFO }

/**
 * The last N messages, newest first — the journal behind the "Recent
 * messages" menu row. Errors and info messages alike used to be a snackbar
 * and nothing else: they auto-dismissed in seconds and a no-match was
 * indistinguishable from any other failure, so the user could never read
 * what happened. The journal keeps them (in memory for the session, hard
 * capped at [JOURNAL_MAX_LENGTH] — the oldest entry falls out) and the
 * screen reveals the technical details only on request, with severity
 * filters (errors / info / all).
 */
class ErrorJournal {
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

        /** The hard cap: the last 10 messages, the oldest falls out. */
        const val JOURNAL_MAX_LENGTH = 10
    }
}

/** The Settings choices for the journal length (kept for future use; the cap is fixed at 10 today). */
val ERROR_JOURNAL_LENGTH_CHOICES = listOf(3, 5, 10, 25)