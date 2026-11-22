package org.siros.sdk.wallet

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The wallet's group message store (issue #77): the inbox (the messages
 * the wallet's sessions received) and the outbox (its own sends) —
 * CLIENT-SIDE ONLY (never the backend: the relay is the Delivery
 * Service, wmp-mls.md §5 — it routes and queues, the plaintext and its
 * history live in the wallet).
 *
 * The seam: the SDK owns the plumbing ([SirosWallet] appends every
 * arrival, the apps render snapshots) and the STORE is app-supplied —
 * the app constructs its own persistence (its files, its database)
 * against this interface, exactly like the engine's [Host] port. The
 * privatedata Rust library lands here later: it implements this
 * interface, the app constructs it instead, nothing else moves.
 *
 * The cursors ride the same store (the `wmp.message.poll` `since`): a
 * persistent store means a restart resumes the read where it left off,
 * not from the top (the replay).
 */
interface WmpMessageStore {
    /** Append one message (idempotent by [WmpGroupMessage.messageId] when present). */
    fun append(message: WmpGroupMessage)

    /** The messages a session holds, newest first, up to [limit]. */
    fun load(backend: String, sessionId: String, limit: Int = 50): List<WmpGroupMessage>

    /** The poll cursor (the last `wmp_message_id` answered), null when none. */
    fun cursor(backend: String, sessionId: String): String?

    /** Set the poll cursor. */
    fun setCursor(backend: String, sessionId: String, since: String)

    /** Keep at most [keep] messages per session (the retention). */
    fun prune(keep: Int = 50)

    /** Drop everything (the logout/relogin path). */
    fun clear()
}

/** The message id's dedup key (absent ids fall back to the text). */
internal fun WmpGroupMessage.storeKey() = "${backend}:${sessionId}:${messageId ?: text}"

/**
 * The in-memory store (the SDK's default when the app supplies none):
 * the whole inbox lives in a map, gone with the process. The app that
 * wants persistence constructs its own [WmpMessageStore] (its files,
 * its database) and passes it in the config.
 */
class InMemoryWmpMessageStore : WmpMessageStore {
    private val lock = Any()
    private val boxes = HashMap<String, MutableList<WmpGroupMessage>>()
    private val cursors = HashMap<String, String>()

    override fun append(message: WmpGroupMessage) = synchronized(lock) {
        val box = boxes.getOrPut("${message.backend}:${message.sessionId}") { mutableListOf() }
        if (box.none { it.storeKey() == message.storeKey() }) box.add(0, message)
    }

    override fun load(backend: String, sessionId: String, limit: Int): List<WmpGroupMessage> =
        synchronized(lock) { boxes["$backend:$sessionId"].orEmpty().take(limit) }

    override fun cursor(backend: String, sessionId: String): String? =
        synchronized(lock) { cursors["$backend:$sessionId"] }

    override fun setCursor(backend: String, sessionId: String, since: String) =
        synchronized(lock) { cursors["$backend:$sessionId"] = since }

    override fun prune(keep: Int) = synchronized(lock) {
        boxes.values.forEach { box -> if (box.size > keep) box.subList(keep, box.size).clear() }
    }

    override fun clear() = synchronized(lock) {
        boxes.clear()
        cursors.clear()
    }
}