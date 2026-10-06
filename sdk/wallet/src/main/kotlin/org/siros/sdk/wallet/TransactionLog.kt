// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/** How an SCA presentation attempt ended (EC TS12 v1.0.1 5.3 covers successful and failed attempts). */
@Serializable
enum class TransactionOutcome {
    /** The user confirmed and a presentation was produced. */
    @SerialName("consented") CONSENTED,

    /** The user declined. */
    @SerialName("declined") DECLINED,

    /** The wallet refused the request; see [TransactionLogEntry.reason]. */
    @SerialName("refused") REFUSED,
}

/**
 * One SCA presentation attempt, as EC TS12 v1.0.1 5.3 requires the wallet to
 * record it. Only the items 5.3 names are kept, never the full payload.
 *
 * @property transactionId `payload.transaction_id`; `null` when the request was
 *   refused before it could be read.
 * @property transactionType the transaction data `type`.
 * @property typeName for the four built-in types, the name 5.3 prescribes
 *   ("Payment Confirmation", "Login, Risk-based Authentication", "Payment
 *   Account Information Access", "E-mandate"); `null` otherwise.
 * @property entities the relevant entity names that are present, keyed
 *   `payee`, `pisp`, `service`, `aisp` (for an e-mandate, the names inside its
 *   `payment_payload`).
 * @property verifier the verifier as the wallet identified it.
 * @property credential display name of the SCA attestation.
 * @property reason for [TransactionOutcome.REFUSED] and [TransactionOutcome.DECLINED]: the
 *   [org.siros.sdk.credentials.TransactionDataReason] code.
 */
@Serializable
data class TransactionLogEntry(
    @SerialName("transaction_id") val transactionId: String?,
    @SerialName("transaction_type") val transactionType: String?,
    @SerialName("type_name") val typeName: String? = null,
    val entities: Map<String, String> = emptyMap(),
    val verifier: String? = null,
    val credential: String? = null,
    @SerialName("timestamp_millis") val timestampMillis: Long,
    val outcome: TransactionOutcome,
    val reason: String? = null,
)

/**
 * Where SCA attempts are recorded (EC TS12 5.3). The host app lists
 * [entries]. The default store keeps them in encrypted app-private storage.
 */
interface TransactionLogStore {
    /** Records [entry]. Must not throw for a full or unavailable store: logging never blocks a presentation decision. */
    suspend fun append(entry: TransactionLogEntry)

    /** All entries, newest first. */
    suspend fun entries(): List<TransactionLogEntry>

    /** Removes every entry. */
    suspend fun clear()
}

/**
 * A [TransactionLogStore] over one string slot of durable storage, holding a
 * JSON array capped at [maxEntries] (oldest dropped). Concurrency-safe.
 */
class JsonTransactionLogStore(
    private val read: () -> String?,
    private val write: (String?) -> Unit,
    private val maxEntries: Int = 500,
) : TransactionLogStore {
    private val json = Json { ignoreUnknownKeys = true }
    private val serializer = ListSerializer(TransactionLogEntry.serializer())
    private val lock = Any()

    private fun load(): List<TransactionLogEntry> = try {
        read()?.let { json.decodeFromString(serializer, it) }.orEmpty()
    } catch (_: Exception) {
        // A corrupt slot must not lose new entries to an exception.
        emptyList()
    }

    override suspend fun append(entry: TransactionLogEntry) {
        synchronized(lock) {
            val updated = (listOf(entry) + load()).take(maxEntries)
            write(json.encodeToString(serializer, updated))
        }
    }

    override suspend fun entries(): List<TransactionLogEntry> = synchronized(lock) { load() }

    override suspend fun clear() {
        synchronized(lock) { write(null) }
    }
}
