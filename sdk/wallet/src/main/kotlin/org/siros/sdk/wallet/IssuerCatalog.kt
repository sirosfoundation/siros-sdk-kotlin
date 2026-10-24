// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.CredentialOffer
import org.siros.sdk.credentials.IssuerEntry
import timber.log.Timber
import java.io.File

/**
 * What the wallet currently knows about the credentials it can be issued, and whether it is refreshing that.
 *
 * @property offers the offers of every visible issuer, from the cache or the last refresh (empty before the first one completes).
 * @property refreshing a background refresh is running; [offers] is what was known when it started.
 * @property fetchedAtMillis when [offers] were fetched from the backend (0 when there are none).
 * @property lastRefreshFailed the last refresh could not even list the issuers; [offers] is the stale list, never blanked.
 */
data class AvailableCredentials(
    val offers: List<CredentialOffer> = emptyList(),
    val refreshing: Boolean = false,
    val fetchedAtMillis: Long = 0L,
    val lastRefreshFailed: Boolean = false,
)

/** Where the issuer catalog is persisted between launches. The content is public issuer metadata. */
interface IssuerCatalogStore {
    suspend fun load(): String?
    suspend fun save(text: String)
    suspend fun clear()
}

/** An in-memory [IssuerCatalogStore] (nothing survives a process): the default for a wallet without a file. */
class InMemoryIssuerCatalogStore : IssuerCatalogStore {
    @Volatile private var text: String? = null
    override suspend fun load(): String? = text
    override suspend fun save(text: String) { this.text = text }
    override suspend fun clear() { text = null }
}

/**
 * The catalog as one JSON file under the app's no-backup directory: public issuer metadata (the bytes any wallet fetches), nothing
 * worth protecting or restoring from a backup. A missing, unreadable or corrupt file reads as empty; a failed write is logged and the
 * in-memory catalog carries on; writes are atomic (temp file, then rename).
 */
class FileIssuerCatalogStore(private val file: File) : IssuerCatalogStore {
    constructor(context: Context) : this(File(context.noBackupFilesDir, "issuer-catalog.json"))

    private val mutex = Mutex()

    override suspend fun load(): String? = withContext(Dispatchers.IO) {
        mutex.withLock {
            try {
                if (file.exists()) file.readText() else null
            } catch (e: Exception) {
                Timber.w(e, "Issuer catalog file unreadable; treated as empty")
                null
            }
        }
    }

    override suspend fun save(text: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            try {
                val tmp = File(file.parentFile, file.name + ".tmp")
                tmp.writeText(text)
                if (!tmp.renameTo(file)) {
                    file.writeText(text)
                    if (!tmp.delete()) Timber.w("Issuer catalog temp file could not be deleted")
                }
            } catch (e: Exception) {
                Timber.w(e, "Issuer catalog could not be persisted")
            }
        }
    }

    override suspend fun clear() = withContext(Dispatchers.IO) {
        mutex.withLock {
            try {
                if (file.exists() && !file.delete()) Timber.w("Issuer catalog file could not be deleted")
                val tmp = File(file.parentFile, file.name + ".tmp")
                if (tmp.exists() && !tmp.delete()) Timber.w("Issuer catalog temp file could not be deleted")
            } catch (e: Exception) {
                Timber.w(e, "Issuer catalog file could not be deleted")
            }
            Unit
        }
    }
}

/**
 * A stale-while-revalidate cache of the issuer list, each issuer's metadata and the credential offers derived from them.
 *
 * - [get] returns the cached offers at once (from memory, else from [store]) and refreshes in the background when they are older than
 *   [ttlMillis]; only when there is nothing cached does it wait for a refresh.
 * - One refresh at a time ([refresh] joins a running one); per-issuer metadata is fetched in parallel, each with [issuerTimeoutMillis];
 *   an issuer that fails or times out keeps its previous entry (the list is never blanked by a failure); an issuer that is no longer
 *   listed is dropped.
 * - Offers are derived with [buildOffers] every time the catalog is assembled (refresh or load), so side effects of deriving them (the
 *   wallet's record of which configurations advertise a delivered seed) are present for cached reads too.
 * - The catalog belongs to one [scopeKey] (tenant, backend and session user): a different key never reads another's data, and [clear]
 *   drops memory and storage (logout, destroy).
 *
 * @param fetchIssuers the visible issuers; failure is reported, never swallowed into an empty list.
 * @param fetchMetadata one issuer's metadata exactly as the backend returned it.
 * @param buildOffers the offers of one issuer from its metadata (empty when the metadata is unusable).
 */
internal class IssuerCatalog(
    private val scope: CoroutineScope,
    private val store: IssuerCatalogStore,
    private val fetchIssuers: suspend () -> List<IssuerEntry>,
    private val fetchMetadata: suspend (IssuerEntry) -> JsonObject,
    private val buildOffers: (IssuerEntry, JsonObject) -> List<CredentialOffer>,
    private val ttlMillis: Long = DEFAULT_TTL_MILLIS,
    private val issuerTimeoutMillis: Long = DEFAULT_ISSUER_TIMEOUT_MILLIS,
    private val maxParallel: Int = DEFAULT_PARALLELISM,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    @Serializable
    private class Entry(val issuer: IssuerEntry, val metadata: JsonObject)

    @Serializable
    private class Snapshot(val scopeKey: String, val fetchedAtMillis: Long, val entries: List<Entry>)

    private val json = Json { ignoreUnknownKeys = true }
    private val lock = Any() // guards the fields below and every publication; never held across a suspension
    private var snapshot: Snapshot? = null
    private var loadedFromStore = false
    private var inFlight: Deferred<Unit>? = null
    private var inFlightKey: String? = null
    private var currentScope: String? = null
    private var epoch = 0

    private val _state = MutableStateFlow(AvailableCredentials())
    val state: StateFlow<AvailableCredentials> = _state.asStateFlow()

    /** The offers, cache first (see the class doc). Throws only when nothing is cached and the issuer list cannot be fetched. */
    suspend fun get(scopeKey: String): List<CredentialOffer> {
        enterScope(scopeKey)
        val cached = cachedFor(scopeKey)
        if (cached != null) {
            if (clock() - cached.fetchedAtMillis > ttlMillis) refreshInBackground(scopeKey)
            return _state.value.offers
        }
        refresh(scopeKey)
        val after = _state.value
        if (after.lastRefreshFailed && after.offers.isEmpty()) throw IssuerCatalogUnavailable()
        return after.offers
    }

    /** Starts a refresh without waiting (joins one that is running). Never throws. */
    fun refreshInBackground(scopeKey: String) {
        // Registered NOW, not when the launch runs: a logout or scope change in between cancels this very job.
        val job = registerRefresh(scopeKey)
        scope.launch {
            try {
                job.start()
                job.await()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w(e, "Catalog refresh failed")
            }
        }
    }

    /** Refreshes now and returns when done; joins a refresh that is already running or about to (single flight). */
    suspend fun refresh(scopeKey: String) {
        val job = registerRefresh(scopeKey)
        job.start()
        job.await()
    }

    private fun registerRefresh(scopeKey: String): Deferred<Unit> = synchronized(lock) {
        resetIfOtherScopeLocked(scopeKey)
        val running = inFlight?.takeIf { !it.isCompleted }
        if (running != null && inFlightKey == scopeKey) running
        else scope.async(start = kotlinx.coroutines.CoroutineStart.LAZY) { runRefresh(scopeKey) }.also { inFlight = it; inFlightKey = scopeKey }
    }

    /**
     * Drops the cache from memory at once (synchronously: logout must not leave the previous user's list readable) and stops a running
     * refresh. Follow with [clearStore] to remove the persisted copy.
     */
    fun clearMemory() {
        val running = synchronized(lock) { invalidateLocked(loaded = true) }
        running?.cancel()
    }

    /** Removes the persisted copy. */
    suspend fun clearStore() = store.clear()

    /** [clearMemory] then [clearStore]. */
    suspend fun clear() {
        clearMemory()
        clearStore()
    }

    /** Invalidates everything of the current scope (generation, snapshot, published state, running refresh) in one critical section. */
    private fun invalidateLocked(loaded: Boolean): Deferred<Unit>? {
        epoch++
        snapshot = null
        loadedFromStore = loaded
        currentScope = null
        _state.value = AvailableCredentials()
        return inFlight.also { inFlight = null; inFlightKey = null }
    }

    private fun resetIfOtherScopeLocked(scopeKey: String) {
        val known = currentScope
        if (known != null && known != scopeKey) {
            // Another user, backend or tenant: nothing of the previous scope stays readable, published or running.
            invalidateLocked(loaded = false)?.cancel()
        }
        currentScope = scopeKey
    }

    private fun enterScope(scopeKey: String) = synchronized(lock) { resetIfOtherScopeLocked(scopeKey) }

    /**
     * The in-memory snapshot of [scopeKey], loading the persisted one on first use, publishing it. Throws [CancellationException] when
     * the catalog was invalidated (logout, another scope) while the persisted copy was being read: that call must not publish or refresh.
     */
    private suspend fun cachedFor(scopeKey: String): Snapshot? {
        val startEpoch = synchronized(lock) {
            val have = snapshot
            if (have != null) return have.takeIf { it.scopeKey == scopeKey }
            if (loadedFromStore) return null
            epoch
        }
        val persisted = try {
            store.load()?.let { json.decodeFromString(Snapshot.serializer(), it) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "Persisted issuer catalog unreadable; ignored")
            null
        }
        synchronized(lock) {
            if (epoch != startEpoch) throw CancellationException("The issuer catalog was invalidated while it was being loaded")
            if (snapshot == null) {
                loadedFromStore = true
                if (persisted != null && persisted.scopeKey == scopeKey) {
                    snapshot = persisted
                    publishLocked(persisted, refreshing = false, failed = false)
                }
            }
            return snapshot?.takeIf { it.scopeKey == scopeKey }
        }
    }

    private fun publishLocked(s: Snapshot, refreshing: Boolean, failed: Boolean) {
        val offers = s.entries.flatMap { e ->
            try { buildOffers(e.issuer, e.metadata) } catch (ex: Exception) { Timber.w(ex, "Offers of ${e.issuer.credentialIssuerIdentifier} unusable"); emptyList() }
        }
        _state.value = AvailableCredentials(offers, refreshing, s.fetchedAtMillis, failed)
    }

    /** Updates the published flags of the refresh started in generation [gen]; a refresh of an invalidated generation touches nothing. */
    private fun markState(gen: Int, refreshing: Boolean, failed: Boolean? = null) {
        synchronized(lock) {
            if (epoch != gen) return
            _state.value = _state.value.copy(refreshing = refreshing, lastRefreshFailed = failed ?: _state.value.lastRefreshFailed)
        }
    }

    private suspend fun runRefresh(scopeKey: String) {
        val myEpoch = synchronized(lock) { epoch }
        // Load the persisted copy first so a refresh after a cold start also keeps the stale entries of issuers that now fail.
        cachedFor(scopeKey)
        val previous = synchronized(lock) { snapshot?.takeIf { it.scopeKey == scopeKey } }
        markState(myEpoch, refreshing = true)
        try {
            val issuers = try {
                fetchIssuers()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w(e, "Issuer list could not be refreshed; keeping what is cached")
                markState(myEpoch, refreshing = false, failed = true)
                return
            }
            val next = Snapshot(scopeKey, clock(), fetchAll(issuers, previous))
            val published = synchronized(lock) {
                if (epoch == myEpoch) {
                    snapshot = next
                    publishLocked(next, refreshing = false, failed = false)
                    true
                } else {
                    false
                }
            }
            if (published) store.save(json.encodeToString(Snapshot.serializer(), next))
        } finally {
            markState(myEpoch, refreshing = false)
        }
    }

    /** Every issuer's entry: fresh metadata, else the previous entry (stale beats nothing), else none. Jobs die with the refresh. */
    private suspend fun fetchAll(issuers: List<IssuerEntry>, previous: Snapshot?): List<Entry> = coroutineScope {
        val gate = Semaphore(maxParallel)
        issuers.map { issuer ->
            async {
                gate.withPermit {
                    val meta = withTimeoutOrNull(issuerTimeoutMillis) { fetchMetadataOrNull(issuer) }
                    if (meta != null) Entry(issuer, meta)
                    else previous?.entries?.firstOrNull { it.issuer.id == issuer.id }?.let { Entry(issuer, it.metadata) }
                }
            }
        }.awaitAll().filterNotNull()
    }

    private suspend fun fetchMetadataOrNull(issuer: IssuerEntry): JsonObject? = try {
        fetchMetadata(issuer)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Timber.w(e, "Metadata of ${issuer.credentialIssuerIdentifier} could not be refreshed")
        null
    }

    companion object {
        const val DEFAULT_TTL_MILLIS = 10 * 60 * 1000L
        const val DEFAULT_ISSUER_TIMEOUT_MILLIS = 20_000L
        const val DEFAULT_PARALLELISM = 6
    }
}

/** Nothing was cached and the issuer list could not be fetched. */
internal class IssuerCatalogUnavailable : Exception("The issuer list could not be fetched and nothing is cached")
