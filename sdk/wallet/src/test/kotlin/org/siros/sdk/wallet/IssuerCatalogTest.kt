// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.siros.sdk.credentials.CredentialOffer
import org.siros.sdk.credentials.IssuerEntry

@OptIn(ExperimentalCoroutinesApi::class)
class IssuerCatalogTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun issuer(id: Long) = IssuerEntry(id = id, credentialIssuerIdentifier = "https://issuer-$id.example.com")
    private fun meta(name: String) = buildJsonObject { put("name", JsonPrimitive(name)) }

    /** The fake backend: what it lists, what each issuer says, how often it was asked, and hooks to hold or fail a call. */
    private class Backend {
        var issuers = listOf<Long>(1, 2)
        val names = mutableMapOf(1L to "one", 2L to "two", 3L to "three")
        var issuerCalls = 0
        val metadataCalls = mutableMapOf<Long, Int>()
        var holdIssuers: CompletableDeferred<Unit>? = null
        var failIssuers = false
        val failMetadata = mutableSetOf<Long>()
        val hangMetadata = mutableSetOf<Long>()
        /** A successful fetch whose metadata [buildOffers] cannot use (no "name" field), as opposed to [failMetadata]'s HTTP failure. */
        val invalidMetadata = mutableSetOf<Long>()
        /** A registry row's URL, when it differs from the default "https://issuer-<id>.example.com". */
        val urlOverrides = mutableMapOf<Long, String>()
    }

    private class Harness(val scope: CoroutineScope, val backend: Backend, val store: IssuerCatalogStore, val clock: LongArray, ttl: Long = 1_000L) {
        val built = mutableListOf<Long>()
        val catalog = IssuerCatalog(
            scope = scope,
            store = store,
            fetchIssuers = {
                backend.issuerCalls++
                backend.holdIssuers?.await()
                if (backend.failIssuers) throw java.io.IOException("issuers down")
                backend.issuers.map { IssuerEntry(id = it, credentialIssuerIdentifier = backend.urlOverrides[it] ?: "https://issuer-$it.example.com") }
            },
            fetchMetadata = { i ->
                backend.metadataCalls[i.id] = (backend.metadataCalls[i.id] ?: 0) + 1
                if (i.id in backend.hangMetadata) awaitCancellation()
                if (i.id in backend.failMetadata) throw java.io.IOException("metadata down")
                if (i.id in backend.invalidMetadata) buildJsonObject { put("bogus", JsonPrimitive(1)) }
                else buildJsonObject { put("name", JsonPrimitive(backend.names.getValue(i.id))) }
            },
            buildOffers = { i, m ->
                built += i.id
                listOf(CredentialOffer("cfg", i.credentialIssuerIdentifier, (m["name"] as JsonPrimitive).content, issuerName = "I${i.id}"))
            },
            ttlMillis = ttl,
            issuerTimeoutMillis = 5_000L,
            clock = { clock[0] },
        )
        fun names() = catalog.state.value.offers.map { it.credentialName }
    }

    private fun TestScope.harness(backend: Backend = Backend(), store: IssuerCatalogStore = InMemoryIssuerCatalogStore(), clock: LongArray = longArrayOf(10_000L)) =
        Harness(CoroutineScope(StandardTestDispatcher(testScheduler) + SupervisorJob()), backend, store, clock)

    @Test
    fun theFirstCallWaitsForTheFetchAndLaterCallsHitTheCacheWithoutAnyNetworkCall() = runTest {
        val h = harness()
        val first = h.catalog.get("k")
        assertEquals(listOf("one", "two"), first.map { it.credentialName })
        assertEquals(1, h.backend.issuerCalls)
        assertEquals(mapOf(1L to 1, 2L to 1), h.backend.metadataCalls)
        // Within the TTL: zero calls of any kind, however often it is read.
        repeat(5) { assertEquals(first, h.catalog.get("k")) }
        runCurrent()
        assertEquals(1, h.backend.issuerCalls)
        assertEquals(mapOf(1L to 1, 2L to 1), h.backend.metadataCalls)
    }

    @Test
    fun aStaleCacheIsServedAtOnceWhileTheRefreshRuns_andTheStateUpdatesWhenItFinishes() = runTest {
        val h = harness()
        h.catalog.get("k")
        h.clock[0] += 5_000 // past the TTL
        h.backend.names[1L] = "one-v2"
        h.backend.holdIssuers = CompletableDeferred()
        val served = h.catalog.get("k") // must not wait for the held refresh
        assertEquals(listOf("one", "two"), served.map { it.credentialName })
        runCurrent()
        assertTrue("a background refresh is running", h.catalog.state.value.refreshing)
        assertEquals(listOf("one", "two"), h.names()) // still the stale list while it runs
        h.backend.holdIssuers!!.complete(Unit)
        runCurrent()
        assertFalse(h.catalog.state.value.refreshing)
        assertEquals(listOf("one-v2", "two"), h.names())
    }

    @Test
    fun aFailedRefreshKeepsTheStaleListAndNeverBlanksIt() = runTest {
        val h = harness()
        h.catalog.get("k")
        h.clock[0] += 5_000
        h.backend.failIssuers = true
        assertEquals(listOf("one", "two"), h.catalog.get("k").map { it.credentialName })
        runCurrent()
        assertEquals(listOf("one", "two"), h.names())
        assertTrue(h.catalog.state.value.lastRefreshFailed)
        // Nothing cached and the list cannot be fetched: that is an error, not an empty list.
        val cold = harness(backend = Backend().also { it.failIssuers = true })
        try {
            cold.catalog.get("k")
            fail("returned an empty list for a failed first fetch")
        } catch (_: IssuerCatalogUnavailable) {
        }
    }

    @Test
    fun anIssuerThatFailsOrTimesOutKeepsItsPreviousEntryWhileTheOthersUpdate() = runTest {
        val h = harness()
        h.catalog.get("k")
        h.backend.names[1L] = "one-v2"
        h.backend.names[2L] = "two-v2"
        h.backend.failMetadata += 1L
        h.catalog.refresh("k")
        assertEquals("a failing issuer keeps its stale entry", listOf("one", "two-v2"), h.names())
        h.backend.failMetadata.clear()
        h.backend.hangMetadata += 2L
        h.backend.names[1L] = "one-v3"
        val refresh = async { h.catalog.refresh("k") }
        advanceTimeBy(6_000) // past the per-issuer timeout
        runCurrent()
        refresh.await()
        assertEquals("a hanging issuer keeps its stale entry", listOf("one-v3", "two-v2"), h.names())
        assertTrue("the hang was cut at the per-issuer timeout, not left to run", testScheduler.currentTime < 10_000)
    }

    @Test
    fun metadataThatBuildOffersCannotUseIsRejectedAndThePreviousEntryIsKeptAndPersisted() = runTest {
        val store = InMemoryIssuerCatalogStore()
        val h = harness(store = store)
        h.catalog.get("k")
        assertEquals(listOf("one", "two"), h.names())
        // A successful HTTP fetch, but metadata buildOffers cannot turn into offers - unlike failMetadata/hangMetadata, this is not
        // a transport failure at all.
        h.backend.invalidMetadata += 1L
        h.backend.names[1L] = "one-but-broken"
        h.catalog.refresh("k")
        assertEquals(
            "invalid metadata is treated like a failed fetch: the previous (valid, decodable) entry is kept, not replaced",
            listOf("one", "two"),
            h.names(),
        )
        // And the persisted snapshot was not corrupted with the unusable entry either: a cold read of it builds the same offers.
        val cold = harness(backend = Backend(), store = store)
        assertEquals(listOf("one", "two"), cold.catalog.get("k").map { it.credentialName })
    }

    @Test
    fun anIssuerThatIsNoLongerListedIsDroppedAndANewOneAppears() = runTest {
        val h = harness()
        h.catalog.get("k")
        h.backend.issuers = listOf(2L, 3L)
        h.catalog.refresh("k")
        assertEquals(listOf("two", "three"), h.names())
    }

    @Test
    fun aRowWhoseUrlChangedIsNeverServedUnderTheOldUrlsMetadataWhenTheFreshFetchFails() = runTest {
        val h = harness()
        h.catalog.get("k")
        assertTrue(h.catalog.state.value.offers.any { it.credentialIssuerIdentifier == "https://issuer-1.example.com" })

        // The SAME registry row (id 1) now reports a DIFFERENT URL, and its metadata fetch fails - the fallback must not
        // attach issuer 1's OLD (issuer-1.example.com) metadata to the NEW URL; it must drop the row instead.
        h.backend.urlOverrides[1L] = "https://issuer-1-moved.example.com"
        h.backend.failMetadata += 1L
        h.catalog.refresh("k")

        assertTrue(
            "no offer was served under the new URL with the old URL's metadata",
            h.catalog.state.value.offers.none { it.credentialIssuerIdentifier == "https://issuer-1-moved.example.com" },
        )
        assertTrue(
            "and none under the old URL either - the row is gone, not stuck on the stale URL",
            h.catalog.state.value.offers.none { it.credentialIssuerIdentifier == "https://issuer-1.example.com" },
        )
    }

    @Test
    fun concurrentRefreshesAreOneFlight() = runTest {
        val h = harness()
        h.backend.holdIssuers = CompletableDeferred()
        val callers = (1..6).map { async { runCatching { h.catalog.refresh("k") } } }
        runCurrent()
        assertEquals("one fetch for six callers", 1, h.backend.issuerCalls)
        h.backend.holdIssuers!!.complete(Unit)
        val results = callers.awaitAll()
        assertTrue("every caller joined the one refresh and saw it complete", results.all { it.isSuccess })
        assertEquals(1, h.backend.issuerCalls)
        assertEquals(mapOf(1L to 1, 2L to 1), h.backend.metadataCalls)
    }

    @Test
    fun clearDropsMemoryAndStorage_andAnotherScopeNeverReadsTheCache() = runTest {
        val store = InMemoryIssuerCatalogStore()
        val h = harness(store = store)
        h.catalog.get("user-a")
        assertTrue(store.load() != null)
        // Another user (scope key) never sees the first user's list, even before any clear.
        val b = h.catalog.get("user-b")
        assertEquals(listOf("one", "two"), b.map { it.credentialName })
        assertEquals("fetched afresh for the other scope", 2, h.backend.issuerCalls)
        h.catalog.clearMemory()
        assertTrue(h.catalog.state.value.offers.isEmpty())
        assertTrue("the persisted copy is still there until the store is cleared", store.load() != null)
        h.catalog.clearStore()
        assertNull(store.load())
        h.catalog.get("user-b")
        assertEquals("nothing survives a clear: fetched again", 3, h.backend.issuerCalls)
    }

    @Test
    fun aColdStartServesThePersistedCatalogWithoutNetworkAndStillDerivesTheOffers() = runTest {
        val store = InMemoryIssuerCatalogStore()
        harness(store = store).catalog.get("k")
        // A new process: new catalog, same storage, nothing in memory.
        val cold = harness(backend = Backend(), store = store)
        val offers = cold.catalog.get("k")
        assertEquals(listOf("one", "two"), offers.map { it.credentialName })
        assertEquals(0, cold.backend.issuerCalls)
        assertTrue(cold.backend.metadataCalls.isEmpty())
        // The offers were derived from the cached metadata (this is where the wallet records which configurations advertise a seed).
        assertEquals(listOf(1L, 2L), cold.built.distinct())
    }

    @Test
    fun aRefreshThatIsCancelledPublishesNothingAndALaterOneWorks() = runTest {
        val h = harness()
        h.backend.holdIssuers = CompletableDeferred()
        val first = async { runCatching { h.catalog.refresh("k") } }
        runCurrent()
        h.catalog.clearMemory() // cancels the running refresh (a logout)
        runCurrent()
        assertTrue(first.await().isFailure)
        assertTrue("nothing was published by the cancelled refresh", h.catalog.state.value.offers.isEmpty())
        h.backend.holdIssuers = null
        h.catalog.refresh("k")
        assertEquals(listOf("one", "two"), h.names())
    }

    @Test
    fun theFileStoreRoundTripsAndTreatsACorruptFileAsEmpty() = runTest {
        val file = tmp.newFile("issuer-catalog.json")
        val store = FileIssuerCatalogStore(file)
        store.save("""{"hello":1}""")
        assertEquals("""{"hello":1}""", store.load())
        file.writeText("{not json")
        val h = harness(store = store)
        // A corrupt persisted catalog is ignored and the fetch proceeds.
        assertEquals(listOf("one", "two"), h.catalog.get("k").map { it.credentialName })
        store.clear()
        assertNull(store.load())
    }

    @Test
    fun aLogoutDuringThePersistedReadCannotRepublishTheOldUsersCatalog() = runTest {
        val inner = InMemoryIssuerCatalogStore()
        harness(store = inner).catalog.get("user-a")
        val gate = CompletableDeferred<Unit>()
        val slow = object : IssuerCatalogStore {
            override suspend fun load(): String? { gate.await(); return inner.load() }
            override suspend fun save(text: String) = inner.save(text)
            override suspend fun clear() = inner.clear()
        }
        val h = harness(backend = Backend(), store = slow)
        val read = async { runCatching { h.catalog.get("user-a") } }
        runCurrent()
        h.catalog.clearMemory() // logout while the persisted copy is being read
        gate.complete(Unit)
        runCurrent()
        assertTrue("the invalidated read was aborted", read.await().isFailure)
        assertTrue("nothing of the old user was republished", h.catalog.state.value.offers.isEmpty())
        assertEquals("and no refresh was started for it", 0, h.backend.issuerCalls)
    }

    @Test
    fun anotherScopeNeverSeesThePreviousScopesOffers_evenWhenItsOwnFetchFails() = runTest {
        val h = harness()
        h.catalog.get("user-a")
        h.backend.failIssuers = true
        try {
            h.catalog.get("user-b")
            fail("returned user-a's offers for user-b")
        } catch (_: IssuerCatalogUnavailable) {
        }
        assertTrue(h.catalog.state.value.offers.isEmpty())
    }

    @Test
    fun cancellingARefreshCancelsItsMetadataRequests() = runTest {
        val h = harness()
        h.backend.hangMetadata += 1L
        h.backend.hangMetadata += 2L
        val refresh = async { runCatching { h.catalog.refresh("k") } }
        runCurrent()
        assertEquals(2, h.backend.metadataCalls.size)
        h.catalog.clearMemory()
        runCurrent()
        refresh.await()
        assertEquals("nothing is still running or queued after the cancellation", 0, h.scope.coroutineContext[kotlinx.coroutines.Job]!!.children.count { it.isActive })
    }

    @Test
    fun aBackgroundRefreshQueuedBeforeALogoutNeverFetchesOrPublishes() = runTest {
        val h = harness()
        h.catalog.refreshInBackground("user-a") // queued: the dispatcher has not run it yet
        h.catalog.clearMemory() // logout before it runs
        runCurrent()
        advanceTimeBy(60_000)
        runCurrent()
        assertEquals("no fetch was made for the logged-out user", 0, h.backend.issuerCalls)
        assertTrue(h.catalog.state.value.offers.isEmpty())
    }
}
