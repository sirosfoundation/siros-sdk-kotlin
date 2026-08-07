// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Covers every branch of [WscdSelectionPolicy.resolve]'s resolution order -
 * see that class's doc comment for the numbered list this test class
 * mirrors - plus regression coverage for the 5 bugs fixed alongside the
 * user-override feature (PR #85 review) and the new override precedence.
 */
class WscdSelectionPolicyTest {

    private class InMemoryWscdTofuStore : WscdTofuStore {
        val entries = mutableMapOf<String, String>()
        private fun key(issuer: String, credentialType: String) = "$issuer|$credentialType"
        override fun get(issuer: String, credentialType: String): String? = entries[key(issuer, credentialType)]
        override fun put(issuer: String, credentialType: String, pluginId: String) {
            entries[key(issuer, credentialType)] = pluginId
        }
        override fun getAll(): Map<String, String> = entries.toMap()
        override fun remove(issuer: String, credentialType: String) {
            entries.remove(key(issuer, credentialType))
        }
        override fun clearAll() {
            entries.clear()
        }
    }

    private class InMemoryWscdUserOverrideStore : WscdUserOverrideStore {
        val entries = mutableMapOf<String, String>()
        var globalOverride: String? = null
        private fun key(issuer: String, credentialType: String) = "$issuer|$credentialType"
        override fun get(issuer: String, credentialType: String): String? = entries[key(issuer, credentialType)]
        override fun put(issuer: String, credentialType: String, pluginId: String) {
            entries[key(issuer, credentialType)] = pluginId
        }
        override fun getAll(): Map<String, String> = entries.toMap()
        override fun remove(issuer: String, credentialType: String) {
            entries.remove(key(issuer, credentialType))
        }
        override fun clearAll() {
            entries.clear()
        }
        override fun getGlobal(): String? = globalOverride
        override fun setGlobal(pluginId: String) {
            globalOverride = pluginId
        }
        override fun clearGlobal() {
            globalOverride = null
        }
    }

    private val issuer = "https://issuer.example.com"
    private val credentialType = "urn:eu.europa.ec.eudi:pid:1"

    // ── 1. No requirement declared ──────────────────────────────────

    @Test
    fun resolve_returnsNull_whenRequiredTierIsNull() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = null,
            availablePluginIds = setOf("softkey", "fido2"),
        )

        assertNull(result)
        assertTrue("no requirement must never write a TOFU entry", tofu.entries.isEmpty())
    }

    // ── 2. TOFU hit ──────────────────────────────────────────────────

    @Test
    fun resolve_reusesPersistedTofuChoice_whenStillSufficient() = runTest {
        val tofu = InMemoryWscdTofuStore().apply { put(issuer, credentialType, "fido2") }
        var choicePrompted = false
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = mapOf("$issuer|$credentialType" to "softkey"),
            requestChoice = { _, _, _ -> choicePrompted = true; WscdChoiceResult.Cancelled },
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("softkey", "fido2"),
        )

        assertEquals("fido2", result)
        assertTrue("a sufficient TOFU hit must short-circuit before consulting defaultMapping or prompting", !choicePrompted)
    }

    @Test
    fun resolve_ignoresPersistedTofuChoice_whenNoLongerSufficient() = runTest {
        // Persisted choice was "softkey" (e.g. chosen for a lower-tier
        // credential type earlier), but this resolution needs "high" and
        // softkey is only "basic" - must fall through to the next step
        // rather than returning the insufficient persisted plugin.
        val tofu = InMemoryWscdTofuStore().apply { put(issuer, credentialType, "softkey") }
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("softkey", "fido2"),
        )

        // Falls through TOFU (insufficient) and defaultMapping (none) to the
        // "exactly one eligible" auto-pick branch.
        assertEquals("fido2", result)
    }

    // ── 3. Default-mapping hit ───────────────────────────────────────

    @Test
    fun resolve_usesDefaultMapping_whenNoTofuAndSufficient() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = mapOf("$issuer|$credentialType" to "fido2"),
            requestChoice = null,
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("softkey", "fido2", "r2ps"),
        )

        assertEquals("fido2", result)
        assertEquals("a default-mapping hit must be persisted as the new TOFU entry", "fido2", tofu.get(issuer, credentialType))
    }

    // ── 4. Auto single-match / prefer current default ───────────────

    @Test
    fun resolve_autoPicks_theOnlyEligiblePlugin() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("softkey", "fido2"),
        )

        assertEquals("fido2", result)
        assertEquals("fido2", tofu.get(issuer, credentialType))
    }

    @Test
    fun resolve_prefersCurrentDefault_whenMultipleEligibleButDefaultAlreadySufficient() = runTest {
        val tofu = InMemoryWscdTofuStore()
        var choicePrompted = false
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> choicePrompted = true; WscdChoiceResult.Cancelled },
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"), // both "high" per the static table
            currentDefaultPluginId = "r2ps",
        )

        assertEquals("r2ps", result)
        assertTrue("must not switch away from an already-sufficient current default", !choicePrompted)
    }

    // Regression (bug 3): currentDefaultPluginId meets the tier but is no
    // longer one of availablePluginIds (e.g. host app unregistered it) -
    // must NOT be trusted just because it meets the tier check; must ask
    // the user (or throw) the same as if there were no current default.
    @Test
    fun resolve_ignoresCurrentDefault_whenNotRegistered_andMultipleEligible() = runTest {
        val tofu = InMemoryWscdTofuStore()
        var offeredIds: List<String>? = null
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, ids -> offeredIds = ids; WscdChoiceResult.Chosen(ids.first()) },
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"), // both eligible, "yubikey" not among them
            currentDefaultPluginId = "yubikey", // not registered at all
        )

        assertEquals(
            "must fall through to ask-user instead of trusting an unregistered currentDefaultPluginId",
            setOf("fido2", "r2ps"),
            offeredIds?.toSet(),
        )
        assertEquals(offeredIds!!.first(), result)
    }

    // ── 5. Ask-user multi-match ──────────────────────────────────────

    @Test
    fun resolve_invokesRequestChoice_withEligibleList_whenMultipleEligibleAndDefaultInsufficient() = runTest {
        val tofu = InMemoryWscdTofuStore()
        var offeredIds: List<String>? = null
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { i, c, ids ->
                assertEquals(issuer, i)
                assertEquals(credentialType, c)
                offeredIds = ids
                WscdChoiceResult.Chosen("r2ps")
            },
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"),
            currentDefaultPluginId = "softkey", // insufficient, not in eligible set
        )

        assertEquals("r2ps", result)
        assertEquals(setOf("fido2", "r2ps"), offeredIds?.toSet())
        assertEquals("Chosen result must be persisted as the new TOFU entry", "r2ps", tofu.get(issuer, credentialType))
    }

    // Regression (bug 5): ambiguous resolution with no way to pick a winner
    // must throw, not silently return null (which the caller would treat as
    // "use the default keystore", defeating the whole point of this policy).
    @Test
    fun resolve_throwsAmbiguousWscdPluginException_whenUserCancelsChoice() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> WscdChoiceResult.Cancelled },
        )

        try {
            policy.resolve(
                issuer = issuer,
                credentialType = credentialType,
                requiredTier = "iso_18045_high",
                availablePluginIds = setOf("fido2", "r2ps"),
            )
            fail("expected AmbiguousWscdPluginException")
        } catch (e: AmbiguousWscdPluginException) {
            assertEquals(issuer, e.issuer)
            assertEquals(credentialType, e.credentialType)
            assertEquals(setOf("fido2", "r2ps"), e.eligiblePluginIds.toSet())
        }
        assertNull("a cancelled choice must not be persisted", tofu.get(issuer, credentialType))
    }

    @Test
    fun resolve_throwsAmbiguousWscdPluginException_whenNoRequestChoiceCallbackConfigured() = runTest {
        // Multiple eligible, no callback wired up at all - must fail loudly
        // (never silently proceed with the default keystore).
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)

        try {
            policy.resolve(
                issuer = issuer,
                credentialType = credentialType,
                requiredTier = "iso_18045_high",
                availablePluginIds = setOf("fido2", "r2ps"),
            )
            fail("expected AmbiguousWscdPluginException")
        } catch (e: AmbiguousWscdPluginException) {
            assertEquals(setOf("fido2", "r2ps"), e.eligiblePluginIds.toSet())
        }
    }

    @Test
    fun resolve_throwsAmbiguousWscdPluginException_ifChosenPluginIdNotInOfferedEligibleList() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> WscdChoiceResult.Chosen("softkey") }, // not eligible, not offered
        )

        try {
            policy.resolve(
                issuer = issuer,
                credentialType = credentialType,
                requiredTier = "iso_18045_high",
                availablePluginIds = setOf("fido2", "r2ps", "softkey"),
            )
            fail("expected AmbiguousWscdPluginException")
        } catch (e: AmbiguousWscdPluginException) {
            // expected
        }
        assertNull(tofu.get(issuer, credentialType))
    }

    // ── RememberScope handling for Chosen results ─────────────────────

    @Test
    fun resolve_chosenWithOnceScope_returnsPlugin_butPersistsNothing() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val overrides = InMemoryWscdUserOverrideStore()
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> WscdChoiceResult.Chosen("r2ps", RememberScope.ONCE) },
            userOverrideStore = overrides,
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"),
        )

        assertEquals("r2ps", result)
        assertNull("Once must not persist to TOFU", tofu.get(issuer, credentialType))
        assertNull("Once must not persist as a global override", overrides.getGlobal())
        assertTrue("Once must not persist as a per-issuer override", overrides.entries.isEmpty())
    }

    @Test
    fun resolve_chosenWithThisIssuerScope_persistsToTofu_notGlobalOverride() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val overrides = InMemoryWscdUserOverrideStore()
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> WscdChoiceResult.Chosen("r2ps", RememberScope.THIS_ISSUER) },
            userOverrideStore = overrides,
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"),
        )

        assertEquals("r2ps", result)
        assertEquals("r2ps", tofu.get(issuer, credentialType))
        assertNull(overrides.getGlobal())
    }

    @Test
    fun resolve_chosenWithAllIssuersScope_persistsAsGlobalOverride_notTofu() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val overrides = InMemoryWscdUserOverrideStore()
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> WscdChoiceResult.Chosen("r2ps", RememberScope.ALL_ISSUERS) },
            userOverrideStore = overrides,
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"),
        )

        assertEquals("r2ps", result)
        assertEquals("r2ps", overrides.getGlobal())
        assertNull("AllIssuers must not also write a TOFU entry", tofu.get(issuer, credentialType))
    }

    // ── 6. Zero eligible ─────────────────────────────────────────────

    @Test
    fun resolve_throwsNoEligibleWscdPluginException_whenZeroPluginsMeetRequirement() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)

        try {
            policy.resolve(
                issuer = issuer,
                credentialType = credentialType,
                requiredTier = "iso_18045_high",
                availablePluginIds = setOf("softkey"), // only "basic"
            )
            fail("expected NoEligibleWscdPluginException")
        } catch (e: NoEligibleWscdPluginException) {
            assertEquals(issuer, e.issuer)
            assertEquals(credentialType, e.credentialType)
            assertEquals("iso_18045_high", e.requiredTier)
        }
    }

    // ── tofuMapping/clearTofuMapping/clearAllTofuMappings ─────────────

    @Test
    fun tofuMapping_reflectsPersistedChoices_forSettingsUi() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)

        assertTrue(policy.tofuMapping().isEmpty())

        policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2"),
        )

        assertEquals(mapOf("$issuer|$credentialType" to "fido2"), policy.tofuMapping())
    }

    @Test
    fun clearTofuMapping_removesOnlyThatEntry() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)
        val otherCredentialType = "urn:eu.europa.ec.eudi:mdl:1"

        policy.resolve(issuer, credentialType, "iso_18045_high", setOf("fido2"))
        policy.resolve(issuer, otherCredentialType, "iso_18045_high", setOf("fido2"))

        policy.clearTofuMapping(issuer, credentialType)

        assertNull(tofu.get(issuer, credentialType))
        assertEquals("fido2", tofu.get(issuer, otherCredentialType))
    }

    @Test
    fun clearAllTofuMappings_removesEveryEntry() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)

        policy.resolve(issuer, credentialType, "iso_18045_high", setOf("fido2"))
        policy.clearAllTofuMappings()

        assertTrue(policy.tofuMapping().isEmpty())
    }

    // ── User-override precedence (new feature) ────────────────────────

    @Test
    fun resolve_usesPerIssuerUserOverride_beforeGlobalOverrideOrTofu() = runTest {
        val tofu = InMemoryWscdTofuStore().apply { put(issuer, credentialType, "fido2") }
        val overrides = InMemoryWscdUserOverrideStore().apply {
            put(issuer, credentialType, "r2ps")
            globalOverride = "fido2"
        }
        var choicePrompted = false
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> choicePrompted = true; WscdChoiceResult.Cancelled },
            userOverrideStore = overrides,
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"),
        )

        assertEquals("per-issuer override must win over both TOFU and the global override", "r2ps", result)
        assertTrue(!choicePrompted)
        assertEquals("per-issuer override must NOT be written into TOFU", "fido2", tofu.get(issuer, credentialType))
    }

    @Test
    fun resolve_usesGlobalUserOverride_whenNoPerIssuerOverride_beforeTofu() = runTest {
        val tofu = InMemoryWscdTofuStore().apply { put(issuer, credentialType, "fido2") }
        val overrides = InMemoryWscdUserOverrideStore().apply { globalOverride = "r2ps" }
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = null,
            userOverrideStore = overrides,
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"),
        )

        assertEquals("global override must win over TOFU", "r2ps", result)
    }

    @Test
    fun resolve_fallsThrough_whenPerIssuerOverrideNoLongerMeetsRaisedTier() = runTest {
        // Override was "softkey" (basic tier), but this resolution now
        // requires "high" - the override is stale and must be skipped, not
        // treated as an error.
        val tofu = InMemoryWscdTofuStore()
        val overrides = InMemoryWscdUserOverrideStore().apply { put(issuer, credentialType, "softkey") }
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = null,
            userOverrideStore = overrides,
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("softkey", "fido2"),
        )

        assertEquals("must fall through to the rest of the chain, not error", "fido2", result)
    }

    @Test
    fun resolve_fallsThrough_whenPerIssuerOverridePluginUnregistered() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val overrides = InMemoryWscdUserOverrideStore().apply { put(issuer, credentialType, "r2ps") }
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = null,
            userOverrideStore = overrides,
        )

        // "r2ps" is no longer registered.
        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2"),
        )

        assertEquals("fido2", result)
    }

    @Test
    fun resolve_fallsThrough_whenGlobalOverrideNoLongerSufficientOrUnregistered() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val overrides = InMemoryWscdUserOverrideStore().apply { globalOverride = "softkey" }
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = null,
            userOverrideStore = overrides,
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("softkey", "fido2"),
        )

        assertEquals("fido2", result)
    }

    @Test
    fun setUserOverride_and_currentUserOverrides_and_clearUserOverride_roundTrip() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val overrides = InMemoryWscdUserOverrideStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, userOverrideStore = overrides)

        assertTrue(policy.currentUserOverrides().isEmpty())

        policy.setUserOverride(issuer, credentialType, "r2ps")
        assertEquals(mapOf("$issuer|$credentialType" to "r2ps"), policy.currentUserOverrides())

        policy.clearUserOverride(issuer, credentialType)
        assertTrue(policy.currentUserOverrides().isEmpty())
    }

    @Test
    fun setGlobalUserOverride_and_currentGlobalUserOverride_and_clearGlobalUserOverride_roundTrip() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val overrides = InMemoryWscdUserOverrideStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, userOverrideStore = overrides)

        assertNull(policy.currentGlobalUserOverride())

        policy.setGlobalUserOverride("r2ps")
        assertEquals("r2ps", policy.currentGlobalUserOverride())

        policy.clearGlobalUserOverride()
        assertNull(policy.currentGlobalUserOverride())
    }

    // ── Read-modify-write locking pattern regression (bug 4) ──────────
    //
    // SessionStoreWscdTofuStore.put/remove/clearAll and
    // SessionStoreWscdUserOverrideStore's equivalents fix a read-all,
    // merge-one-entry, write-all-back race by wrapping it in
    // `synchronized(sessionStore)`. Exercising the real classes here would
    // require constructing a real android.content.Context-backed
    // SessionStore (EncryptedSharedPreferences), which this pure-JVM
    // unit-test module has no Robolectric/instrumented runtime for - so
    // this reproduces the identical "read-all / merge / write-all" pattern
    // those two classes use, guarded the same way, to prove: (a) the locked
    // version never drops a concurrent writer's entry, and (b) removing the
    // lock (i.e. the pre-fix behavior) demonstrably can.
    private class BlobBackedMapStore(private val synchronize: Boolean) {
        private val lock = Any()
        @Volatile private var blob: Map<String, String> = emptyMap()

        fun put(key: String, value: String) {
            fun readModifyWrite() {
                val current = blob
                // Widen the race window so an unguarded run reliably
                // demonstrates the drop instead of getting lucky.
                Thread.sleep(1)
                blob = current + (key to value)
            }
            if (synchronize) synchronized(lock) { readModifyWrite() } else readModifyWrite()
        }

        fun getAll(): Map<String, String> = blob
    }

    @Test
    fun concurrentPuts_withLocking_neverDropAnEntry() {
        val store = BlobBackedMapStore(synchronize = true)
        val threads = (0 until 20).map { i -> Thread { store.put("k$i", "v$i") } }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        assertEquals("every concurrent put must survive, none silently dropped", 20, store.getAll().size)
    }

    @Test
    fun concurrentPuts_withoutLocking_canDropAnEntry_demonstratingTheBugThisFixPrevents() {
        val store = BlobBackedMapStore(synchronize = false)
        val threads = (0 until 20).map { i -> Thread { store.put("k$i", "v$i") } }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        assertTrue(
            "expected the unguarded version to lose at least one concurrent write, " +
                "demonstrating the last-writer-wins race the lock fixes",
            store.getAll().size < 20,
        )
    }
}
