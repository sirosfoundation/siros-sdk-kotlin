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
 * mirrors.
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

    @Test
    fun resolve_returnsNull_whenUserCancelsChoice() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> WscdChoiceResult.Cancelled },
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"),
        )

        assertNull(result)
        assertNull("a cancelled choice must not be persisted", tofu.get(issuer, credentialType))
    }

    @Test
    fun resolve_returnsNull_whenNoRequestChoiceCallbackConfigured() = runTest {
        // Multiple eligible, no callback wired up at all - must degrade
        // gracefully (treat like Cancelled), not throw or crash.
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(tofuStore = tofu, defaultMapping = null, requestChoice = null)

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps"),
        )

        assertNull(result)
    }

    @Test
    fun resolve_ignoresChosenPluginId_ifNotInOfferedEligibleList() = runTest {
        val tofu = InMemoryWscdTofuStore()
        val policy = WscdSelectionPolicy(
            tofuStore = tofu,
            defaultMapping = null,
            requestChoice = { _, _, _ -> WscdChoiceResult.Chosen("softkey") }, // not eligible, not offered
        )

        val result = policy.resolve(
            issuer = issuer,
            credentialType = credentialType,
            requiredTier = "iso_18045_high",
            availablePluginIds = setOf("fido2", "r2ps", "softkey"),
        )

        assertNull(result)
        assertNull(tofu.get(issuer, credentialType))
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
}
