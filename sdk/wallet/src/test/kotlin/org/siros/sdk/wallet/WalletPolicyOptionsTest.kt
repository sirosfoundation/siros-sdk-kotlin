// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.app.Activity
import io.mockk.mockk
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkPlanResult
import org.siros.sdk.credentials.CircuitZkPlanner
import org.siros.sdk.credentials.CredentialDisclosureGuard
import org.siros.sdk.credentials.NonDisclosurePolicy
import org.siros.sdk.wallet.dcapi.ExpectedOriginsMode

class WalletPolicyOptionsTest {
    private val base = WalletConfig(backendUrl = "https://backend.example")
    private val nymPsc = listOf(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, "psc")
    private val nymSsc = listOf(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, "ssc")
    private val nymBirth = listOf(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, "birth_date")

    private val planner = CircuitZkPlanner { _, _ -> CircuitZkPlanResult.InvalidRequest }
    private val circuits = CircuitZkCircuitSource { listOf(CircuitZkCircuit("s", "c", setOf("t"))) }

    private var savedPolicy = CredentialDisclosureGuard.policy

    @Before
    fun save() {
        savedPolicy = CredentialDisclosureGuard.policy
    }

    @After
    fun restore() {
        CredentialDisclosureGuard.policy = savedPolicy
    }

    @Test
    fun theDefaultsReproduceTheWalletConfigDefaults() {
        val applied = WalletPolicyOptions().applyTo(base)
        assertSame(base.nonDisclosurePolicy, applied.nonDisclosurePolicy)
        assertEquals(base.dcApiExpectedOrigins, applied.dcApiExpectedOrigins)
        assertFalse(applied.circuitZk)
        assertNull(applied.circuitZkProver)
        assertEquals(base.circuitZkVerifierIdSources.map { it.type }, applied.circuitZkVerifierIdSources.map { it.type })
        val query = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"circuit_zk"}]}""",
        ) as kotlinx.serialization.json.JsonObject
        val plain = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"id":"q","format":"mso_mdoc"}]}""",
        ) as kotlinx.serialization.json.JsonObject
        assertTrue(applied.dcApiRequiresSignedRequest(query))
        assertFalse(applied.dcApiRequiresSignedRequest(plain))
    }

    @Test
    fun everyChoiceReachesTheConfig() {
        val applied = WalletPolicyOptions(
            nonDisclosure = NonDisclosureMode.NONE,
            circuitZk = true,
            expectedOrigins = ExpectedOriginsMode.REQUIRED,
            signedRequest = SignedRequestRule.ALWAYS,
            fakeProver = true,
            verifierIdSources = setOf(VerifierIdSourceKind.AUTHZEN),
        ).applyTo(base, planner, circuits)
        assertSame(NonDisclosurePolicy.NONE, applied.nonDisclosurePolicy)
        assertTrue(applied.circuitZk)
        assertSame(planner, applied.circuitZkPlanner)
        assertSame(circuits, applied.circuitZkCircuits)
        assertTrue(applied.circuitZkProver!!.isFake)
        assertEquals(ExpectedOriginsMode.REQUIRED, applied.dcApiExpectedOrigins)
        assertTrue(applied.dcApiRequiresSignedRequest(kotlinx.serialization.json.JsonObject(emptyMap())))
        assertEquals(listOf("semantic"), applied.circuitZkVerifierIdSources.map { it.type })
    }

    @Test
    fun aProductionProverOnTheBaseIsKeptUnlessTheFakeIsSelected() {
        val real = org.siros.sdk.keystore.FakeCircuitZkProver.optIn()
        val withReal = base.copy(circuitZkProver = real)
        assertSame(real, WalletPolicyOptions(circuitZk = true).applyTo(withReal, planner, circuits).circuitZkProver)
        val fake = WalletPolicyOptions(circuitZk = true, fakeProver = true).applyTo(withReal, planner, circuits).circuitZkProver
        assertTrue(fake!!.isFake)
        assertTrue(fake !== real)
    }

    @Test
    fun theFakeProverIsNeverInstalledWithoutCircuitZk_andCircuitZkAloneInstallsNoProver() {
        assertNull(WalletPolicyOptions(circuitZk = false, fakeProver = true).applyTo(base, planner, circuits).circuitZkProver)
        val on = WalletPolicyOptions(circuitZk = true).applyTo(base, planner, circuits)
        assertNull(on.circuitZkProver)
        assertNull(WalletPolicyOptions(circuitZk = false).applyTo(base, planner, circuits).circuitZkPlanner)
        assertEquals(emptyList<String>(), WalletPolicyOptions(verifierIdSources = emptySet()).applyTo(base).circuitZkVerifierIdSources.map { it.type })
    }

    @Test
    fun storedOptionsRoundTrip_andDamagedValuesFallBackPerOption() {
        val chosen = WalletPolicyOptions(
            nonDisclosure = NonDisclosureMode.NONE, circuitZk = true, expectedOrigins = ExpectedOriginsMode.IF_PRESENT,
            signedRequest = SignedRequestRule.ALWAYS, fakeProver = true, verifierIdSources = setOf(VerifierIdSourceKind.X509_SAN_DNS),
        )
        val stored = chosen.toStored()
        assertEquals(chosen, WalletPolicyOptions.fromStored { stored[it] })
        assertEquals(WalletPolicyOptions(), WalletPolicyOptions.fromStored { null })
        assertEquals(emptySet<VerifierIdSourceKind>(), WalletPolicyOptions.fromStored { if (it == "verifier_id_sources") "" else null }.verifierIdSources)
        val damaged = WalletPolicyOptions.fromStored { if (it == "circuit_zk") "maybe" else stored[it] }
        assertEquals(chosen.copy(circuitZk = false), damaged)
        assertEquals(WalletPolicyOptions().expectedOrigins, WalletPolicyOptions.fromStored { if (it == "expected_origins") "STRICT" else null }.expectedOrigins)
    }

    // The unit tests' usual wallet is allocated without running its initializers, which skips the policy
    // installation. These two build the wallet through its real constructor.
    //
    // The constructor cannot finish on the JVM: further down it opens Keystore-backed encrypted preferences
    // (SessionStore), which the Android stubs do not provide. The policy is installed by an init block that
    // runs before that, so it is in force by the time the constructor throws - which is what is asserted.
    // Should the installation ever move behind SessionStore, these tests fail and say so.

    private fun createWalletThroughItsRealInit(config: WalletConfig) {
        val failure = runCatching { SirosWallet.create(mockk<Activity>(relaxed = true), config) }.exceptionOrNull()
        // Only the Android-stub failure is tolerated; anything else is a real constructor bug.
        if (failure != null) {
            val chain = generateSequence<Throwable>(failure) { it.cause }.toList()
            assertTrue("unexpected failure: $failure", chain.any { it.message.orEmpty().contains("not mocked") || it is NoClassDefFoundError || it is ExceptionInInitializerError })
        }
    }

    @Test
    fun theWalletsRealInitInstallsANonDefaultPolicy() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy.DEFAULT
        createWalletThroughItsRealInit(WalletPolicyOptions(nonDisclosure = NonDisclosureMode.NONE).applyTo(base))
        assertSame(NonDisclosurePolicy.NONE, CredentialDisclosureGuard.policy)
        assertFalse(CredentialDisclosureGuard.isProtected(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, nymPsc))
    }

    @Test
    fun aSecondWalletWithNoProtection_doesNotWeakenARunningWalletsPolicy() {
        CredentialDisclosureGuard.policy = NonDisclosurePolicy.NONE
        createWalletThroughItsRealInit(base)
        assertTrue(CredentialDisclosureGuard.isProtected(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, nymPsc))
        createWalletThroughItsRealInit(WalletPolicyOptions(nonDisclosure = NonDisclosureMode.NONE).applyTo(base))
        assertTrue(CredentialDisclosureGuard.isProtected(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, nymPsc))
        assertTrue(CredentialDisclosureGuard.isProtected(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, nymSsc))
    }

    @Test
    fun theWalletsRealInitInstallsTheDefaultPolicy_whichProtectsTheNymAuthSeedCommitments() {
        // Start from the opposite policy so a wallet that installed nothing would fail this.
        CredentialDisclosureGuard.policy = NonDisclosurePolicy.NONE
        assertFalse(CredentialDisclosureGuard.isProtected(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, nymPsc))
        createWalletThroughItsRealInit(base)
        assertSame(NonDisclosurePolicy.DEFAULT, CredentialDisclosureGuard.policy)
        assertTrue(CredentialDisclosureGuard.isProtected(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, nymPsc))
        assertTrue(CredentialDisclosureGuard.isProtected(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, nymSsc))
        assertFalse(CredentialDisclosureGuard.isProtected(NonDisclosurePolicy.NYM_AUTH_DOCTYPE, nymBirth))
        assertFalse(CredentialDisclosureGuard.isProtected("some.other.doctype", nymPsc))
    }
}
