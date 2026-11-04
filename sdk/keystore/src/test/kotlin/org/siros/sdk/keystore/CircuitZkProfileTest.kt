// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CredentialFormat
import org.siros.sdk.credentials.CredentialTypeRef
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.credentials.ZkProofSystemRegistry
import org.siros.sdk.credentials.ZkProofSystemPreference
import org.siros.sdk.credentials.mdoc.DocumentMdoc

class CircuitZkProfileTest {
    private val client = ZkCircuitClient(sources = emptyList())
    private val presentation = ZkMdocPresentation(ZkProofSystemRegistry(emptyList()))

    private class ExampleAdapter(override val systems: Set<CircuitZkSystemKey>) : CircuitZkSystemAdapter {
        override fun admits(circuit: CircuitZkCircuit, plan: CircuitZkPlan) = true
        override suspend fun prove(descriptor: ZkCircuitDescriptor, input: CircuitZkProveInput): CircuitZkProveOutput =
            CircuitZkProveOutput(byteArrayOf(1), emptyMap())
    }

    private class ExampleHandler(override val functionId: String) : CircuitZkFunctionHandler {
        override fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind> = emptySet()
        override fun holds(function: CircuitZkFunction, credential: DocumentMdoc) = true
    }

    private val additional = CircuitZkProfile(
        ExampleAdapter(setOf(CircuitZkSystemKey("example-profile", "1"))),
        listOf(ExampleHandler("example_function")),
    )

    @Test
    fun `nym_auth and legacy are ordinary profile registrations and additional handlers compose`() {
        val profiles = CatalogCircuitZkProver.standardProfiles(client, presentation, additional = listOf(additional))

        assertEquals(3, profiles.size)
        assertTrue(profiles[0].adapter is NymAuthCircuitZkAdapter)
        assertTrue(profiles[1].adapter is LegacyZkCircuitZkAdapter)
        assertEquals(additional.adapter, profiles[2].adapter)
        val ids = CircuitZkProfile.handlers(profiles).map { it.functionId }.toSet()
        assertTrue("pseudonym" in ids)
        assertTrue(org.siros.sdk.credentials.CircuitZkLegacyDisclosure.FUNCTION_ID in ids)
        assertTrue("age_check" in ids)
        assertTrue("example_function" in ids)
    }

    @Test
    fun `profile predicates come from configuration instead of being forced to the nym defaults`() {
        val profiles = CatalogCircuitZkProver.standardProfiles(
            client,
            presentation,
            additional = emptyList(),
            predicates = org.siros.sdk.credentials.PredicateFunctions(emptyList()),
        )
        val ids = CircuitZkProfile.handlers(profiles).map { it.functionId }.toSet()
        assertTrue("pseudonym" in ids)
        assertTrue(org.siros.sdk.credentials.CircuitZkLegacyDisclosure.FUNCTION_ID in ids)
        assertFalse("age_check" in ids)
    }

    @Test
    fun `a duplicate catalog key is refused at standard registration`() {
        try {
            CatalogCircuitZkProver.standard(client, presentation, profiles = listOf(LegacyZkCircuitZkAdapter.profile(presentation).copy(handlers = emptyList())))
            fail("expected duplicate catalog key to be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message.orEmpty().contains("claimed by two adapters"))
        }
    }

    @Test
    fun `a duplicate profile function id is refused at standard registration`() {
        val duplicate = CircuitZkProfile(additional.adapter, listOf(PseudonymFunctionHandler))
        try {
            CatalogCircuitZkProver.standard(client, presentation, profiles = listOf(duplicate))
            fail("expected duplicate function id to be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message.orEmpty().contains("claimed by two profiles"))
        }
    }

    @Test
    fun `longfellow and vega accept additional mdoc credential types without changing their defaults`() {
        val another = CredentialTypeRef(CredentialFormat.MSO_MDOC, "example.credential.1")
        val longfellow = LongfellowZkProofSystem(client, additionalTypes = setOf(another))
        val vega = VegaProofSystem(client, additionalTypes = setOf(another))
        for (system in listOf(longfellow, vega)) {
            assertTrue(another in system.supportedCredentialTypes)
            assertTrue(CredentialTypeRef(CredentialFormat.MSO_MDOC, "org.iso.18013.5.1.mDL") in system.supportedCredentialTypes)
            assertTrue(CredentialTypeRef(CredentialFormat.MSO_MDOC, "eu.europa.ec.eudi.pid.1") in system.supportedCredentialTypes)
        }
        // The original constructors retain exactly the built-in defaults.
        assertEquals(2, LongfellowZkProofSystem(client).supportedCredentialTypes.size)
        assertEquals(2, VegaProofSystem(client).supportedCredentialTypes.size)
    }

    @Test
    fun `a future proof-system preference is data, not a nym-only allow-list`() {
        val future = CircuitZkCircuit(
            system = "future-profile",
            circuitId = "future-circuit-v1",
            docTypes = setOf("example.credential.1"),
            proofSystem = "future-proof-system-v1",
        )
        ZkProofSystemPreference.require(listOf("future-proof-system-v1", "future-circuit-v1"))
        assertEquals(listOf(future), ZkProofSystemPreference.order(listOf(future), listOf("future-proof-system-v1")))
    }

    @Test
    fun `the example adapter still has to return a proof through the generic interface`() = runBlocking {
        val output = additional.adapter.prove(
            ZkCircuitDescriptor(
                id = "example",
                system = "example-profile",
                systemVersion = "1",
                proofSystem = "future-proof-system-v1",
                docTypes = listOf("example.credential.1"),
                published = true,
                status = "active",
            ),
            CircuitZkProveInput(
                CircuitZkCircuit("example-profile", "example", setOf("example.credential.1")),
                CircuitZkPlan(emptyList()),
                byteArrayOf(),
                byteArrayOf(),
                null,
                null,
                emptyMap(),
                { _, _ -> byteArrayOf() },
            ),
        )
        assertEquals(1, output.proof.size)
    }
}
