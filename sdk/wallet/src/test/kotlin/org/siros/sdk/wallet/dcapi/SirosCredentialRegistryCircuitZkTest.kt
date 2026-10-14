package org.siros.sdk.wallet.dcapi

import org.junit.Assert.assertEquals
import org.junit.Test
import org.siros.sdk.credentials.CircuitZkCircuit
import uniffi.siros_dc_matcher_ffi.FfiCapability

/** How the wallet's circuits are declared to the matcher (the blob itself is built natively; see the device tests). */
class SirosCredentialRegistryCircuitZkTest {
    @Test
    fun aCircuitRegistersUnderItsIdAndUnderEachAlias() {
        val c = CircuitZkCircuit("sys", "c1", setOf("d"), aliases = setOf("old", "older"))
        assertEquals(
            listOf(
                FfiCapability("sys", mapOf("circuit_id" to "c1")),
                FfiCapability("sys", mapOf("circuit_id" to "old")),
                FfiCapability("sys", mapOf("circuit_id" to "older")),
            ),
            SirosCredentialRegistry.circuitCapabilities(c),
        )
    }

    @Test
    fun functionsAreDeclaredOnlyWhenTheCatalogSaysWhichThereAre() {
        val declared = CircuitZkCircuit("sys", "c1", setOf("d"), functions = setOf("pseudonym-v1-sha256", "age_check"))
        assertEquals(
            mapOf("circuit_id" to "c1", "functions" to "age_check,pseudonym-v1-sha256"),
            SirosCredentialRegistry.circuitCapabilities(declared).single().params,
        )
        val undeclared = CircuitZkCircuit("sys", "c1", setOf("d"))
        assertEquals(mapOf("circuit_id" to "c1"), SirosCredentialRegistry.circuitCapabilities(undeclared).single().params)
    }
}
