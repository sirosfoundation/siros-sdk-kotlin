// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.keystore.CircuitZkProfile
import org.siros.sdk.keystore.CircuitZkProveInput
import org.siros.sdk.keystore.CircuitZkProveOutput
import org.siros.sdk.keystore.CircuitZkSystemAdapter
import org.siros.sdk.keystore.CircuitZkSystemKey
import org.siros.sdk.keystore.NymAuthCircuitZkAdapter
import org.siros.sdk.keystore.PseudonymFunctionHandler

class WalletConfigCompatibilityTest {
    private class Adapter(key: CircuitZkSystemKey) : CircuitZkSystemAdapter {
        override val systems: Set<CircuitZkSystemKey> = setOf(key)
        override fun admits(circuit: org.siros.sdk.credentials.CircuitZkCircuit, plan: org.siros.sdk.credentials.CircuitZkPlan) = true
        override suspend fun prove(descriptor: org.siros.sdk.credentials.ZkCircuitDescriptor, input: CircuitZkProveInput): CircuitZkProveOutput =
            throw UnsupportedOperationException("test adapter")
    }

    @Test
    fun `the pre-profile constructor and copy JVM descriptors remain available`() {
        val constructors = WalletConfig::class.java.declaredConstructors
        val current = constructors.single { it.parameterCount == 55 }
        val previous = constructors.single { it.parameterCount == 50 }
        assertTrue(previous.parameterTypes.contentEquals(current.parameterTypes.copyOfRange(0, 50)))

        val currentDefault = constructors.single { it.parameterCount == 58 }
        val previousDefault = constructors.single { it.parameterCount == 53 }
        assertTrue(previousDefault.parameterTypes.copyOfRange(0, 50).contentEquals(previous.parameterTypes))
        assertTrue(
            previousDefault.parameterTypes.copyOfRange(50, 53).contentEquals(
                arrayOf(Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, kotlin.jvm.internal.DefaultConstructorMarker::class.java),
            ),
        )
        assertTrue(currentDefault.parameterTypes.copyOfRange(0, 55).contentEquals(current.parameterTypes))

        val methods = WalletConfig::class.java.declaredMethods
        val currentCopy = methods.single { it.name == "copy" && it.parameterCount == 55 }
        val previousCopy = methods.single { it.name == "copy" && it.parameterCount == 50 }
        assertTrue(previousCopy.parameterTypes.contentEquals(previous.parameterTypes))
        assertTrue(currentCopy.parameterTypes.contentEquals(current.parameterTypes))

        val currentCopyDefault = methods.single { it.name == "copy\$default" && it.parameterCount == 59 }
        val previousCopyDefault = methods.single { it.name == "copy\$default" && it.parameterCount == 54 }
        assertTrue(previousCopyDefault.parameterTypes.copyOfRange(1, 51).contentEquals(previousCopy.parameterTypes))
        assertTrue(currentCopyDefault.parameterTypes.copyOfRange(1, 56).contentEquals(currentCopy.parameterTypes))
    }

    @Test
    fun `copy keeps registered profiles and built-in collisions fail at configuration construction`() {
        val profile = CircuitZkProfile(Adapter(CircuitZkSystemKey("example-profile", "1")))
        val config = WalletConfig(backendUrl = "https://wallet.example", circuitZkProfiles = listOf(profile))
        assertEquals(listOf(profile), config.copy(tenantId = "other").circuitZkProfiles)

        assertThrows(IllegalArgumentException::class.java) {
            WalletConfig(
                backendUrl = "https://wallet.example",
                circuitZkProfiles = listOf(
                    CircuitZkProfile(Adapter(CircuitZkSystemKey(NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM, "61a8a73"))),
                ),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            WalletConfig(
                backendUrl = "https://wallet.example",
                circuitZkProfiles = listOf(
                    CircuitZkProfile(Adapter(CircuitZkSystemKey("another-profile", "1")), listOf(PseudonymFunctionHandler)),
                ),
            )
        }
    }
}
