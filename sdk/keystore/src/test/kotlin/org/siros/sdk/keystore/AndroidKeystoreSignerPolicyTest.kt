// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.keystore.AndroidKeystoreSigner.AuthenticationMethod.BIOMETRIC
import org.siros.sdk.keystore.AndroidKeystoreSigner.AuthenticationMethod.DEVICE_CREDENTIAL
import org.siros.sdk.keystore.AndroidKeystoreSigner.Companion.effectiveMethods
import org.siros.sdk.keystore.AndroidKeystoreSigner.Companion.keystoreAuthTypes
import org.siros.sdk.keystore.AndroidKeystoreSigner.Companion.meets
import org.siros.sdk.keystore.AndroidKeystoreSigner.Companion.methodsOf
import org.siros.sdk.keystore.AndroidKeystoreSigner.Companion.scaFactors
import org.siros.sdk.keystore.AndroidKeystoreSigner.HardwareRequirement
import org.siros.sdk.keystore.AndroidKeystoreSigner.KeyPolicy
import org.siros.sdk.keystore.AndroidKeystoreSigner.SecurityLevel
import org.siros.sdk.keystore.AndroidKeystoreSigner.UserAuthentication

class AndroidKeystoreSignerPolicyTest {

    @Test
    fun defaults_areStrongBox_noUserAuthentication_unlockedDeviceRequired() {
        val policy = KeyPolicy()
        assertEquals(HardwareRequirement.STRONGBOX, policy.hardware)
        assertEquals(UserAuthentication.None, policy.userAuthentication)
        assertTrue(policy.unlockedDeviceRequired)
        assertEquals(setOf(BIOMETRIC, DEVICE_CREDENTIAL), UserAuthentication.EveryUse().methods)
    }

    @Test(expected = IllegalArgumentException::class)
    fun everyUse_needsAMethod() {
        UserAuthentication.EveryUse(emptySet())
    }

    @Test
    fun meets_isStrictForStrongBox_andNeverAcceptsSoftwareForHardware() {
        for (level in SecurityLevel.values()) {
            assertEquals("STRONGBOX vs $level", level == SecurityLevel.STRONGBOX, meets(level, HardwareRequirement.STRONGBOX))
            assertEquals(
                "HARDWARE vs $level",
                level == SecurityLevel.STRONGBOX || level == SecurityLevel.TRUSTED_ENVIRONMENT,
                meets(level, HardwareRequirement.HARDWARE),
            )
            assertTrue("ANY vs $level", meets(level, HardwareRequirement.ANY))
        }
    }

    @Test
    fun effectiveMethods_dropTheDeviceCredentialBeforeAndroid11() {
        val both = UserAuthentication.EveryUse(setOf(BIOMETRIC, DEVICE_CREDENTIAL))
        val pinOnly = UserAuthentication.EveryUse(setOf(DEVICE_CREDENTIAL))
        assertEquals(emptySet<AndroidKeystoreSigner.AuthenticationMethod>(), effectiveMethods(UserAuthentication.None, 34))
        assertEquals(setOf(BIOMETRIC, DEVICE_CREDENTIAL), effectiveMethods(both, 30))
        assertEquals(setOf(BIOMETRIC), effectiveMethods(both, 29))
        assertEquals(setOf(DEVICE_CREDENTIAL), effectiveMethods(pinOnly, 30))
        assertTrue("refused before Android 11", effectiveMethods(pinOnly, 28).isEmpty())
    }

    @Test
    fun keystoreAuthTypes_roundTrip() {
        for (methods in listOf(setOf(BIOMETRIC), setOf(DEVICE_CREDENTIAL), setOf(BIOMETRIC, DEVICE_CREDENTIAL))) {
            assertEquals(methods, methodsOf(keystoreAuthTypes(methods)))
        }
        assertEquals(2, keystoreAuthTypes(setOf(BIOMETRIC))) // KeyProperties.AUTH_BIOMETRIC_STRONG
        assertEquals(1, keystoreAuthTypes(setOf(DEVICE_CREDENTIAL))) // KeyProperties.AUTH_DEVICE_CREDENTIAL
    }

    @Test
    fun scaFactors_arePossessionPlusTheUsersFactor_twoCategories() {
        val bio = scaFactors(BIOMETRIC)
        assertEquals(listOf(AuthenticationCategory.POSSESSION, AuthenticationCategory.INHERENCE), bio.map { it.category })
        val pin = scaFactors(DEVICE_CREDENTIAL)
        assertEquals(listOf(AuthenticationCategory.POSSESSION, AuthenticationCategory.KNOWLEDGE), pin.map { it.category })
        assertEquals(AndroidKeystoreSigner.POSSESSION_METHOD, bio[0].method)
        // The factors pass the SDK's own SCA check against themselves.
        ScaSignSession.requireMatching(bio, bio)
        ScaSignSession.requireMatching(pin, pin)
        assertFalse(bio.toSet() == pin.toSet())
    }

    @Test
    fun biometricPrompt_offersTheDeviceCredentialFromAndroid11Only() {
        val both = setOf(BIOMETRIC, DEVICE_CREDENTIAL)
        val strong = 0x000F // BiometricManager.Authenticators.BIOMETRIC_STRONG
        val credential = 0x8000 // BiometricManager.Authenticators.DEVICE_CREDENTIAL
        assertEquals(strong or credential, BiometricPromptAuthenticator.authenticatorsFor(both, 30))
        assertEquals(strong, BiometricPromptAuthenticator.authenticatorsFor(both, 29))
        assertEquals(strong, BiometricPromptAuthenticator.authenticatorsFor(setOf(BIOMETRIC), 34))
        assertEquals(0, BiometricPromptAuthenticator.authenticatorsFor(setOf(DEVICE_CREDENTIAL), 29))
    }
}
