// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import androidx.fragment.app.FragmentActivity
import androidx.fragment.app.testing.EmptyFragmentActivity
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.keystore.AndroidKeystoreSigner.AuthenticationMethod
import org.siros.sdk.keystore.AndroidKeystoreSigner.HardwareRequirement
import org.siros.sdk.keystore.AndroidKeystoreSigner.KeyPolicy
import org.siros.sdk.keystore.AndroidKeystoreSigner.UserAuthentication

/**
 * The real prompt, with a person at the phone: runs only with the instrumentation argument
 * `interactive=true`, the phone unlocked, a screen lock set and a fingerprint enrolled.
 *
 * ```
 * ./gradlew :sdk:keystore:connectedDebugAndroidTest \
 *   -Pandroid.testInstrumentationRunnerArguments.class=org.siros.sdk.keystore.AndroidKeystoreSignerInteractiveTest \
 *   -Pandroid.testInstrumentationRunnerArguments.interactive=true
 * ```
 *
 * Each test shows one prompt: authenticate as its title says.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreSignerInteractiveTest {

    private lateinit var scenario: ActivityScenario<EmptyFragmentActivity>
    private lateinit var activity: FragmentActivity

    @Before
    fun setUp() {
        assumeTrue(
            "interactive: pass -Pandroid.testInstrumentationRunnerArguments.interactive=true",
            InstrumentationRegistry.getArguments().getString("interactive") == "true",
        )
        scenario = ActivityScenario.launch(EmptyFragmentActivity::class.java)
        scenario.onActivity { activity = it }
    }

    @After
    fun tearDown() {
        if (::scenario.isInitialized) scenario.close()
    }

    private fun signer(prefix: String, methods: Set<AuthenticationMethod>, title: String) = AndroidKeystoreSigner(
        aliasPrefix = "org.siros.sdk.test.androidkeystore.interactive.$prefix.",
        defaultPolicy = KeyPolicy(HardwareRequirement.HARDWARE, UserAuthentication.EveryUse(methods)),
        authenticator = BiometricPromptAuthenticator({ activity }, title = title),
    )

    @Test
    fun biometricKey_signsAfterTheFingerprint_andReportsInherence() = runBlocking {
        val s = signer("bio", setOf(AuthenticationMethod.BIOMETRIC), "SDK test: touch the fingerprint sensor")
        val keyId = s.generateKey("ES256")
        try {
            val session = s.beginScaSign(keyId)
            val declared = session.declaredFactors
            assertEquals(
                setOf(AuthenticationCategory.POSSESSION, AuthenticationCategory.INHERENCE),
                declared.map { it.category }.toSet(),
            )
            val signed = session.sign("transaction".toByteArray())
            ScaSignSession.requireMatching(declared, signed.factors)
            assertEquals(64, signed.signature.size)
        } finally {
            s.deleteKey(keyId)
        }
    }

    @Test
    fun eitherKey_signsAfterThePin_andReportsKnowledge() = runBlocking {
        val s = signer(
            "pin",
            setOf(AuthenticationMethod.BIOMETRIC, AuthenticationMethod.DEVICE_CREDENTIAL),
            "SDK test: choose 'Use PIN' and enter the PIN",
        )
        val keyId = s.generateKey("ES256")
        try {
            val session = s.beginScaSign(keyId)
            val categories = session.declaredFactors.map { it.category }.toSet()
            assertTrue("$categories", AuthenticationCategory.POSSESSION in categories && categories.size == 2)
            val signed = session.sign("transaction".toByteArray())
            ScaSignSession.requireMatching(session.declaredFactors, signed.factors)
        } finally {
            s.deleteKey(keyId)
        }
    }

    @Test
    fun plainSign_promptsForEveryUse() = runBlocking {
        val s = signer("each", setOf(AuthenticationMethod.BIOMETRIC), "SDK test: fingerprint (1 of 2)")
        val keyId = s.generateKey("ES256")
        try {
            assertEquals(64, s.sign(keyId, byteArrayOf(1)).size)
            val again = signer("each", setOf(AuthenticationMethod.BIOMETRIC), "SDK test: fingerprint (2 of 2)")
            assertEquals(64, again.sign(keyId, byteArrayOf(2)).size)
        } finally {
            s.deleteKey(keyId)
        }
    }
}
