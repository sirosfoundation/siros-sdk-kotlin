// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.keystore.AndroidKeystoreSigner.AuthenticationMethod
import org.siros.sdk.keystore.AndroidKeystoreSigner.HardwareRequirement
import org.siros.sdk.keystore.AndroidKeystoreSigner.KeyPolicy
import org.siros.sdk.keystore.AndroidKeystoreSigner.SecurityLevel
import org.siros.sdk.keystore.AndroidKeystoreSigner.UserAuthentication

/**
 * The signer against the phone's real Android Keystore (no user at the phone: the prompts are in
 * [AndroidKeystoreSignerInteractiveTest]). On a phone with StrongBox (a Pixel 8) StrongBox keys
 * must land there.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreSignerTest {

    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val hasStrongBox: Boolean get() = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    private val deviceSecure: Boolean get() = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    private val prefix = "org.siros.sdk.test.androidkeystore."
    private val signer = AndroidKeystoreSigner(aliasPrefix = prefix, defaultPolicy = KeyPolicy(hardware = HardwareRequirement.HARDWARE))

    @After
    fun cleanUp() = runBlocking {
        signer.listKeys().forEach { signer.deleteKey(it.keyId) }
    }

    private fun publicKey(jwkBytes: ByteArray): java.security.PublicKey {
        val jwk = Json.parseToJsonElement(String(jwkBytes)).jsonObject
        fun coord(name: String) = BigInteger(1, Base64.getUrlDecoder().decode(jwk[name]!!.jsonPrimitive.content))
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(coord("x"), coord("y")), params))
    }

    private fun assertCode(code: String, block: suspend () -> Unit) = runBlocking {
        try {
            block()
            fail("expected $code")
        } catch (e: KeystoreException) {
            assertEquals(e.message, code, e.errorCode)
        }
    }

    @Test
    fun generateSignVerify_withTheExportedPublicKey() = runBlocking {
        val keyId = signer.generateKey("ES256")
        val data = "DeviceAuthentication".toByteArray()
        val raw = signer.sign(keyId, data)
        assertEquals(64, raw.size)
        assertTrue(BigInteger(1, raw.copyOfRange(32, 64)) <= EcdsaSignatures.P256_ORDER.shiftRight(1))
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey(signer.exportPublicKey(keyId)))
            update(data)
            verify(EcdsaSignatures.rawToDer(raw))
        }
        assertTrue(ok)
    }

    @Test
    fun strongBoxRequired_isMetOrRefused() = runBlocking {
        val strict = AndroidKeystoreSigner(aliasPrefix = "${prefix}strict.")
        if (hasStrongBox) {
            val created = strict.createKey()
            try {
                assertEquals(SecurityLevel.STRONGBOX, created.securityLevel)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    assertEquals(SecurityLevel.STRONGBOX, strict.securityLevel(created.keyId))
                    assertEquals(listOf("hardware"), strict.securityProperties(created.keyId).keyStorage)
                }
            } finally {
                strict.deleteKey(created.keyId)
            }
        } else {
            assertCode("strongbox_unavailable") { strict.createKey() }
            assertTrue("a refused key must not be left behind", strict.listKeys().isEmpty())
        }
    }

    @Test
    fun hardwareRequired_landsInStrongBoxOrTheTee() = runBlocking {
        val created = signer.createKey(KeyPolicy(hardware = HardwareRequirement.HARDWARE))
        val hardware = setOf(SecurityLevel.STRONGBOX, SecurityLevel.TRUSTED_ENVIRONMENT)
        assertTrue("level ${created.securityLevel}", created.securityLevel in hardware)
        if (hasStrongBox) assertEquals(SecurityLevel.STRONGBOX, created.securityLevel)
    }

    @Test
    fun listAndDelete_seeOnlyThisPrefix() = runBlocking {
        val a = signer.generateKey("ES256")
        val other = AndroidKeystoreSigner(aliasPrefix = "${prefix}other.", defaultPolicy = KeyPolicy(hardware = HardwareRequirement.HARDWARE))
        val b = other.generateKey("ES256")
        try {
            assertEquals(listOf(a), signer.listKeys().map { it.keyId })
            signer.deleteKey(a)
            assertTrue(signer.listKeys().isEmpty())
            assertEquals(listOf(b), other.listKeys().map { it.keyId })
        } finally {
            other.deleteKey(b)
        }
    }

    @Test
    fun refusesOtherAlgorithmsAndUnknownKeys() {
        assertCode("unsupported_algorithm") { signer.generateKey("EdDSA") }
        assertCode("key_not_found") { signer.sign("no-such-key", byteArrayOf(1)) }
    }

    @Test
    fun keysAreDeviceBound() = runBlocking {
        val keyId = signer.generateKey("ES256")
        assertTrue(signer.exportPrivateKeypairs().isEmpty())
        assertEquals(MigrationResult.ReEnrollmentRequired(keyId), signer.migrateKey(keyId, "softkey"))
        assertFalse(signer.listKeys().isEmpty())
    }

    @Test
    fun keyWithoutUserAuthentication_isPossessionOnly() = runBlocking {
        val keyId = signer.generateKey("ES256")
        assertTrue(signer.securityProperties(keyId).userAuthentication.isEmpty())
        assertFalse(signer.scaAuthenticationCapability(keyId).isPossible)
        try {
            signer.beginScaSign(keyId)
            fail("SCA with a possession-only key")
        } catch (e: Exception) {
            assertTrue(e.toString(), e is org.siros.sdk.credentials.TransactionDataError)
        }
    }

    @Test
    fun everyUseKey_refusesWithoutAnAuthenticator() = runBlocking {
        assumeTrue("needs a secure lock screen", deviceSecure)
        val created = signer.createKey(KeyPolicy(HardwareRequirement.HARDWARE, UserAuthentication.EveryUse()))
        val keyId = created.keyId
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            assertEquals(listOf("biometric", "device_credential"), signer.securityProperties(keyId).userAuthentication)
        }
        assertCode("user_authentication_required") { signer.sign(keyId, byteArrayOf(1)) }
        assertFalse("no authenticator: no SCA", signer.scaAuthenticationCapability(keyId).isPossible)
    }

    @Test
    fun everyUseKey_cannotSignWithAnAuthenticationThatDidNotHappen() = runBlocking {
        assumeTrue("needs a secure lock screen", deviceSecure)
        // An authenticator that claims success without showing anything: the Keystore must still refuse.
        val liar = UserAuthenticator { request -> request.allowed.first() }
        val lying = AndroidKeystoreSigner(
            aliasPrefix = "${prefix}liar.",
            defaultPolicy = KeyPolicy(HardwareRequirement.HARDWARE, UserAuthentication.EveryUse()),
            authenticator = liar,
        )
        // generateKey() is best effort and ignores defaultPolicy's user-authentication requirement (see
        // AndroidKeystoreSignerTest, the JVM one, aPlainKeyIsAlsoBestEffort_...), so make the policy key explicitly:
        // createKey() is the entry point EveryUse keys are actually made through.
        val created = lying.createKey()
        try {
            assertTrue(lying.scaAuthenticationCapability(created.keyId).isPossible)
            assertCode("signing_failed") { lying.sign(created.keyId, byteArrayOf(1)) }
            val session = lying.beginScaSign(created.keyId)
            assertCode("signing_failed") { session.sign(byteArrayOf(1)) }
        } finally {
            lying.listKeys().forEach { lying.deleteKey(it.keyId) }
        }
    }

    @Test
    fun deviceCredentialAlone_needsAndroid11() = runBlocking {
        assumeTrue(Build.VERSION.SDK_INT < Build.VERSION_CODES.R)
        assertCode("user_authentication_unsupported") {
            val pinOnly = UserAuthentication.EveryUse(setOf(AuthenticationMethod.DEVICE_CREDENTIAL))
            signer.createKey(KeyPolicy(HardwareRequirement.HARDWARE, pinOnly))
        }
    }
}
