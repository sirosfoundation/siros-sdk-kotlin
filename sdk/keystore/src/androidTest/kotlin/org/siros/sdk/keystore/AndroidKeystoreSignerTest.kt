// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.content.pm.PackageManager
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
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.credentials.COSE_ALG_ES256
import org.siros.sdk.credentials.KeystoreException

/**
 * The signer against the phone's real Android Keystore. On a phone with StrongBox (a Pixel 8)
 * the key must land there; elsewhere in the TEE.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreSignerTest {

    private val signer = AndroidKeystoreSigner(aliasPrefix = "org.siros.sdk.test.androidkeystore.")

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
    fun keyLandsInStrongBox_whenThePhoneHasIt_elseInTheTee() = runBlocking {
        val keyId = signer.generateKey("ES256")
        val hasStrongBox = InstrumentationRegistry.getInstrumentation().targetContext.packageManager
            .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val level = signer.securityLevel(keyId)
        if (hasStrongBox && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            assertEquals(AndroidKeystoreSigner.SecurityLevel.STRONGBOX, level)
            assertEquals(listOf("hardware"), signer.securityProperties(keyId).keyStorage)
        } else {
            val hardware = setOf(AndroidKeystoreSigner.SecurityLevel.TRUSTED_ENVIRONMENT, AndroidKeystoreSigner.SecurityLevel.STRONGBOX)
            assertTrue("level $level", level in hardware)
        }
    }

    @Test
    fun teeOnly_whenStrongBoxIsNotPreferred() = runBlocking {
        val tee = AndroidKeystoreSigner(aliasPrefix = "org.siros.sdk.test.androidkeystore.tee.", preferStrongBox = false)
        val keyId = tee.generateKey("ES256")
        try {
            assertNotEquals(AndroidKeystoreSigner.SecurityLevel.STRONGBOX, tee.securityLevel(keyId))
        } finally {
            tee.deleteKey(keyId)
        }
    }

    @Test
    fun listAndDelete_seeOnlyThisPrefix() = runBlocking {
        val a = signer.generateKey("ES256")
        val other = AndroidKeystoreSigner(aliasPrefix = "org.siros.sdk.test.androidkeystore.other.")
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
    fun refusesOtherAlgorithmsAndUnknownKeys() = runBlocking {
        try {
            signer.generateKey("EdDSA")
            fail("made an EdDSA key")
        } catch (e: KeystoreException) {
            assertEquals("unsupported_algorithm", e.errorCode)
        }
        try {
            signer.sign("no-such-key", byteArrayOf(1))
            fail("signed with a missing key")
        } catch (e: KeystoreException) {
            assertEquals("key_not_found", e.errorCode)
        }
    }

    @Test
    fun zkWitnessSigner_signsEs256AndRefusesAnythingElse() = runBlocking {
        val keyId = signer.generateKey("ES256")
        val zk = signer.zkWitnessSigner(keyId)
        assertEquals(64, zk.sign(COSE_ALG_ES256, byteArrayOf(1, 2, 3)).size)
        try {
            zk.sign(-35, byteArrayOf(1)) // ES384
            fail("signed ES384")
        } catch (e: KeystoreException) {
            assertEquals("unsupported_algorithm", e.errorCode)
        }
    }

    @Test
    fun keysAreDeviceBound() = runBlocking {
        val keyId = signer.generateKey("ES256")
        assertTrue(signer.exportPrivateKeypairs().isEmpty())
        assertEquals(MigrationResult.ReEnrollmentRequired(keyId), signer.migrateKey(keyId, "softkey"))
        assertFalse(signer.listKeys().isEmpty())
    }
}
