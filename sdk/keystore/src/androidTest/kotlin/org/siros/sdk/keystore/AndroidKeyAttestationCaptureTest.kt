// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import android.content.pm.PackageManager
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Produces REAL Android key attestation chains for the backend's test data (go-wallet-backend pull 486,
 * `internal/service/testdata/android/`). Needs a device: it is NOT a unit test and nothing runs it automatically.
 *
 * For one WIA challenge C (instrumentation argument `wia_challenge`, else a random one; the string exactly as
 * `POST /wallet-provider/wia/challenge` returns it) it generates one StrongBox key (when the device has StrongBox) and one TEE key,
 * each bound to SHA-256("siros-instance-key-v1" || C), and writes into `<externalFilesDir>/instance-key-capture/`:
 *
 *   strongbox-chain.pem / tee-chain.pem      the chain, leaf first, PEM CERTIFICATE blocks
 *   strongbox.json / tee.json                {"wia_challenge", "captured_at", "app_digest", "expect_home"}
 *
 * `app_digest` is the hex SHA-256 of the signing certificate of the APK that generated the key: the signed wallet build is the one
 * the backend allowlists. A debug or test APK reports its own digest; the backend operator has to list whichever was used.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeyAttestationCaptureTest {
    private fun pem(der: ByteArray): String =
        "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) + "\n-----END CERTIFICATE-----\n"

    @Suppress("DEPRECATION")
    private fun appDigestHex(): String {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val pm = ctx.packageManager
        val signers = if (Build.VERSION.SDK_INT >= 28) {
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners
        } else {
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES).signatures
        }
        val cert = signers!!.single().toByteArray()
        return MessageDigest.getInstance("SHA-256").digest(cert).joinToString("") { "%02x".format(it) }
    }

    private fun capture(label: String, c: String, expectHome: String, strongBox: Boolean, outDir: File): Boolean {
        val backend = SystemAndroidKeyStore()
        val alias = "siros-ak-capture-$label"
        runCatching { backend.delete(alias) }
        val challenge = MessageDigest.getInstance("SHA-256").digest(("siros-instance-key-v1" + c).toByteArray(Charsets.UTF_8))
        try {
            backend.generate(alias, challenge, strongBox)
        } catch (e: AndroidKeyStoreBackend.StrongBoxUnavailable) {
            return false
        }
        val chain = backend.certificateChain(alias)
        try {
            assertTrue("a chain of at least a leaf and a root", chain.size >= 2)
            val leaf = CertificateFactory.getInstance("X.509").generateCertificate(chain[0].inputStream()) as X509Certificate
            assertEquals("the leaf certifies the generated key", backend.publicKey(alias).encoded.toList(), leaf.publicKey.encoded.toList())
            assertTrue("the challenge is inside the leaf's attestation extension", indexOf(chain[0], challenge) >= 0)
            outDir.mkdirs()
            File(outDir, "$label-chain.pem").writeText(chain.joinToString("") { pem(it) })
            File(outDir, "$label.json").writeText(
                """{"wia_challenge":"$c","captured_at":"${Instant.now()}","app_digest":"${appDigestHex()}","expect_home":"$expectHome"}""" + "\n",
            )
        } finally {
            backend.delete(alias)
        }
        return true
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    @Test
    fun captureStrongBoxAndTeeChains() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        val c = args.getString("wia_challenge")
            ?: Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) })
        val out = File(InstrumentationRegistry.getInstrumentation().targetContext.getExternalFilesDir(null), "instance-key-capture")
        val tee = capture("tee", c, "tee", strongBox = false, outDir = out)
        val strong = capture("strongbox", c, "strongbox", strongBox = true, outDir = out)
        println("instance-key capture: dir=$out tee=$tee strongbox=$strong wia_challenge=$c")
        assumeTrue("at least the TEE chain was captured", tee || strong)
    }

    @Test
    fun theSignerProducesAChainThatCarriesTheWalletsChallenge() = runBlocking {
        val signer = AndroidKeystoreSigner(SystemAndroidKeyStore())
        val challenge = MessageDigest.getInstance("SHA-256").digest("siros-instance-key-v1C".toByteArray())
        val id = signer.generateAttestedKey("ES256", challenge)
        try {
            val chain = signer.attestationChain(id)!!
            assertEquals(AttestationChain.FORMAT_ANDROID_KEY, chain.format)
            assertTrue(chain.certificates.size >= 2)
            assertTrue(indexOf(chain.certificates[0], challenge) >= 0)
            assertEquals("ES256 raw R||S", 64, signer.sign(id, byteArrayOf(1, 2, 3)).size)
        } finally {
            signer.deleteKey(id)
        }
    }
}
