// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import uniffi.siros_wscd_manager.FfiAndroidKeystoreSecurityLevel
import uniffi.siros_wscd_manager.FfiWscdException

/**
 * Exercises [AndroidKeystoreWscdCallbackBridge]'s own mapping/sequencing
 * logic (security-level mapping, StrongBoxUnavailable translation, the
 * sign-with-authentication dance) against a fully in-memory fake backend -
 * no device needed. What cannot be faithfully simulated off-device (that
 * Android's own Keystore refuses to let a Signature sign unless a genuine
 * biometric/device-credential prompt unlocked it) is out of scope here, same
 * as [AndroidKeystoreSignerTest]'s own doc comment explains for that class.
 */
class AndroidKeystoreWscdCallbackBridgeTest {

    private class FakeBackend(
        var strongBoxAvailable: Boolean = true,
        /** Simulates an ordinary (non-[KeystoreException], non-[FfiWscdException]) platform exception, e.g. a raw `android.security.KeyStoreException`. */
        var certificateChainFailsWithPlatformException: Boolean = false,
    ) : AndroidKeyStoreBackend {
        private class Entry(
            val level: AndroidKeystoreSigner.SecurityLevel,
            val methods: Set<AndroidKeystoreSigner.AuthenticationMethod>,
            val keyPair: java.security.KeyPair,
        )

        private val entries = linkedMapOf<String, Entry>()
        val deleted = mutableListOf<String>()

        override fun generate(
            alias: String,
            attestationChallenge: ByteArray?,
            strongBox: Boolean,
            userAuthenticationMethods: Set<AndroidKeystoreSigner.AuthenticationMethod>,
            unlockedDeviceRequired: Boolean,
        ): AndroidKeystoreSigner.SecurityLevel {
            if (strongBox && !strongBoxAvailable) throw AndroidKeyStoreBackend.StrongBoxUnavailable()
            val level = if (strongBox) AndroidKeystoreSigner.SecurityLevel.STRONGBOX else AndroidKeystoreSigner.SecurityLevel.TRUSTED_ENVIRONMENT
            val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            entries[alias] = Entry(level, userAuthenticationMethods, keyPair)
            return level
        }

        override fun certificateChain(alias: String): List<ByteArray> {
            if (certificateChainFailsWithPlatformException) throw IllegalStateException("simulated raw platform failure")
            return emptyList()
        }

        override fun publicKey(alias: String) = entries.getValue(alias).keyPair.public as java.security.interfaces.ECPublicKey

        override fun securityLevel(alias: String): AndroidKeystoreSigner.SecurityLevel = entries.getValue(alias).level

        override fun userAuthenticationMethods(alias: String): Set<AndroidKeystoreSigner.AuthenticationMethod> = entries.getValue(alias).methods

        override fun newSignature(alias: String): Signature =
            Signature.getInstance("SHA256withECDSA").apply { initSign(entries.getValue(alias).keyPair.private) }

        override fun aliases(): List<String> = entries.keys.toList()

        override fun delete(alias: String) {
            entries.remove(alias)
            deleted += alias
        }
    }

    @Test
    fun generate_mapsSecurityLevelsToTheFfiEnum() {
        val backend = FakeBackend(strongBoxAvailable = true)
        val bridge = AndroidKeystoreWscdCallbackBridge(backend)

        assertEquals(
            FfiAndroidKeystoreSecurityLevel.STRONG_BOX,
            bridge.generate("a", null, strongBox = true, userAuthenticationMethods = emptyList(), unlockedDeviceRequired = false),
        )
        assertEquals(
            FfiAndroidKeystoreSecurityLevel.TRUSTED_EXECUTION,
            bridge.generate("b", null, strongBox = false, userAuthenticationMethods = emptyList(), unlockedDeviceRequired = false),
        )
    }

    @Test
    fun generate_translatesStrongBoxUnavailableToTheTypedFfiException() {
        val bridge = AndroidKeystoreWscdCallbackBridge(FakeBackend(strongBoxAvailable = false))

        try {
            bridge.generate("a", null, strongBox = true, userAuthenticationMethods = emptyList(), unlockedDeviceRequired = false)
            fail("expected FfiWscdException.StrongBoxUnavailable")
        } catch (e: FfiWscdException.StrongBoxUnavailable) {
            // expected
        }
    }

    @Test
    fun sign_withNoAuthenticationRequired_producesAVerifiableRawSignature() {
        val backend = FakeBackend()
        val bridge = AndroidKeystoreWscdCallbackBridge(backend)
        bridge.generate("a", null, strongBox = true, userAuthenticationMethods = emptyList(), unlockedDeviceRequired = false)

        val data = "hello".toByteArray()
        val raw = bridge.sign("a", data)

        assertEquals(64, raw.size)
        // Verify under the SAME backend's public key, independently of the signing path - proves the raw r||s
        // bridge.sign returns is a real, valid signature, not just "some 64 bytes".
        val der = EcdsaSignatures.let {
            // Re-derive a DER signature is not available publicly; verify via java.security directly using
            // the raw r||s split back into DER, mirroring how a verifier would reconstruct it.
            val r = java.math.BigInteger(1, raw.copyOfRange(0, 32))
            val s = java.math.BigInteger(1, raw.copyOfRange(32, 64))
            derEncode(r, s)
        }
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(backend.publicKey("a"))
            update(data)
        }
        assertTrue("the raw r||s signature must verify under the key's own public half", verifier.verify(der))
    }

    @Test
    fun sign_withAuthenticationRequiredAndNoAuthenticatorConfigured_throwsAuthRequired() {
        val backend = FakeBackend()
        val bridge = AndroidKeystoreWscdCallbackBridge(backend, authenticator = null)
        bridge.generate(
            "a",
            null,
            strongBox = true,
            userAuthenticationMethods = listOf("biometric"),
            unlockedDeviceRequired = false,
        )

        try {
            bridge.sign("a", "hello".toByteArray())
            fail("expected FfiWscdException.AuthRequired")
        } catch (e: FfiWscdException.AuthRequired) {
            // expected
        }
    }

    @Test
    fun sign_withAuthenticationRequiredAndAConfiguredAuthenticator_succeeds() = runTest {
        val backend = FakeBackend()
        val authenticator = UserAuthenticator { request -> AndroidKeystoreSigner.AuthenticationMethod.BIOMETRIC }
        val bridge = AndroidKeystoreWscdCallbackBridge(backend, authenticator)
        bridge.generate(
            "a",
            null,
            strongBox = true,
            userAuthenticationMethods = listOf("biometric"),
            unlockedDeviceRequired = false,
        )

        val raw = bridge.sign("a", "hello".toByteArray())
        assertEquals(64, raw.size)
    }

    @Test
    fun publicKeyJwk_returnsAParseableEcJwk() {
        val backend = FakeBackend()
        val bridge = AndroidKeystoreWscdCallbackBridge(backend)
        bridge.generate("a", null, strongBox = true, userAuthenticationMethods = emptyList(), unlockedDeviceRequired = false)

        val jwk = kotlinx.serialization.json.Json.parseToJsonElement(bridge.publicKeyJwk("a")) as kotlinx.serialization.json.JsonObject
        assertEquals("EC", (jwk["kty"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals("P-256", (jwk["crv"] as kotlinx.serialization.json.JsonPrimitive).content)
    }

    @Test
    fun publicKeyJwk_includesAKidMatchingTheJwkThumbprintTheRustPluginComputesFromTheSameJwk() {
        val backend = FakeBackend()
        val bridge = AndroidKeystoreWscdCallbackBridge(backend)
        bridge.generate("a", null, strongBox = true, userAuthenticationMethods = emptyList(), unlockedDeviceRequired = false)

        val jwkJson = bridge.publicKeyJwk("a")
        val jwk = kotlinx.serialization.json.Json.parseToJsonElement(jwkJson) as kotlinx.serialization.json.JsonObject
        val kid = (jwk["kid"] as? kotlinx.serialization.json.JsonPrimitive)?.content
        assertTrue("publicKeyJwk must include a kid, or SirosWallet.extractProofKeyId cannot recover the holder key", !kid.isNullOrEmpty())

        // The Rust plugin (AndroidKeystorePlugin::finish_generate_key) independently derives the key's own kid via
        // jwk_thumbprint, which reads only the canonical crv/kty/x/y members and ignores any kid already present - so
        // the embedded kid must equal the RFC 7638 thumbprint of this exact JWK, computed the same way
        // KeypairIdentity's own thumbprint matching already relies on (nimbus-jose-jwt's JWK.computeThumbprint()).
        val independentThumbprint = com.nimbusds.jose.jwk.JWK.parse(jwkJson).computeThumbprint().toString()
        assertEquals(independentThumbprint, kid)
    }

    @Test
    fun generate_rejectsAnUnsupportedAuthenticationMethodInsteadOfSilentlyDroppingIt() {
        val backend = FakeBackend()
        val bridge = AndroidKeystoreWscdCallbackBridge(backend)

        try {
            bridge.generate(
                "a",
                null,
                strongBox = true,
                userAuthenticationMethods = listOf("some_future_method_this_bridge_does_not_know"),
                unlockedDeviceRequired = false,
            )
            fail("an unrecognized authentication method must be rejected, not silently dropped to an empty (unauthenticated) set")
        } catch (e: FfiWscdException.Plugin) {
            // expected - and, crucially, no key was generated as an unauthenticated fallback:
            assertEquals(emptyList<String>(), bridge.aliases())
        }
    }

    @Test
    fun certificateChain_translatesAnOrdinaryPlatformExceptionToATypedFfiException() {
        val backend = FakeBackend(certificateChainFailsWithPlatformException = true)
        val bridge = AndroidKeystoreWscdCallbackBridge(backend)
        bridge.generate("a", null, strongBox = true, userAuthenticationMethods = emptyList(), unlockedDeviceRequired = false)

        try {
            bridge.certificateChain("a")
            fail("expected a typed FfiWscdException, not the raw platform exception to escape across the UniFFI callback boundary")
        } catch (e: FfiWscdException.Plugin) {
            // expected - an ordinary IllegalStateException from the backend must not reach UniFFI as an unexpected
            // callback error, bypassing the Rust side's typed cleanup/fallback handling.
        }
    }

    @Test
    fun delete_forwardsToTheBackend() {
        val backend = FakeBackend()
        val bridge = AndroidKeystoreWscdCallbackBridge(backend)
        bridge.generate("a", null, strongBox = true, userAuthenticationMethods = emptyList(), unlockedDeviceRequired = false)

        bridge.delete("a")

        assertEquals(listOf("a"), backend.deleted)
        assertEquals(emptyList<String>(), bridge.aliases())
    }

    /** Minimal DER `SEQUENCE { INTEGER r, INTEGER s }` encoder, for re-verifying [AndroidKeystoreWscdCallbackBridge.sign]'s raw output independently of [EcdsaSignatures]'s own (already separately tested) conversion logic. */
    private fun derEncode(r: java.math.BigInteger, s: java.math.BigInteger): ByteArray {
        fun encodeInt(v: java.math.BigInteger): ByteArray {
            var bytes = v.toByteArray()
            return byteArrayOf(0x02, bytes.size.toByte()) + bytes
        }
        val rEnc = encodeInt(r)
        val sEnc = encodeInt(s)
        val body = rEnc + sEnc
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
