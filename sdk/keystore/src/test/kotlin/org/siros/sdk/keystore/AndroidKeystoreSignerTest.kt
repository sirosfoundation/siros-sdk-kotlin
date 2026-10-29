// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.keystore.AndroidKeystoreSigner.AuthenticationMethod
import org.siros.sdk.keystore.AndroidKeystoreSigner.HardwareRequirement
import org.siros.sdk.keystore.AndroidKeystoreSigner.KeyPolicy
import org.siros.sdk.keystore.AndroidKeystoreSigner.SecurityLevel
import org.siros.sdk.keystore.AndroidKeystoreSigner.UserAuthentication

/**
 * Exercises [AndroidKeystoreSigner]'s own logic against a fully in-memory [FakeBackend] (no device needed): alias
 * management, the best-effort StrongBox/TEE fallback, the explicit [AndroidKeystoreSigner.KeyPolicy] checks, SCA, and
 * the cancellation-safety of every key-generation entry point. [FakeBackend.newSignature] hands back a REAL
 * `java.security.Signature` initialized over an in-memory software EC key, so the per-use-authentication/SCA flow is
 * exercised end to end here; what cannot be faithfully simulated off-device - that Android's own Keystore refuses to
 * let a `Signature` sign unless a genuine biometric/device-credential prompt unlocked it, independent of whatever an
 * authenticator claims - is covered on a real device by `AndroidKeystoreSignerTest` (androidTest).
 */
class AndroidKeystoreSignerTest {
    private class Generated(val alias: String, val challenge: ByteArray?, val strongBox: Boolean)

    private class FakeBackend(
        var strongBoxAvailable: Boolean = true,
        var chainLength: Int = 3,
        /** The level reported for a TEE (strongBox=false) request; set to SOFTWARE to simulate an emulator with no secure hardware at all. */
        var fallbackLevel: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
    ) : AndroidKeyStoreBackend {
        private class Entry(
            val level: SecurityLevel,
            val methods: Set<AuthenticationMethod>,
            val keyPair: java.security.KeyPair,
        )

        val generated = mutableListOf<Generated>()
        val deleted = mutableListOf<String>()
        private val entries = linkedMapOf<String, Entry>()
        /** Foreign aliases visible in the same physical keystore but not tracked as [Entry]s (no methods, no chain). */
        val foreignAliases = mutableSetOf<String>()

        var generatedOn: String? = null
        var signedOn: String? = null

        /** Invoked synchronously right after the key is persisted, still inside generate() - simulates cancellation racing the dispatcher handoff back from the IO thread. */
        var afterGenerate: (() -> Unit)? = null

        override fun generate(
            alias: String,
            attestationChallenge: ByteArray?,
            strongBox: Boolean,
            userAuthenticationMethods: Set<AuthenticationMethod>,
            unlockedDeviceRequired: Boolean,
        ): SecurityLevel {
            generatedOn = Thread.currentThread().name
            if (strongBox && !strongBoxAvailable) throw AndroidKeyStoreBackend.StrongBoxUnavailable()
            val level = if (strongBox) SecurityLevel.STRONGBOX else fallbackLevel
            val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            entries[alias] = Entry(level, userAuthenticationMethods, keyPair)
            generated += Generated(alias, attestationChallenge?.copyOf(), strongBox)
            afterGenerate?.invoke()
            return level
        }

        override fun certificateChain(alias: String): List<ByteArray> =
            if (alias in entries) List(chainLength) { i -> byteArrayOf(alias.length.toByte(), i.toByte()) } else emptyList()

        override fun publicKey(alias: String): ECPublicKey = entries.getValue(alias).keyPair.public as ECPublicKey
        override fun securityLevel(alias: String): SecurityLevel = entries[alias]?.level ?: SecurityLevel.UNKNOWN
        override fun userAuthenticationMethods(alias: String): Set<AuthenticationMethod> = entries[alias]?.methods.orEmpty()

        override fun newSignature(alias: String): Signature {
            signedOn = Thread.currentThread().name
            return Signature.getInstance("SHA256withECDSA").apply { initSign(entries.getValue(alias).keyPair.private) }
        }

        override fun aliases(): List<String> = entries.keys.toList() + foreignAliases
        override fun delete(alias: String) {
            deleted += alias
            entries.remove(alias)
        }
    }

    private fun signer(b: FakeBackend, policy: KeyPolicy = KeyPolicy(), authenticator: UserAuthenticator? = null): AndroidKeystoreSigner =
        // A real UUID, as production's default newAlias also produces: listKeys() tells this signer's own keys apart
        // from another signer's (whose prefix might extend this one's) by that shape - see AndroidKeystoreSigner.KEY_ID.
        AndroidKeystoreSigner(b, defaultPolicy = policy, authenticator = authenticator)

    // ---------------------------------------------------------------------------------------------------------------
    // Best effort (generateKey / generateAttestedKey): never refused on the hardware level.
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    fun anAttestedKeyIsAskedForStrongBoxFirstWithTheChallenge() = runTest {
        val b = FakeBackend()
        val challenge = ByteArray(32) { it.toByte() }
        val id = signer(b).generateAttestedKey("ES256", challenge)
        assertEquals(1, b.generated.size)
        assertTrue(b.generated.single().strongBox)
        assertArrayEquals(challenge, b.generated.single().challenge)
        assertTrue(id.isNotEmpty())
    }

    @Test
    fun withoutStrongBoxItFallsBackToTheTeeOnANewAlias_withTheSameChallenge() = runTest {
        val b = FakeBackend(strongBoxAvailable = false)
        val challenge = ByteArray(32) { 7 }
        val s = signer(b)
        val id = s.generateAttestedKey("ES256", challenge)
        assertEquals(1, b.generated.size)
        assertFalse(b.generated.single().strongBox)
        assertArrayEquals(challenge, b.generated.single().challenge)
        assertEquals("the first (half-made StrongBox) alias was dropped", 1, b.deleted.size)
        assertEquals(listOf("trusted_execution"), s.securityProperties(id).keyStorage)
    }

    @Test
    fun aStrongBoxKeyIsReportedAsHardware() = runTest {
        val s = signer(FakeBackend())
        val id = s.generateAttestedKey("ES256", ByteArray(32) { 1 })
        assertEquals(listOf("hardware"), s.securityProperties(id).keyStorage)
    }

    @Test
    fun aPlainKeyHasNoChallenge() = runTest {
        val b = FakeBackend()
        signer(b).generateKey("ES256")
        assertNull(b.generated.single().challenge)
    }

    @Test
    fun aPlainKeyIsAlsoBestEffort_neverRefusedForWantOfStrongBox() = runTest {
        // generateKey() must behave exactly like generateAttestedKey() on the hardware level: it is what the WIA
        // flow falls back to (SirosWallet.generateInstanceKey), and instance-key provisioning must succeed on every
        // Android device, including the majority with no StrongBox chip - never the strict createKey(policy) default.
        val b = FakeBackend(strongBoxAvailable = false)
        val s = signer(b)
        val id = s.generateKey("ES256")
        assertEquals(listOf("trusted_execution"), s.securityProperties(id).keyStorage)
    }

    @Test
    fun onlyEs256IsAccepted() = runTest {
        val s = signer(FakeBackend())
        for (call in listOf<suspend () -> Unit>(
            { s.generateKey("EdDSA") },
            { s.generateAttestedKey("RS256", ByteArray(32)) },
        )) {
            try {
                call()
                fail("accepted")
            } catch (e: KeystoreException) {
                assertEquals("unsupported_algorithm", e.errorCode)
            }
        }
    }

    @Test
    fun aNonEmptyChallengeIsRequired() = runTest {
        try {
            signer(FakeBackend()).generateAttestedKey("ES256", ByteArray(0))
            fail("accepted")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun theChainIsDerLeafFirstInAndroidKeyFormat_andAbsentForALoneCertificate() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val id = s.generateAttestedKey("ES256", ByteArray(32))
        val chain = s.attestationChain(id)!!
        assertEquals(AttestationChain.FORMAT_ANDROID_KEY, chain.format)
        assertEquals(listOf(0, 1, 2), chain.certificates.map { it[1].toInt() }) // order as the keystore returned it: leaf first
        assertEquals(0, chain.clientDataHash.size)
        b.chainLength = 1
        assertNull(s.attestationChain(id))
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Cancellation safety: every key-generation entry point.
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Review of #312: Android Keystore has already persisted the key by the time create() returns from the IO
     * dispatcher, so a cancellation landing exactly at the handoff back to the caller must not leak it - the caller
     * never receives the alias (CancellationException propagates instead), and from the wallet's point of view the
     * key simply does not exist, so it can never be deleted through the ordinary deleteKey path.
     */
    @Test
    fun aCancellationAtTheDispatcherHandoffDeletesTheAlreadyPersistedKeyInsteadOfLeakingIt() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        lateinit var job: Job
        b.afterGenerate = { job.cancel() } // the key is already persisted; cancel right as create() is about to return
        job = launch {
            runCatching { s.generateKey("ES256") }
        }
        job.join()
        assertTrue("the orphaned key was deleted, not left behind", b.deleted.isNotEmpty())
        assertTrue("no key survives in the backend", b.aliases().isEmpty())
    }

    /** Same race, but for the attested-key path (a separate call site in AndroidKeystoreSigner). */
    @Test
    fun aCancellationAtTheDispatcherHandoffDeletesTheAlreadyPersistedAttestedKeyInsteadOfLeakingIt() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        lateinit var job: Job
        b.afterGenerate = { job.cancel() }
        job = launch {
            runCatching { s.generateAttestedKey("ES256", ByteArray(32) { 1 }) }
        }
        job.join()
        assertTrue(b.deleted.isNotEmpty())
        assertTrue(b.aliases().isEmpty())
    }

    /** Same race again, for createKey(policy) - the new entry point this port adds. */
    @Test
    fun aCancellationAtTheDispatcherHandoffDeletesTheAlreadyPersistedPolicyKeyInsteadOfLeakingIt() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        lateinit var job: Job
        b.afterGenerate = { job.cancel() }
        job = launch {
            runCatching { s.createKey(KeyPolicy(HardwareRequirement.HARDWARE)) }
        }
        job.join()
        assertTrue(b.deleted.isNotEmpty())
        assertTrue(b.aliases().isEmpty())
    }

    // ---------------------------------------------------------------------------------------------------------------
    // createKey(policy): strict hardware requirement, confirmed and enforced.
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    fun strongBoxRequired_isMetOrRefused() = runTest {
        val strict = signer(FakeBackend())
        val created = strict.createKey()
        assertEquals(SecurityLevel.STRONGBOX, created.securityLevel)
        assertEquals(listOf("hardware"), strict.securityProperties(created.keyId).keyStorage)
    }

    @Test
    fun strongBoxRequired_refusesAndLeavesNoKeyBehindWhenTheDeviceHasNone() = runTest {
        val b = FakeBackend(strongBoxAvailable = false)
        val strict = signer(b)
        try {
            strict.createKey()
            fail("expected strongbox_unavailable")
        } catch (e: KeystoreException) {
            assertEquals("strongbox_unavailable", e.errorCode)
        }
        assertTrue("a refused key must not be left behind", strict.listKeys().isEmpty())
        assertTrue(b.aliases().isEmpty())
    }

    @Test
    fun hardwareRequired_fallsBackToTheTeeInsteadOfRefusing() = runTest {
        val b = FakeBackend(strongBoxAvailable = false)
        val s = signer(b)
        val created = s.createKey(KeyPolicy(HardwareRequirement.HARDWARE))
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, created.securityLevel)
        assertEquals(1, b.deleted.size) // the half-made StrongBox attempt
    }

    @Test
    fun hardwareRequired_refusesASoftwareOnlyDevice() = runTest {
        val b = FakeBackend(strongBoxAvailable = false, fallbackLevel = SecurityLevel.SOFTWARE)
        val s = signer(b)
        try {
            s.createKey(KeyPolicy(HardwareRequirement.HARDWARE))
            fail("expected hardware_unavailable")
        } catch (e: KeystoreException) {
            assertEquals("hardware_unavailable", e.errorCode)
        }
        assertTrue(s.listKeys().isEmpty())
    }

    @Test
    fun anyRequirement_acceptsWhateverTheKeystoreGives() = runTest {
        val b = FakeBackend(strongBoxAvailable = false, fallbackLevel = SecurityLevel.SOFTWARE)
        val s = signer(b)
        val created = s.createKey(KeyPolicy(HardwareRequirement.ANY))
        assertEquals(SecurityLevel.SOFTWARE, created.securityLevel)
    }

    @Test
    fun deviceCredentialAlone_needsAndroid11_pureFunctionCheck() {
        // The live Build.VERSION.SDK_INT branch is covered by the instrumented AndroidKeystoreSignerTest; this is
        // the same decision table AndroidKeystoreSignerPolicyTest exercises directly.
        assertTrue(AndroidKeystoreSigner.effectiveMethods(UserAuthentication.EveryUse(setOf(AuthenticationMethod.DEVICE_CREDENTIAL)), 28).isEmpty())
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Per-use user authentication and SCA.
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    fun keyWithoutUserAuthentication_isPossessionOnly() = runTest {
        val s = signer(FakeBackend())
        val id = s.generateKey("ES256")
        assertTrue(s.securityProperties(id).userAuthentication.isEmpty())
        assertFalse(s.scaAuthenticationCapability(id).isPossible)
        try {
            s.beginScaSign(id)
            fail("SCA with a possession-only key")
        } catch (e: Exception) {
            assertTrue(e.toString(), e is TransactionDataError)
        }
    }

    @Test
    fun everyUseKey_refusesWithoutAnAuthenticator() = runTest {
        val s = signer(FakeBackend())
        val created = s.createKey(KeyPolicy(HardwareRequirement.ANY, UserAuthentication.EveryUse()))
        val keyId = created.keyId
        // Not asserting the exact method set: a plain JVM unit test has no real Build.VERSION.SDK_INT, so
        // effectiveMethods() drops DEVICE_CREDENTIAL as it would pre-Android-11 - the live SDK-dependent behavior is
        // covered by AndroidKeystoreSignerPolicyTest (the pure function) and the instrumented AndroidKeystoreSignerTest.
        assertTrue(s.securityProperties(keyId).userAuthentication.isNotEmpty())
        try {
            s.sign(keyId, byteArrayOf(1))
            fail("expected user_authentication_required")
        } catch (e: KeystoreException) {
            assertEquals("user_authentication_required", e.errorCode)
        }
        assertFalse("no authenticator: no SCA", s.scaAuthenticationCapability(keyId).isPossible)
    }

    @Test
    fun everyUseKey_signsAfterTheAuthenticatorApproves_andReachesTwoScaCategories() = runTest {
        val b = FakeBackend()
        val authenticator = UserAuthenticator { request -> request.allowed.first() }
        val s = signer(b, authenticator = authenticator)
        val created = s.createKey(KeyPolicy(HardwareRequirement.ANY, UserAuthentication.EveryUse(setOf(AuthenticationMethod.BIOMETRIC))))
        val keyId = created.keyId
        assertTrue(s.scaAuthenticationCapability(keyId).isPossible)
        val raw = s.sign(keyId, "hello".toByteArray())
        assertEquals(64, raw.size)
        val session = s.beginScaSign(keyId)
        assertEquals(
            setOf(AuthenticationCategory.POSSESSION, AuthenticationCategory.INHERENCE),
            session.declaredFactors.map { it.category }.toSet(),
        )
        val signed = session.sign("transaction".toByteArray())
        ScaSignSession.requireMatching(session.declaredFactors, signed.factors)
        assertEquals(64, signed.signature.size)
    }

    @Test
    fun everyUseKey_refusesWhenTheAuthenticatorApprovesAMethodTheKeyDoesNotAllow() = runTest {
        val b = FakeBackend()
        // The authenticator claims a method outside what the key's policy allows.
        val authenticator = UserAuthenticator { AuthenticationMethod.DEVICE_CREDENTIAL }
        val s = signer(b, authenticator = authenticator)
        val created = s.createKey(KeyPolicy(HardwareRequirement.ANY, UserAuthentication.EveryUse(setOf(AuthenticationMethod.BIOMETRIC))))
        try {
            s.sign(created.keyId, byteArrayOf(1))
            fail("expected user_authentication_failed")
        } catch (e: KeystoreException) {
            assertEquals("user_authentication_failed", e.errorCode)
        }
    }

    @Test
    fun scaSignSession_signsOnlyOnce() = runTest {
        val b = FakeBackend()
        val authenticator = UserAuthenticator { request -> request.allowed.first() }
        val s = signer(b, authenticator = authenticator)
        val created = s.createKey(KeyPolicy(HardwareRequirement.ANY, UserAuthentication.EveryUse(setOf(AuthenticationMethod.BIOMETRIC))))
        val session = s.beginScaSign(created.keyId)
        session.sign(byteArrayOf(1))
        try {
            session.sign(byteArrayOf(2))
            fail("a session must sign once")
        } catch (_: IllegalStateException) {
        }
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Signing, export, listing, migration, dispatcher placement.
    // ---------------------------------------------------------------------------------------------------------------

    @Test
    fun signReturnsARaw64ByteSignatureThatVerifiesWithTheExportedPublicKey() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val id = s.generateKey("ES256")
        val data = "DeviceAuthentication".toByteArray()
        val raw = s.sign(id, data)
        assertEquals(64, raw.size)
        assertTrue(BigInteger(1, raw.copyOfRange(32, 64)) <= EcdsaSignatures.P256_ORDER.shiftRight(1))
        val jwk = Json.parseToJsonElement(String(s.exportPublicKey(id))) as JsonObject
        val x = Base64.getUrlDecoder().decode((jwk["x"] as JsonPrimitive).content)
        val y = Base64.getUrlDecoder().decode((jwk["y"] as JsonPrimitive).content)
        val params = java.security.AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        val publicKey = java.security.KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.ECPublicKeySpec(java.security.spec.ECPoint(BigInteger(1, x), BigInteger(1, y)), params),
        )
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(data)
            verify(EcdsaSignatures.rawToDer(raw))
        }
        assertTrue(ok)
    }

    @Test
    fun theExportedPublicKeyIsAP256JwkWithTheKeyIdAsKid() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val id = s.generateKey("ES256")
        val jwk = Json.parseToJsonElement(String(s.exportPublicKey(id))) as JsonObject
        assertEquals("P-256", (jwk["crv"] as JsonPrimitive).content)
        // kid carries the key id so WscdKeystoreAdapter/SirosWallet.extractProofKeyId can recover which holder key an
        // embedded-JWK proof was made with (a multi-key mdoc batch would otherwise fall back to the wrong key).
        assertEquals(id, (jwk["kid"] as JsonPrimitive).content)
    }

    @Test
    fun listAndDeleteOnlyTouchTheSignersOwnKeys_evenAcrossOverlappingPrefixes() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val a = s.generateKey("ES256")
        val other = AndroidKeystoreSigner(b, aliasPrefix = "${AndroidKeystoreSigner.DEFAULT_ALIAS_PREFIX}other.")
        val bKey = other.generateKey("ES256")
        assertEquals(listOf(a), s.listKeys().map { it.keyId })
        s.deleteKey(a)
        assertTrue(s.listKeys().isEmpty())
        assertEquals(listOf(bKey), other.listKeys().map { it.keyId })
        other.deleteKey(bKey)
    }

    @Test
    fun refusesUnknownKeys() = runTest {
        val s = signer(FakeBackend())
        try {
            s.sign("no-such-key", byteArrayOf(1))
            fail("expected key_not_found")
        } catch (e: KeystoreException) {
            assertEquals("key_not_found", e.errorCode)
        }
    }

    @Test
    fun keysAreDeviceBound() = runTest {
        val s = signer(FakeBackend())
        val id = s.generateKey("ES256")
        assertTrue(s.exportPrivateKeypairs().isEmpty())
        assertEquals(MigrationResult.ReEnrollmentRequired(id), s.migrateKey(id, "softkey"))
    }

    @Test
    fun theSignerAnnouncesTheAttestationCapability() = runTest {
        val s = signer(FakeBackend())
        assertTrue(s.supportsAttestedKeyGeneration)
    }

    @Test
    fun hardwareKeyGenerationAndSigningNeverRunOnTheCallersDispatcher() = runTest {
        val b = FakeBackend()
        val s = signer(b)
        val caller = Thread.currentThread().name
        val attestedId = s.generateAttestedKey("ES256", ByteArray(32) { 1 })
        val attestedOn = b.generatedOn!!
        s.generateKey("ES256")
        val plainOn = b.generatedOn!!
        val createdId = s.createKey(KeyPolicy(HardwareRequirement.ANY)).keyId
        val policyOn = b.generatedOn!!
        s.sign(attestedId, byteArrayOf(1))
        assertTrue("attested generation ran on $attestedOn, the caller is $caller", attestedOn.startsWith("DefaultDispatcher") && attestedOn != caller)
        assertTrue("plain generation ran on $plainOn", plainOn.startsWith("DefaultDispatcher"))
        assertTrue("policy generation ran on $policyOn", policyOn.startsWith("DefaultDispatcher"))
        assertTrue("signing ran on ${b.signedOn}", b.signedOn!!.startsWith("DefaultDispatcher"))
        assertTrue(createdId.isNotEmpty())
    }
}
