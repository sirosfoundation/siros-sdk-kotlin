package org.siros.sdk.keystore

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class WscdKeystoreAdapterTest {

    private fun createMockSigner(): Signer = mockk<Signer>(relaxed = true).also {
        coEvery { it.generateKey(any()) } returns "test-key-1"
        coEvery { it.sign(any(), any()) } returns ByteArray(64) { it.toByte() }
        coEvery { it.listKeys() } returns listOf(
            SignerKeyInfo("test-key-1", "ES256")
        )
        coEvery { it.exportPublicKey(any()) } returns """{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}""".toByteArray()
        coEvery { it.deleteKey(any()) } returns Unit
        coEvery { it.attestationChain(any()) } returns null
        coEvery { it.securityProperties(any()) } returns SignerSecurityProperties(
            keyStorage = listOf("hardware"),
            userAuthentication = listOf("pin"),
            certification = org.siros.sdk.credentials.CertificationInfo.Certified(
                scheme = "EUCC",
                assuranceLevel = "substantial",
            ),
        )
    }

    @Test
    fun initiallyLocked() {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        assertFalse(adapter.isUnlocked)
    }

    @Test
    fun unlockSetsState() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))
        assertTrue(adapter.isUnlocked)
    }

    @Test
    fun lockClearsState() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))
        assertTrue(adapter.isUnlocked)
        adapter.lock()
        assertFalse(adapter.isUnlocked)
    }

    @Test
    fun lockClearsCredentials() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        // Store a credential
        adapter.saveCredential("cred-1", """{"type":"VerifiableCredential"}""")
        assertNotNull(adapter.getCredential("cred-1"))

        // Lock should clear
        adapter.lock()

        // After re-unlock, credential should be gone
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))
        assertEquals(null, adapter.getCredential("cred-1"))
    }

    @Test
    fun generateKeyDelegatesToSigner() = runTest {
        val signer = createMockSigner()
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val keyId = adapter.generateKey("ES256")
        assertEquals("test-key-1", keyId)
        coVerify { signer.generateKey("ES256") }
    }

    @Test
    fun signDelegatesToSigner() = runTest {
        val signer = createMockSigner()
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val sig = adapter.sign("test-key-1", "hello".toByteArray(), "ES256")
        assertEquals(64, sig.size)
        coVerify { signer.sign("test-key-1", "hello".toByteArray()) }
    }

    @Test(expected = IllegalStateException::class)
    fun signThrowsWhenLocked() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.sign("key", "data".toByteArray(), "ES256")
    }

    @Test(expected = IllegalStateException::class)
    fun generateKeyThrowsWhenLocked() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.generateKey()
    }

    @Test
    fun listKeysDelegatesToSigner() = runTest {
        val signer = createMockSigner()
        val adapter = WscdKeystoreAdapter(signer)

        val keys = adapter.listKeys()
        assertEquals(1, keys.size)
        assertEquals("test-key-1", keys[0].keyId)
    }

    @Test(expected = org.siros.sdk.credentials.KeystoreException::class)
    fun exportEncryptedContainerThrowsWhenLocked() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.exportEncryptedContainer()
    }

    @Test
    fun exportAndRestoreCredentialsRoundTrip() = runTest {
        val prfOutput = ByteArray(32) { it.toByte() }
        val hkdfSalt = ByteArray(32) { (it * 2).toByte() }
        val hkdfInfo = "test-info".toByteArray()

        val adapter1 = WscdKeystoreAdapter(createMockSigner())
        adapter1.unlock(prfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        // Realistic shape: EncryptedCredentialStore always saves the full
        // StoredCredential JSON (id/format/raw/kid/...) - the underlying
        // JweKeystore container only round-trips the privatedata-spec's
        // normative fields (format/kid/raw as "data"), not arbitrary JSON.
        adapter1.saveCredential("cred-1", """{"id":"cred-1","format":"vc+sd-jwt","raw":"header.payload.sig","kid":"key-1"}""")
        val exported = adapter1.exportEncryptedContainer()
        assertTrue(exported.isNotEmpty())

        // A fresh adapter, unlocked with the SAME PRF material and the
        // exported container, should recover the credential - this is what
        // makes credentials survive logout+login for WSCD-backed keystores
        // (previously exportEncryptedContainer() just threw, so nothing was
        // ever persisted at all), AND (per privatedata-spec) uses the exact
        // same container format wallet-frontend/JweKeystore-backed native
        // clients use, so the same passkey unlocks the same credentials
        // across any client, not just this WSCD-backed one.
        val adapter2 = WscdKeystoreAdapter(createMockSigner())
        adapter2.unlock(prfOutput, exported, hkdfSalt, hkdfInfo)
        val restored = adapter2.getCredential("cred-1")
        assertNotNull(restored)
        assertTrue(restored!!.contains("\"format\":\"vc+sd-jwt\""))
        assertTrue(restored.contains("header.payload.sig"))
    }

    @Test(expected = Exception::class)
    fun unlockWithWrongPrfOutputThrows() = runTest {
        val hkdfSalt = ByteArray(32) { (it * 2).toByte() }
        val hkdfInfo = "test-info".toByteArray()

        val adapter1 = WscdKeystoreAdapter(createMockSigner())
        adapter1.unlock(ByteArray(32) { it.toByte() }, ByteArray(0), hkdfSalt, hkdfInfo)
        adapter1.saveCredential("cred-1", """{"id":"cred-1","format":"vc+sd-jwt","raw":"x"}""")
        val exported = adapter1.exportEncryptedContainer()

        // A wrong PRF output must fail loudly (not silently start empty) -
        // matches JweKeystore's own existing behavior for a wrong key.
        val adapter2 = WscdKeystoreAdapter(createMockSigner())
        adapter2.unlock(ByteArray(32) { (it + 1).toByte() }, exported, hkdfSalt, hkdfInfo)
    }

    @Test
    fun credentialCRUD() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        // Save
        adapter.saveCredential("id-1", """{"type":"VC"}""")
        adapter.saveCredential("id-2", """{"type":"VC2"}""")

        // Get
        assertEquals("""{"type":"VC"}""", adapter.getCredential("id-1"))
        assertEquals(null, adapter.getCredential("nonexistent"))

        // GetAll
        val all = adapter.getAllCredentials()
        assertEquals(2, all.size)

        // Delete
        adapter.deleteCredential("id-1")
        assertEquals(null, adapter.getCredential("id-1"))
        assertEquals(1, adapter.getAllCredentials().size)

        // Clear
        adapter.clearCredentials()
        assertEquals(0, adapter.getAllCredentials().size)
    }

    @Test
    fun attestationChainReturnsNull() = runTest {
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))
        adapter.generateKey()

        val chain = adapter.attestationChain("test-key-1")
        // MockK returns null for attestationChain
        assertEquals(null, chain)
    }

    @Test
    fun generateKeypairs() = runTest {
        val signer = createMockSigner()
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val keypairs = adapter.generateKeypairs(2)
        assertEquals(2, keypairs.size)
        coVerify(exactly = 2) { signer.generateKey(any()) }
    }

    /** A real, curve-valid P-256 public key JWK JSON - JWK.parse validates curve membership. */
    private fun realPublicKeyJwkJson(): String =
        com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
            .generate().toPublicJWK().toJSONString()

    // ── Signer key round-trip through privatedata (softkey persistence) ──

    private val fakePrfOutput = ByteArray(32) { it.toByte() }
    private val hkdfSalt = ByteArray(32) { (it + 0x10).toByte() }
    private val hkdfInfo = "SIROS Wallet PRF".toByteArray(Charsets.UTF_8)

    @Test
    fun exportEncryptedContainerFoldsInSignersExportablePrivateKeys() = runTest {
        val keyJwk = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
            .keyID("softkey-1").generate().toJSONString()
        val signer = mockk<Signer>(relaxed = true)
        coEvery { signer.exportPrivateKeypairs() } returns listOf(
            ExportedPrivateKeypair(keyId = "softkey-1", algorithm = "ES256", privateJwk = keyJwk)
        )
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)

        adapter.exportEncryptedContainer()

        coVerify(exactly = 1) { signer.exportPrivateKeypairs() }
    }

    @Test
    fun unlockRestoresSignersPreviouslyExportedPrivateKeysFromPrivatedata() = runTest {
        val keyJwk = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
            .keyID("softkey-1").generate().toJSONString()
        val signer = mockk<Signer>(relaxed = true)
        coEvery { signer.exportPrivateKeypairs() } returns listOf(
            ExportedPrivateKeypair(keyId = "softkey-1", algorithm = "ES256", privateJwk = keyJwk)
        )
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        // No keys existed yet on this first (fresh) unlock, so nothing to restore.
        coVerify(exactly = 0) { signer.importPrivateKeypairs(any()) }

        val exported = adapter.exportEncryptedContainer()
        adapter.lock()

        adapter.unlock(fakePrfOutput, exported, hkdfSalt, hkdfInfo)

        coVerify(exactly = 1) {
            signer.importPrivateKeypairs(match { restored ->
                restored.size == 1 &&
                    restored[0].keyId == "softkey-1" &&
                    com.nimbusds.jose.jwk.ECKey.parse(restored[0].privateJwk).d != null
            })
        }
    }

    @Test
    fun signerWithNoExportableKeysNeverTriggersImport() = runTest {
        // The default Signer.exportPrivateKeypairs()/importPrivateKeypairs()
        // no-ops (hardware/remote-HSM plugins have nothing exportable) -
        // exportEncryptedContainer/unlock must stay side-effect-free for them.
        val adapter = WscdKeystoreAdapter(createMockSigner())
        adapter.unlock(fakePrfOutput, ByteArray(0), hkdfSalt, hkdfInfo)
        val exported = adapter.exportEncryptedContainer()
        adapter.lock()

        adapter.unlock(fakePrfOutput, exported, hkdfSalt, hkdfInfo)
        assertTrue(adapter.isUnlocked)
    }

    @Test
    fun generateKeyAttestationBuildsValidJwtWithAttestedKeysAndSecurityProperties() = runTest {
        val signer = createMockSigner()
        coEvery { signer.exportPublicKey(any()) } returns realPublicKeyJwkJson().toByteArray()
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val jwt = adapter.generateKeyAttestation(nonce = "test-nonce-123", count = 3)

        val parsed = com.nimbusds.jwt.SignedJWT.parse(jwt)
        assertEquals("key-attestation+jwt", parsed.header.type.toString())
        assertEquals(com.nimbusds.jose.JWSAlgorithm.ES256, parsed.header.algorithm)
        assertNotNull(parsed.header.jwk)

        val claims = parsed.jwtClaimsSet
        assertEquals("test-nonce-123", claims.getClaim("nonce"))
        val attestedKeys = claims.getClaim("attested_keys") as List<*>
        assertEquals(3, attestedKeys.size)
        // Raw WSCD vocabulary ("hardware"/"pin") must be translated to the
        // OID4VCI spec's registered iso_18045_* values, not passed through -
        // confirmed via a real conformance-test issuer that an unrecognized
        // enum value here gets rejected.
        assertEquals(listOf("iso_18045_moderate"), claims.getClaim("key_storage"))
        assertEquals(listOf("iso_18045_basic"), claims.getClaim("user_authentication"))

        // 3 keys generated for the batch, matching count - not reusing a
        // single pre-existing key.
        coVerify(exactly = 3) { signer.generateKey(any()) }
    }

    @Test
    fun generateKeyAttestationMapsSoftwareKeyStorageToIso18045Basic() = runTest {
        // The exact real-world case that caused a conformance-test issuer to
        // reject the attestation: the "softkey" WSCD plugin reports raw
        // key_storage=["software"], which isn't a registered iso_18045_*
        // value on its own.
        val signer = mockk<Signer>(relaxed = true).also {
            coEvery { it.generateKey(any()) } returns "test-key-1"
            coEvery { it.sign(any(), any()) } returns ByteArray(64) { i -> i.toByte() }
            coEvery { it.exportPublicKey(any()) } returns realPublicKeyJwkJson().toByteArray()
            coEvery { it.securityProperties(any()) } returns SignerSecurityProperties(
                keyStorage = listOf("software"),
                userAuthentication = emptyList(),
            )
        }
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val jwt = adapter.generateKeyAttestation(nonce = "n", count = 1)
        val claims = com.nimbusds.jwt.SignedJWT.parse(jwt).jwtClaimsSet
        assertEquals(listOf("iso_18045_basic"), claims.getClaim("key_storage"))
    }

    @Test
    fun generateKeyAttestationDefaultsKeyStorageWhenSecurityPropertiesUnavailable() = runTest {
        val signer = mockk<Signer>(relaxed = true).also {
            coEvery { it.generateKey(any()) } returns "test-key-1"
            coEvery { it.sign(any(), any()) } returns ByteArray(64) { i -> i.toByte() }
            coEvery { it.exportPublicKey(any()) } returns realPublicKeyJwkJson().toByteArray()
            coEvery { it.securityProperties(any()) } throws IllegalStateException("not supported")
        }
        val adapter = WscdKeystoreAdapter(signer)
        adapter.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0))

        val jwt = adapter.generateKeyAttestation(nonce = "n", count = 1)
        val claims = com.nimbusds.jwt.SignedJWT.parse(jwt).jwtClaimsSet
        assertEquals(listOf("iso_18045_basic"), claims.getClaim("key_storage"))
        assertEquals(null, claims.getClaim("user_authentication"))
    }
}
