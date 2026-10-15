// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import uniffi.siros_wscd_manager.FfiAuthCallback
import uniffi.siros_wscd_manager.FfiAuthFactor
import uniffi.siros_wscd_manager.FfiAuthFactors
import uniffi.siros_wscd_manager.FfiFactorCapability
import uniffi.siros_wscd_manager.FfiFactorCategory
import uniffi.siros_wscd_manager.FfiSignOptions
import uniffi.siros_wscd_manager.FfiSignOutcome
import uniffi.siros_wscd_manager.FfiSignature
import uniffi.siros_wscd_manager.FfiWscdException

class FactorSigningTest {
    private val remote = AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_remote_wscd")
    private val external = AuthenticationFactor(AuthenticationCategory.POSSESSION, "key_in_local_external_wscd")
    private val pin6 = AuthenticationFactor(AuthenticationCategory.KNOWLEDGE, "pin_6_or_more_digits")
    private val face = AuthenticationFactor(AuthenticationCategory.INHERENCE, "face_device")

    private fun ffi(c: AuthenticationCategory, m: String) = FfiAuthFactor(
        when (c) {
            AuthenticationCategory.KNOWLEDGE -> FfiFactorCategory.KNOWLEDGE
            AuthenticationCategory.POSSESSION -> FfiFactorCategory.POSSESSION
            AuthenticationCategory.INHERENCE -> FfiFactorCategory.INHERENCE
        },
        m,
    )

    private fun outcome(vararg f: FfiAuthFactor, two: Boolean = true, sig: ByteArray = byteArrayOf(7)) =
        FfiSignOutcome(FfiSignature(sig), FfiAuthFactors(f.toList(), two, if (two) null else "short"))

    /** The plugin's side: asks for the PIN [pinRequests] times during the sign, then reports [result]. */
    private class FakeBackend(
        var capability: FfiFactorCapability = FfiFactorCapability(true, false, null),
        var plugin: String? = "r2ps",
        var pinRequests: Int = 1,
        var result: () -> FfiSignOutcome,
    ) : FactorSigningBackend {
        var seenOptions: FfiSignOptions? = null
        var seenData: ByteArray? = null
        /** The buffers given to the plugin, and what each held at the moment it was given. */
        val pinBuffers = mutableListOf<ByteArray>()
        val pinsAsSeen = mutableListOf<String>()
        var capabilityThrows = false
        override fun capability(kid: String): FfiFactorCapability {
            if (capabilityThrows) throw IllegalStateException("no such key")
            return capability
        }
        override fun pluginIdOf(kid: String) = plugin
        override fun signWithFactors(kid: String, data: ByteArray, options: FfiSignOptions, auth: FfiAuthCallback): FfiSignOutcome {
            seenOptions = options
            seenData = data
            repeat(pinRequests) {
                val p = auth.requestPin(plugin ?: "?")
                pinBuffers += p
                pinsAsSeen += String(p)
            }
            return result()
        }
    }

    private class Prompts(vararg pins: String) : FfiAuthCallback {
        private val queue = ArrayDeque(pins.map { it.toByteArray() })
        val handedOut = mutableListOf<ByteArray>()
        override fun requestPin(pluginId: String): ByteArray {
            val p = queue.removeFirstOrNull() ?: throw FfiWscdException.AuthCancelled("no more")
            handedOut += p
            return p
        }
        override fun requestWebauthnAssertion(pluginId: String, challenge: ByteArray, rpId: String, allowedCredentials: List<ByteArray>): ByteArray =
            throw FfiWscdException.AuthCancelled("no webauthn")
        val asked get() = handedOut.size
    }

    private fun refused(block: () -> Unit): TransactionDataError {
        val e = runCatching(block).exceptionOrNull()
        assertTrue(e.toString(), e is TransactionDataError)
        assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, (e as TransactionDataError).reason)
        return e
    }

    // ── classification mirrors siros-wscd-manager classify_secret ──

    @Test
    fun `classifySecret follows the wscd manager's measured classes`() {
        fun c(s: String) = FactorSigning.classifySecret(s.toByteArray())
        assertEquals("pin_less_than_6_digits", c("12345"))
        assertEquals("pin_6_or_more_digits", c("123456"))
        assertEquals("passphrase_less_than_8_chars", c("abcdefg"))
        assertEquals("passphrase_less_than_8_chars", c("12345a"))
        assertEquals("passphrase_8_to_11_chars", c("abcdefgh"))
        assertEquals("passphrase_8_to_11_chars", c("abcdefghijk"))
        assertEquals("passphrase_12_or_more_chars", c("abcdefghijkl"))
        // characters, not bytes or UTF-16 units: 7 supplementary-plane characters are 7
        assertEquals("passphrase_less_than_8_chars", c("😀".repeat(7)))
        assertEquals("passphrase_8_to_11_chars", c("😀".repeat(8)))
        // a non-ASCII digit is not a PIN digit
        assertEquals("passphrase_less_than_8_chars", c("١٢٣٤٥٦"))
    }

    @Test
    fun `classifySecret does not guess for an empty or non-UTF-8 secret`() {
        assertNull(FactorSigning.classifySecret(ByteArray(0)))
        assertNull(FactorSigning.classifySecret(byteArrayOf(0xC3.toByte(), 0x28)))
        // a truncated multi-byte sequence at the end is malformed too
        assertNull(FactorSigning.classifySecret(byteArrayOf('1'.code.toByte(), 0xE2.toByte(), 0x82.toByte())))
    }

    // ── capability ──

    @Test
    fun `capability is the managers answer, and never a guess when it cannot be had`() {
        val b = FakeBackend(capability = FfiFactorCapability(false, true, "why")) { outcome() }
        val c = FactorSigning(b, Prompts()).capability("k")
        assertFalse(c.canReachTwoCategories)
        assertTrue(c.requiresHostVerifiedFactor)
        assertEquals("why", c.reason)

        b.capabilityThrows = true
        assertFalse(FactorSigning(b, Prompts()).capability("k").isPossible)
    }

    // ── a signer that reaches two categories itself (PIN) ──

    @Test
    fun `a PIN session claims possession from the plugin and the measured PIN class, asking once`() = runTest {
        val prompts = Prompts("123456")
        val b = FakeBackend(plugin = "r2ps") { outcome(ffi(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"), ffi(AuthenticationCategory.KNOWLEDGE, "pin_6_or_more_digits")) }
        val fs = FactorSigning(b, prompts)

        fs.begin("k", null).use { s ->
            assertEquals(setOf(remote, pin6), s.declaredFactors.toSet())
            val signed = s.sign(byteArrayOf(1, 2, 3))
            ScaSignSession.requireMatching(s.declaredFactors, signed.factors)
            assertArrayEquals(byteArrayOf(7), signed.signature)
        }

        assertEquals("the user is prompted once, not once for the claim and once for the sign", 1, prompts.asked)
        assertEquals("123456", b.pinsAsSeen.single())
        assertTrue(b.seenOptions!!.requireFreshUserAuthentication)
        assertNull(b.seenOptions!!.hostVerifiedFactor)
        assertArrayEquals(byteArrayOf(1, 2, 3), b.seenData)
    }

    @Test
    fun `every PIN buffer given to the plugin is wiped when the sign ends, and the SDK's own copy too`() = runTest {
        val prompts = Prompts("123456", "654321")
        val b = FakeBackend(pinRequests = 2) {
            outcome(ffi(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"), ffi(AuthenticationCategory.KNOWLEDGE, "pin_6_or_more_digits"))
        }

        FactorSigning(b, prompts).begin("k", null).use { it.sign(ByteArray(1)) }

        assertEquals(listOf("123456", "654321"), b.pinsAsSeen)
        assertEquals(2, b.pinBuffers.size)
        assertTrue("the buffers the plugin was given are zeroed", b.pinBuffers.all { buf -> buf.all { it == 0.toByte() } })
        assertTrue("the host's array the SDK held is zeroed", prompts.handedOut.all { buf -> buf.all { it == 0.toByte() } })
    }

    @Test
    fun `buffers are wiped even when the sign fails`() = runTest {
        val prompts = Prompts("123456")
        val b = FakeBackend { throw FfiWscdException.AuthCancelled("cancelled") }

        FactorSigning(b, prompts).begin("k", null).use { runCatching { it.sign(ByteArray(1)) } }

        assertTrue(b.pinBuffers.single().all { it == 0.toByte() })
    }

    @Test
    fun `a session that never signs wipes the PIN typed ahead on close`() {
        val prompts = Prompts("123456")
        FactorSigning(FakeBackend { outcome() }, prompts).begin("k", null).close()
        assertTrue(prompts.handedOut.single().all { it == 0.toByte() })
    }

    @Test
    fun `a second PIN request from the plugin goes to the user again, and a different class then fails the match`() = runTest {
        val prompts = Prompts("123456", "1234")
        val b = FakeBackend(pinRequests = 2) {
            // the plugin measured the LAST PIN it was given
            outcome(ffi(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"), ffi(AuthenticationCategory.KNOWLEDGE, "pin_less_than_6_digits"))
        }

        FactorSigning(b, prompts).begin("k", null).use { s ->
            val signed = s.sign(ByteArray(1))
            assertEquals(2, prompts.asked)
            refused { ScaSignSession.requireMatching(s.declaredFactors, signed.factors) }
        }
    }

    @Test
    fun `a FIDO2 key claims the external-token possession`() {
        val b = FakeBackend(plugin = "fido2") { outcome() }
        FactorSigning(b, Prompts("123456")).begin("k", null).use {
            assertEquals(setOf(external, pin6), it.declaredFactors.toSet())
        }
    }

    @Test
    fun `begin refuses when the manager says two categories are unreachable, before any prompt`() {
        val prompts = Prompts("123456")
        val b = FakeBackend(capability = FfiFactorCapability(false, false, "softkey is single factor")) { outcome() }

        val e = refused { FactorSigning(b, prompts).begin("k", null) }

        assertTrue(e.message!!.contains("softkey"))
        assertEquals(0, prompts.asked)
    }

    @Test
    fun `begin refuses a plugin that establishes no possession factor, and an unknown plugin`() {
        for (plugin in listOf("softkey", "mystery", null)) {
            val prompts = Prompts("123456")
            val b = FakeBackend(plugin = plugin) { outcome() }
            refused { FactorSigning(b, prompts).begin("k", null) }
            assertEquals("no PIN is asked for a key that cannot satisfy SCA", 0, prompts.asked)
        }
    }

    @Test
    fun `begin refuses when the class of the typed secret cannot be determined`() {
        val b = FakeBackend { outcome() }
        refused { FactorSigning(b, Prompts("")).begin("k", null) }
    }

    @Test
    fun `begin refuses when the user does not enter a PIN`() {
        refused { FactorSigning(FakeBackend { outcome() }, Prompts()).begin("k", null) }
    }

    // ── a signer that needs the host's factor ──

    private val needsHost = FfiFactorCapability(false, true, "UV observed, method unknown")

    @Test
    fun `a host session claims the host factor and passes it to the sign without asking for a PIN`() = runTest {
        val prompts = Prompts("123456")
        val b = FakeBackend(capability = needsHost, plugin = "fido2", pinRequests = 0) {
            outcome(ffi(AuthenticationCategory.POSSESSION, "key_in_local_external_wscd"), ffi(AuthenticationCategory.INHERENCE, "face_device"))
        }

        FactorSigning(b, prompts).begin("k", face).use { s ->
            assertEquals(setOf(external, face), s.declaredFactors.toSet())
            ScaSignSession.requireMatching(s.declaredFactors, s.sign(ByteArray(1)).factors)
        }

        assertEquals(0, prompts.asked)
        assertEquals(FfiAuthFactor(FfiFactorCategory.INHERENCE, "face_device"), b.seenOptions!!.hostVerifiedFactor)
        assertTrue(b.seenOptions!!.requireFreshUserAuthentication)
    }

    @Test
    fun `a host session is refused without a host factor or with a possession one`() {
        val b = FakeBackend(capability = needsHost, plugin = "r2ps") { outcome() }
        refused { FactorSigning(b, Prompts()).begin("k", null) }
        refused { FactorSigning(b, Prompts()).begin("k", remote) }
    }

    @Test
    fun `a host factor is not passed to a signer that reaches two categories itself`() = runTest {
        val b = FakeBackend { outcome(ffi(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"), ffi(AuthenticationCategory.KNOWLEDGE, "pin_6_or_more_digits")) }

        FactorSigning(b, Prompts("123456")).begin("k", face).use { s ->
            assertEquals(setOf(remote, pin6), s.declaredFactors.toSet())
            s.sign(ByteArray(1))
        }

        assertNull(b.seenOptions!!.hostVerifiedFactor)
    }

    // ── the sign's own report ──

    @Test
    fun `a flagged sign the plugin cannot honour is a refusal`() = runTest {
        val b = FakeBackend { throw FfiWscdException.Unsupported("no fresh auth") }
        FactorSigning(b, Prompts("123456")).begin("k", null).use { s ->
            val e = runCatching { s.sign(ByteArray(1)) }.exceptionOrNull()
            assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, (e as TransactionDataError).reason)
        }
    }

    @Test
    fun `a report short of two categories, or outside the vocabulary, is a refusal`() = runTest {
        for (r in listOf(
            { outcome(ffi(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"), two = false) },
            { outcome(ffi(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"), FfiAuthFactor(FfiFactorCategory.KNOWLEDGE, "pwd")) },
        )) {
            FactorSigning(FakeBackend(result = r), Prompts("123456")).begin("k", null).use { s ->
                val e = runCatching { s.sign(ByteArray(1)) }.exceptionOrNull()
                assertEquals(TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, (e as TransactionDataError).reason)
            }
        }
    }

    @Test
    fun `other plugin failures propagate and are not turned into a signature`() = runTest {
        val b = FakeBackend { throw FfiWscdException.AuthCancelled("user cancelled") }
        FactorSigning(b, Prompts("123456")).begin("k", null).use { s ->
            val e = runCatching { s.sign(ByteArray(1)) }.exceptionOrNull()
            assertTrue(e.toString(), e is FfiWscdException.AuthCancelled)
        }
    }

    @Test
    fun `a session signs once`() = runTest {
        val b = FakeBackend { outcome(ffi(AuthenticationCategory.POSSESSION, "key_in_remote_wscd"), ffi(AuthenticationCategory.KNOWLEDGE, "pin_6_or_more_digits")) }
        FactorSigning(b, Prompts("123456")).begin("k", null).use { s ->
            s.sign(ByteArray(1))
            assertTrue(runCatching { s.sign(ByteArray(1)) }.exceptionOrNull() is IllegalStateException)
        }
    }

    @Test
    fun `requireMatching demands equal sets and two categories`() {
        ScaSignSession.requireMatching(listOf(remote, pin6), listOf(pin6, remote))
        refused { ScaSignSession.requireMatching(listOf(remote, pin6), listOf(remote)) }
        refused { ScaSignSession.requireMatching(listOf(remote, pin6), listOf(remote, face)) }
        refused { ScaSignSession.requireMatching(listOf(remote, pin6), emptyList()) }
        refused { ScaSignSession.requireMatching(listOf(remote), listOf(remote)) }
    }
}
