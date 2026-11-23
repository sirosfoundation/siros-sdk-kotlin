// Copyright 2026 SIROS Foundation. BSD-2-Clause License.
package org.siros.sdk.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.transport.wmp.WmpMlsCrypto
import kotlin.random.Random

/**
 * The MLS crypto round-trip ON DEVICE (the release validation's Level 3
 * item): the same two-member lifecycle the JVM suite drives
 * (`WmpMlsCryptoTest`) — here against the APK's OWN native library
 * (`lib/arm64-v8a/libengine_adapter_sdk.so`, the arm64 slice of the
 * wallet-core AAR), the exact .so the release ships.
 */
@RunWith(AndroidJUnit4::class)
class WmpMlsCryptoInstrumentedTest {

    /** The X25519 suite (0x0001, the MUST). */
    private val suite = 1L

    @Test
    fun twoMembersRoundTripOnDevice() {
        val alice = WmpMlsCrypto("alice-device")
        val bob = WmpMlsCrypto("bob-device")
        assertEquals("alice-device", alice.identity)

        // The group + the join (spec §3.1/§3.3/§3.2).
        val group = alice.createGroup(suite)
        assertEquals(0L, group.epoch)
        val package_ = bob.generateKeyPackage(suite)
        val staged = alice.addMember(group.groupId, package_.keyPackage)
        assertTrue(staged.commit.isNotEmpty())
        assertTrue(staged.welcome.isNotEmpty())
        val joined = bob.processWelcome(staged.welcome)
        assertEquals("the join answers the creator's group id (the shared MLS GroupId)", group.groupId, joined.groupId)
        assertTrue(joined.epoch >= 1L)

        // The message (spec §4.1): Alice encrypts under the epoch key,
        // Bob decrypts; Alice's own ciphertext refuses (MLS ratchets).
        val plaintext = Random.nextBytes(48)
        val sent = alice.encrypt(group.groupId, plaintext)
        assertTrue(sent.epoch >= 1L)
        val received = bob.decrypt(group.groupId, sent.ciphertext)
        assertArrayEquals(plaintext, received.plaintext)
        assertEquals(sent.epoch, received.epoch)
        val own = runCatching { alice.decrypt(group.groupId, sent.ciphertext) }
        assertTrue("own ciphertexts do not decrypt (MLS ratchets)", own.isFailure)

        // The removal advances the epoch (spec §3.4, the merge).
        val removal = alice.removeMember(group.groupId, "bob-device")
        val advanced = bob.processCommit(joined.groupId, removal)
        assertTrue("the epoch advanced", advanced > joined.epoch)
    }
}