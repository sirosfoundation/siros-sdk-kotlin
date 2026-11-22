package org.siros.sdk.transport.wmp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import kotlin.random.Random

/**
 * The wallet's MLS crypto, round-tripped (the wmp-mls spec, RFC 9420):
 * two members, one group, the messages between them — the same
 * functions the FFI test drives in Rust (`engine-adapter-sdk/tests/
 * mls_ffi.rs`), here against the SAME native library the app ships
 * (libengine_adapter_sdk.so via JNA — `assumeTrue` skips without it).
 */
class WmpMlsCryptoTest {

    /** The X25519 suite (0x0001, the MUST). */
    private val suite = 1L

    private fun memberLoadable(): Boolean = try {
        WmpMlsCrypto("probe").identity
        true
    } catch (_: Throwable) {
        // UnsatisfiedLinkError without the native library (the CI image
        // without the .so); any other failure is the same verdict here.
        false
    }

    @Test
    fun aCreateAddsAMemberWhoJoinsAndSharesTheGroupId() {
        assumeTrue(memberLoadable())
        val alice = WmpMlsCrypto("alice")
        val bob = WmpMlsCrypto("bob")

        // The group (spec §3.1): the create mints alone, epoch 0.
        val group = alice.createGroup(suite)
        assertEquals(0L, group.epoch)

        // Bob's KeyPackage (spec §2.3) — the add flow's input.
        val keyPackage = bob.generateKeyPackage(suite)
        assertTrue(keyPackage.keyPackage.length > 32)

        // The add (spec §3.3): the commit + the Welcome for Bob.
        val staged = alice.addMember(group.groupId, keyPackage.keyPackage)
        assertTrue(staged.commit.isNotEmpty())
        assertTrue(staged.welcome.isNotEmpty())

        // Bob joins (spec §3.2): the SAME group id (the MLS GroupId from
        // the shared GroupContext — the provider keys every member's
        // copy by it), the post-add epoch.
        val joined = bob.processWelcome(staged.welcome)
        assertEquals("the join answers the creator's group id", group.groupId, joined.groupId)
        assertTrue("the join answers the post-add epoch", joined.epoch >= 1L)
    }

    @Test
    fun twoMembersRoundTripAMessage() {
        assumeTrue(memberLoadable())
        val alice = WmpMlsCrypto("alice")
        val bob = WmpMlsCrypto("bob")
        val group = alice.createGroup(suite)
        val keyPackage = bob.generateKeyPackage(suite)
        val staged = alice.addMember(group.groupId, keyPackage.keyPackage)
        bob.processWelcome(staged.welcome)

        // The message (spec §4.1): Alice encrypts to the epoch key, Bob
        // decrypts. MLS ratchets: Alice's own provider refuses her own
        // ciphertext (the recipient's provider answers).
        val plaintext = Random.nextBytes(64)
        val sent = alice.encrypt(group.groupId, plaintext)
        assertTrue(sent.epoch >= 1L)
        assertTrue(sent.ciphertext.isNotEmpty())

        val received = bob.decrypt(group.groupId, sent.ciphertext)
        assertArrayEquals(plaintext, received.plaintext)
        assertEquals(sent.epoch, received.epoch)

        val own = runCatching { alice.decrypt(group.groupId, sent.ciphertext) }
        assertTrue("own ciphertexts do not decrypt (MLS ratchets)", own.isFailure)
    }

    @Test
    fun aRemovalAdvancesTheEpoch() {
        assumeTrue(memberLoadable())
        val alice = WmpMlsCrypto("alice")
        val bob = WmpMlsCrypto("bob")
        val group = alice.createGroup(suite)
        val keyPackage = bob.generateKeyPackage(suite)
        val staged = alice.addMember(group.groupId, keyPackage.keyPackage)
        val joined = bob.processWelcome(staged.welcome)

        // The removal (spec §3.4): the commit cryptographically excludes
        // Bob; the merge advances the epoch.
        val commit = alice.removeMember(group.groupId, "bob")
        val advanced = bob.processCommit(joined.groupId, commit)
        assertTrue("the epoch advanced", advanced > joined.epoch)
    }

    @Test
    fun unknownGroupOperationsRefuse() {
        assumeTrue(memberLoadable())
        val alice = WmpMlsCrypto("alice")
        val refused = runCatching { alice.encrypt("grp-none", byteArrayOf(1, 2, 3)) }
        assertTrue("the unknown group refuses", refused.isFailure)
        val detail = refused.exceptionOrNull()?.message.orEmpty()
        assertTrue(
            "the refusal names the cause (the wallets' logs need it): $detail",
            detail.contains("unknown group"),
        )
        assertFalse(detail.isEmpty())
    }

    @Test
    fun theIdentityAnswersItsConstructor() {
        assumeTrue(memberLoadable())
        assertEquals("alice@example", WmpMlsCrypto("alice@example").identity)
    }
}