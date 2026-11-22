package org.siros.sdk.transport.wmp

// The wallet's MLS crypto (issue #77 + the wmp-mls spec, RFC 9420):
// in-process OpenMLS via the UniFFI bindings (uniffi/engine_adapter_sdk —
// the same Rust `wmp-mls` crate the engine runs, one crypto everywhere;
// the relay is the Delivery Service: it routes and queues ciphertext,
// it never holds plaintext).
//
// The member's identity: its WMP identifier string (the sender the
// session names). The groups it holds are the groups it belongs to.
//
// The wire forms (spec §4.2): every MLS artefact — the KeyPackage, the
// Welcome, the Commit, the application ciphertext — crosses WMP
// base64url-encoded inside its JSON member.
//
// Kotlin parity: the Swift SDK's `WmpMlsCrypto` mirrors this shape.

/**
 * The wallet's MLS member crypto: ONE provider per identity (one
 * identity, one key store), the groups it belongs to.
 *
 * The surface mirrors the Rust FFI (`WmpMls`): [generateKeyPackage],
 * [createGroup], [processWelcome], [addMember], [removeMember],
 * [processCommit], [selfUpdate], [encrypt], [decrypt] — each answering
 * the wire-shape data the WMP message paths carry.
 *
 * A group's id is the group's own MLS GroupId (base64url): the SAME id on
 * every member (the shared GroupContext), so a member can address a group
 * its creator named — [createGroup] and [processWelcome] answer the same
 * string for the same group.
 */
class WmpMlsCrypto(identity: String) {

    private val inner: uniffi.engine_adapter_sdk.WmpMls =
        uniffi.engine_adapter_sdk.WmpMls(identity)

    /** The member's identity (the string the constructor took). */
    val identity: String get() = inner.identity()

    /**
     * A fresh KeyPackage (spec §2.3) for the suite: publish it on the
     * member's well-known for the add flows.
     */
    fun generateKeyPackage(cipherSuite: Long): MlsKeyPackage =
        inner.generateKeyPackage(cipherSuite).let {
            MlsKeyPackage(id = it.id, cipherSuite = it.cipherSuite, keyPackage = it.keyPackage)
        }

    /**
     * Create a group (spec §3.1): THIS member's group, epoch 0. The
     * members join by the add flow ([addMember]) once their KeyPackages
     * are at hand.
     */
    fun createGroup(cipherSuite: Long): MlsGroupCreated =
        inner.createGroup(cipherSuite).let {
            MlsGroupCreated(groupId = it.groupId, epoch = it.epoch)
        }

    /**
     * Process a Welcome (spec §3.2): the member joins the group, the
     * epoch it joined at. The Welcome rides the invitation or the
     * group's message passing (out of band).
     */
    fun processWelcome(welcome: String): MlsJoined =
        inner.processWelcome(welcome).let {
            MlsJoined(groupId = it.groupId, epoch = it.epoch)
        }

    /**
     * Stage an add (spec §3.3): the commit for the group (merged into
     * this member's copy), the Welcome for the added member (hand it
     * over out of band).
     */
    fun addMember(groupId: String, keyPackage: String): MlsAddStaged =
        inner.addMember(groupId, keyPackage).let {
            MlsAddStaged(commit = it.commit, welcome = it.welcome)
        }

    /**
     * Stage a removal (spec §3.4): the commit (merged here) that
     * cryptographically excludes the participant.
     */
    fun removeMember(groupId: String, participant: String): String =
        inner.removeMember(groupId, participant)

    /**
     * Process a commit (a staged add/remove/update this member
     * receives): the epoch it advanced to (the commit is merged).
     */
    fun processCommit(groupId: String, commit: String): Long =
        inner.processCommit(groupId, commit)

    /**
     * A self-update commit (spec §3.5): the post-compromise rotation,
     * merged here. Hand the commit to the group's other members.
     */
    fun selfUpdate(groupId: String): String = inner.selfUpdate(groupId)

    /**
     * Encrypt a message body to the group's current epoch key
     * (spec §4.1): the base64url MLSMessage + the epoch. The relay
     * carries this ciphertext opaque.
     */
    fun encrypt(groupId: String, plaintext: ByteArray): MlsEncrypted =
        inner.encrypt(groupId, plaintext).let {
            MlsEncrypted(ciphertext = it.ciphertext, epoch = it.epoch)
        }

    /**
     * Decrypt the group's ciphertext (spec §4.1): the plaintext + the
     * epoch. A message this member sent itself refuses (MLS ratchets —
     * the recipient's provider answers).
     */
    fun decrypt(groupId: String, ciphertext: String): MlsDecrypted =
        inner.decrypt(groupId, ciphertext).let {
            MlsDecrypted(plaintext = it.plaintext, epoch = it.epoch)
        }
}

/** A member's KeyPackage (spec §2.3): the base64url package, its id, the suite. */
data class MlsKeyPackage(
    /** The minted package id (`kp-<serial>`). */
    val id: String,
    /** The cipher suite (0x0001 X25519 / 0x0002 P-256). */
    val cipherSuite: Long,
    /** The base64url-encoded MLS KeyPackage. */
    val keyPackage: String,
)

/** A group creation: the group's id (its MLS GroupId, base64url), the epoch (0). */
data class MlsGroupCreated(
    /** The group's MLS GroupId (base64url) — the same on every member. */
    val groupId: String,
    /** The epoch the create minted (0). */
    val epoch: Long,
)

/** A Welcome processed: the group joined, the epoch joined at. */
data class MlsJoined(
    /** The group's MLS GroupId (the same id the creator's create answered). */
    val groupId: String,
    /** The epoch the member joined at. */
    val epoch: Long,
)

/** An add staged: the commit for the group, the Welcome for the added member. */
data class MlsAddStaged(
    /** The base64url MLS Commit (merged into this member's group). */
    val commit: String,
    /** The base64url MLS Welcome (hand to the added member). */
    val welcome: String,
)

/** A message encrypted: the base64url MLSMessage, the epoch. */
data class MlsEncrypted(
    /** The base64url MLSMessage (the ciphertext the relay carries). */
    val ciphertext: String,
    /** The epoch the encryption used. */
    val epoch: Long,
)

/** A message decrypted: the plaintext bytes, the epoch. */
data class MlsDecrypted(
    /** The plaintext bytes. */
    val plaintext: ByteArray,
    /** The epoch the ciphertext was encrypted under. */
    val epoch: Long,
)