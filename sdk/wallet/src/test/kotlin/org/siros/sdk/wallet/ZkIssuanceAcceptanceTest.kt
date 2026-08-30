package org.siros.sdk.wallet

import io.mockk.every
import io.mockk.mockk
import java.util.concurrent.ConcurrentHashMap
import kotlin.reflect.full.callSuspend
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.jvm.isAccessible
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.BbsHolderState
import org.siros.sdk.credentials.BbsIssuancePreparation
import org.siros.sdk.credentials.ZkIssuancePreparation
import org.siros.sdk.keystore.BbsHolderStateVault
import org.siros.sdk.keystore.ExtensionStore

/**
 * Accepting an issued blind BBS credential — the second half of the round
 * trip the wallet started by committing.
 *
 * The rule these all circle is that a credential which fails this check must
 * not be stored. It is not a credential with a problem: it is bytes the
 * issuer signed over something other than what the wallet committed to.
 * Storing it hides a mis-issuance until the first presentation fails, by
 * which point nothing points at the cause.
 *
 * Uses the same reflective harness as [SirosWalletTest] — `allocateInstance`
 * plus field injection — because `SirosWallet` needs an Activity it has no
 * use for here.
 */
class ZkIssuanceAcceptanceTest {

    /** An in-memory [ExtensionStore], standing in for a real container. */
    private class FakeExtensionStore : ExtensionStore {
        val entries = mutableMapOf<String, MutableMap<String, String>>()
        override suspend fun extensionEntries(namespace: String): Map<String, String> =
            entries[namespace]?.toMap() ?: emptyMap()
        override suspend fun setExtensionEntry(namespace: String, key: String, value: String) {
            entries.getOrPut(namespace) { mutableMapOf() }[key] = value
        }
        override suspend fun removeExtensionEntry(namespace: String, key: String) {
            entries[namespace]?.remove(key)
        }
    }

    private val holderState = BbsHolderState(
        issuerPublicKey = ByteArray(96) { 1 },
        secretProverBlind = ByteArray(32) { 2 },
        committedMessages = listOf(byteArrayOf(3)),
        keybindPublicKeys = emptyList(),
    )

    private fun preparationAccepting(jwp: String): BbsIssuancePreparation =
        mockk<BbsIssuancePreparation>().also {
            every { it.accept(jwp, any()) } returns holderState
        }

    private fun preparationRejecting(): BbsIssuancePreparation =
        mockk<BbsIssuancePreparation>().also {
            every { it.accept(any(), any()) } throws IllegalStateException("signed over other messages")
        }

    // -----------------------------------------------------------------------

    private class Harness {
        val store = FakeExtensionStore()
        val vault = BbsHolderStateVault(store)
        val preparations = ConcurrentHashMap<String, ZkIssuancePreparation>()
        val wallet: SirosWallet = allocate()

        init {
            set("zkPreparationsByFlow", preparations)
            set("bbsHolderStateVault", vault)
        }

        fun set(name: String, value: Any?) {
            SirosWallet::class.java.getDeclaredField(name).also { it.isAccessible = true }.set(wallet, value)
        }

        fun accept(flowId: String, jwp: String, index: Int): Long? = runBlocking {
            val method = wallet::class.declaredMemberFunctions
                .first { it.name == "acceptZkIssuedCredential" }
            method.isAccessible = true
            method.callSuspend(wallet, flowId, jwp, index) as Long?
        }

        private companion object {
            /** Same reflective allocation [SirosWalletTest] uses. */
            fun allocate(): SirosWallet {
                val unsafeClass = Class.forName("sun.misc.Unsafe")
                val unsafe = unsafeClass.getDeclaredField("theUnsafe")
                    .also { it.isAccessible = true }
                    .get(null)
                return unsafeClass.getMethod("allocateInstance", Class::class.java)
                    .invoke(unsafe, SirosWallet::class.java) as SirosWallet
            }
        }
    }

    private fun harness(input: ZkIssuanceInput? = ZkIssuanceInput("{}", issuerPublicKey = ByteArray(96))) =
        Harness().also { it.set("activeZkIssuanceInput", input) }

    // -----------------------------------------------------------------------

    /** The ordinary path: accepted, persisted, and the id handed back. */
    @Test
    fun anAcceptedCredentialGetsItsHolderStatePersisted() {
        val h = harness()
        h.preparations["flow-1"] = preparationAccepting("the.jwp.here")

        val credentialId = h.accept("flow-1", "the.jwp.here", 0)

        assertNotNull("an accepted credential must be storable", credentialId)
        assertEquals(
            "the state must land under the credential's own id",
            holderState,
            runBlocking { h.vault.get(credentialId.toString()) },
        )
        assertTrue(
            "the preparation is spent once the credential is accepted",
            h.preparations.isEmpty(),
        )
    }

    /**
     * A credential that does not match the commitment must not be stored,
     * and its holder state must not be written either.
     *
     * Writing the state anyway would be worse than storing nothing: a later
     * presentation would find state, use it, and fail somewhere with no
     * connection back to the issuer having signed the wrong thing.
     */
    @Test
    fun aMismatchedCredentialIsRefusedAndNothingIsPersisted() {
        val h = harness()
        h.preparations["flow-1"] = preparationRejecting()

        assertNull(h.accept("flow-1", "wrong.jwp.here", 0))
        assertTrue(
            "no holder state may be written for a credential that was refused",
            h.store.entries[BbsHolderStateVault.NAMESPACE].orEmpty().isEmpty(),
        )
    }

    /**
     * A refusal must leave the preparation in place.
     *
     * It is the only record of what this flow committed to. Consuming it on
     * failure would leave the flow unable to say what went wrong and unable
     * to retry against the same commitment.
     */
    @Test
    fun aRefusalDoesNotSpendThePreparation() {
        val h = harness()
        h.preparations["flow-1"] = preparationRejecting()

        h.accept("flow-1", "wrong.jwp.here", 0)

        assertEquals(1, h.preparations.size)
    }

    /**
     * One commitment authorises exactly one credential.
     *
     * A batch is how the wallet gets unlinkable copies of an ordinary
     * credential, and it is tempting to treat BBS the same way. It is not:
     * each copy would need its own commitment and its own blinding factor.
     * Accepting a second credential against the first one's preparation
     * would store state that describes different messages than the
     * credential it is filed under.
     */
    @Test
    fun aSecondCredentialAgainstOneCommitmentIsRefused() {
        val h = harness()
        h.preparations["flow-1"] = preparationAccepting("the.jwp.here")

        assertNotNull(h.accept("flow-1", "the.jwp.here", 0))
        h.preparations["flow-1"] = preparationAccepting("second.jwp.here")
        assertNull(
            "nothing authorised a second credential",
            h.accept("flow-1", "second.jwp.here", 1),
        )
    }

    /** A flow that committed to nothing has nothing to accept. */
    @Test
    fun aFlowWithNoPreparationIsNotThisPath() {
        assertNull(harness().accept("flow-unknown", "anything", 0))
    }

    /**
     * Without the issuer's key there is no check to perform, so there is
     * nothing to accept.
     *
     * `zkIssuanceExtras` refuses this combination before committing, so
     * reaching here means something cleared the input mid-flow. Storing the
     * credential regardless would mean storing one whose signature was never
     * checked against the commitment at all.
     */
    @Test
    fun withoutAnIssuerKeyNothingIsAccepted() {
        val h = harness(input = ZkIssuanceInput("{}", issuerPublicKey = null))
        h.preparations["flow-1"] = preparationAccepting("the.jwp.here")

        assertNull(h.accept("flow-1", "the.jwp.here", 0))
        assertTrue(h.store.entries[BbsHolderStateVault.NAMESPACE].orEmpty().isEmpty())
    }
}
