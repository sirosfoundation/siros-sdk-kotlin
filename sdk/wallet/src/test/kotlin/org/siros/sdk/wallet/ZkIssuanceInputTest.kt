package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.ZkWitnessSigner

class ZkIssuanceInputTest {

    private val signer = ZkWitnessSigner { _, _ -> ByteArray(64) }

    /** The ordinary case: nothing to bind to, so nothing to sign with. */
    @Test
    fun anUnboundIssuanceNeedsNoSigner() {
        val input = ZkIssuanceInput(holderClaimsJson = """{"device_pin_hash":"abc"}""")
        assertTrue(input.keybindPublicKeys.isEmpty())
        assertEquals(null, input.signer)
    }

    /**
     * A key binding key with no signer must be rejected at construction.
     *
     * Not a defensive check: the commit challenge is signed once per key, and
     * a key committed without that signature is a credential bound to a key
     * nobody proved they hold. Failing here — before any issuance starts —
     * is the difference between an argument error and a credential whose
     * binding is worthless.
     */
    @Test
    fun aKeyBindingKeyWithoutASignerIsRejected() {
        val thrown = assertThrows(IllegalArgumentException::class.java) {
            ZkIssuanceInput(
                holderClaimsJson = "{}",
                keybindPublicKeys = listOf(ByteArray(48)),
            )
        }
        assertTrue(
            "the message should say what is missing, got: ${thrown.message}",
            thrown.message.orEmpty().contains("signer"),
        )
    }

    @Test
    fun aKeyBindingKeyWithASignerIsAccepted() {
        val input = ZkIssuanceInput(
            holderClaimsJson = "{}",
            keybindPublicKeys = listOf(ByteArray(48) { 1 }),
            signer = signer,
        )
        assertEquals(1, input.keybindPublicKeys.size)
        assertEquals(signer, input.signer)
    }
}
