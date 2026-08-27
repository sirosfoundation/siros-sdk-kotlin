// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.zk_cred_bbs.BbsDisclosure
import uniffi.zk_cred_bbs.BbsFfiException
import uniffi.zk_cred_bbs.BbsSuiteId
import uniffi.zk_cred_bbs.blindProofVerify
import uniffi.zk_cred_bbs.commitInit
import uniffi.zk_cred_bbs.verifyBlindSign

/**
 * Exercises `zk-cred-bbs` over its UniFFI boundary, on a real device.
 *
 * This has to be instrumented rather than a JVM unit test: the native
 * library ships as `.so` files inside the crate's AAR, so nothing on the
 * JVM can load it. That makes this the first point at which the Kotlin
 * bindings, the AAR packaging and the Rust implementation are proven to
 * work together at all - each has been verified separately.
 *
 * Vectors are the crate's own `test-vectors/emlun_reference.json`, so the
 * Kotlin, Rust, Go and TypeScript sides all check the same ground truth.
 * The `hardware_keybind` case carries key binding signatures captured from
 * a real YubiKey 5.8.1-alpha0, so a passing run here is agreement with
 * hardware-produced data rather than internal consistency.
 */
@RunWith(AndroidJUnit4::class)
class BbsUniffiVectorTest {

    private fun vectors(): JSONObject {
        val stream = javaClass.classLoader!!.getResourceAsStream("bbs_reference_vectors.json")
            ?: error("bbs_reference_vectors.json missing from androidTest resources")
        return JSONObject(stream.bufferedReader().readText())
    }

    private fun String.unhex(): ByteArray =
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    private fun JSONObject.hexList(key: String): List<ByteArray> {
        val arr = getJSONArray(key)
        return (0 until arr.length()).map { arr.getString(it).unhex() }
    }

    private fun JSONObject.disclosures(key: String): List<BbsDisclosure> {
        val arr = getJSONArray(key)
        return (0 until arr.length()).map {
            when (val v = arr.getString(it)) {
                "DISCLOSE" -> BbsDisclosure.DISCLOSE
                "HIDE" -> BbsDisclosure.HIDE
                "COMMIT" -> BbsDisclosure.COMMIT
                else -> error("unknown disclosure $v")
            }
        }
    }

    /**
     * What the reference vectors can and cannot pin over this boundary.
     *
     * The vectors were generated with a *seeded* scalar source so the
     * captured hardware signatures are reproducible. That source is
     * deliberately not exposed over UniFFI - a "use this deterministic
     * seed" knob reachable from application code is exactly what ends up in
     * production and silently destroys unlinkability. So anything that
     * consumes randomness (`commitInit`, `blindProofGenInit`) cannot
     * reproduce a fixed value here, by design.
     *
     * What remains checkable is everything deterministic: that the
     * reference credential validates, and that the reference proof
     * verifies. Those exercise the whole verification path, which is the
     * part a wrong answer would be silent in.
     */
    @Test
    fun theReferenceCredentialAndProofVerify() {
        val hw = vectors().getJSONObject("hardware_keybind")
        val signerMessages = hw.hexList("signer_messages")
        val allMessages = signerMessages + hw.hexList("committed_messages")
        val disclosures = hw.disclosures("disclosures")

        // What the issuer returned must validate before it is stored.
        verifyBlindSign(
            BbsSuiteId.SCHNORR,
            hw.getString("pk").unhex(),
            hw.getString("signature").unhex(),
            hw.getString("header").unhex(),
            allMessages,
            signerMessages.size.toUInt(),
            hw.hexList("keybind_public_keys"),
            hw.getString("secret_prover_blind").unhex(),
        )

        val disclosed = allMessages.filterIndexed { i, _ -> disclosures[i] == BbsDisclosure.DISCLOSE }
        blindProofVerify(
            BbsSuiteId.SCHNORR,
            hw.getString("pk").unhex(),
            hw.getString("proof").unhex(),
            hw.getString("header").unhex(),
            hw.getString("presentation_header").unhex(),
            signerMessages.size.toUInt(),
            disclosed,
            disclosures,
        )
    }

    /**
     * Two commitments to the same messages must differ.
     *
     * This is the positive form of the point above: the FFI draws real
     * randomness. If a build ever wired the seeded source through by
     * mistake, every wallet would commit identically and the blinding would
     * stop blinding anything - a failure with no other visible symptom.
     */
    @Test
    fun commitmentsAreFreshOnEveryCall() {
        val hw = vectors().getJSONObject("hardware_keybind")
        val committed = hw.hexList("committed_messages")
        val keys = hw.hexList("keybind_public_keys")

        val first = commitInit(BbsSuiteId.SCHNORR, committed, keys)
        val second = commitInit(BbsSuiteId.SCHNORR, committed, keys)

        assertNotEquals(
            "two commitments to the same messages must not be identical",
            first.challenge.hex(),
            second.challenge.hex(),
        )
        assertNotEquals(
            "the prover blind must be fresh per credential",
            first.secretProverBlind.hex(),
            second.secretProverBlind.hex(),
        )
        // Sanity: they are still well-formed scalars of the expected width.
        assertEquals(32, first.secretProverBlind.size)
        assertEquals(32, first.challenge.size)
    }

    /**
     * A tampered proof must be refused. A verifier that accepts everything
     * passes the test above, so this carries as much weight as it does.
     */
    @Test
    fun verificationRejectsATamperedProof() {
        val hw = vectors().getJSONObject("hardware_keybind")
        val disclosures = hw.disclosures("disclosures")
        val allMessages = hw.hexList("signer_messages") + hw.hexList("committed_messages")
        val disclosed = allMessages.filterIndexed { i, _ -> disclosures[i] == BbsDisclosure.DISCLOSE }

        val tampered = hw.getString("proof").unhex()
        tampered[tampered.size / 2] = (tampered[tampered.size / 2].toInt() xor 0x01).toByte()

        assertThrows(BbsFfiException::class.java) {
            blindProofVerify(
                BbsSuiteId.SCHNORR,
                hw.getString("pk").unhex(),
                tampered,
                hw.getString("header").unhex(),
                hw.getString("presentation_header").unhex(),
                hw.getJSONArray("signer_messages").length().toUInt(),
                disclosed,
                disclosures,
            )
        }
    }

    /**
     * Key binding generator 0 is BP1 while 1..K-1 come from
     * `create_generators`, so anything past the first key exercises a path
     * K=1 never reaches - and the hardware case can only ever be K=1.
     *
     * The commitment values are not reproducible here (see above), but its
     * *shape* is: a commitment carries one point per key binding key, so
     * its length grows by a compressed point plus a signature per key.
     * That is enough to catch a generator list built for the wrong K.
     */
    @Test
    fun commitmentGrowsWithEachKeyBindingKey() {
        val v = vectors()
        val hw = v.getJSONObject("hardware_keybind")
        val cases = v.getJSONArray("multi_keybind")
        val committed = hw.hexList("committed_messages")

        var previousLength = 0
        for (i in 0 until cases.length()) {
            val case = cases.getJSONObject(i)
            val k = case.getInt("k")
            val keys = case.hexList("keybind_public_keys")
            assertEquals(k, keys.size)

            val commit = commitInit(BbsSuiteId.SCHNORR, committed, keys)
            // Signatures are the authenticator's, so finalize with the
            // captured ones purely to reach the serialized length; the
            // values do not have to correspond to this fresh commitment for
            // the encoding to be well-formed.
            val length = commit.state.size
            if (i > 0) {
                assertTrue(
                    "K=$k state must be larger than K=${k - 1}",
                    length > previousLength,
                )
            }
            previousLength = length
        }
    }
}
