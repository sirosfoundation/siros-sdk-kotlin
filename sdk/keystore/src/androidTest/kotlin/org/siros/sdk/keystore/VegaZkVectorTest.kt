// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.github.luben.zstd.Zstd
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.zk_cred_vega.FfiClaim
import uniffi.zk_cred_vega.FfiEcdsaWitness
import uniffi.zk_cred_vega.FfiMsoBodyWitness
import uniffi.zk_cred_vega.prepProve
import uniffi.zk_cred_vega.prove
import uniffi.zk_cred_vega.verify
import java.nio.ByteBuffer

/**
 * Exercises the real, vendored `zk_cred_vega` UniFFI bindings directly
 * against the exact real setup keys (`dump_setup`, see this test's resource
 * README) and the native crate's own real, signed test vector
 * (`test-vectors/mdl_4claims_mixed_disclosure.json` - a genuinely realistic
 * mdoc credential with real CBOR framing, real ≥16-byte per-element salts,
 * and a real ECDSA-P256 signature over the real MSO `Sig_structure`, not a
 * self-fabricated toy fixture) - not through [VegaProofSystem], since that
 * class's own witness-extraction ([VegaProofSystem]'s `buildWitness`) is
 * deliberately unimplemented (see its doc comment for why). This instead
 * validates the exact same low-level calls a finished
 * [VegaProofSystem] would make (`deserializeProverKey`/`deserializeVerifierKey`,
 * `prep_prove`, `prove`, `verify`, `ByteBuffer` marshaling) against the real
 * native library, confirming the FFI wiring genuinely works end-to-end from
 * Kotlin - not just that it compiles. Mirrors [LongfellowZkVectorTest]'s
 * role and scope for the Longfellow crate.
 *
 * Instrumented (`androidTest`), not a plain unit test: the native
 * `zk_cred_vega` UniFFI library only loads on a real Android ABI, never in
 * a JVM unit test - same reasoning as [LongfellowZkVectorTest]. Run with
 * `./gradlew :sdk:keystore:connectedDebugAndroidTest`.
 *
 * Resources: `vega-mc-p256-v1-{prover,verifier}-key.bin.zst` are the exact
 * `zk_cred_vega::setup()` output (bincode-serialized `ProverKey`/`VerifierKey`),
 * zstd-compressed, generated via `cargo run --release --bin dump_setup` in
 * the `zk-cred-vega` crate at commit `c4e6a35` (the P0-1-fixed, r7-catalog
 * HEAD as of this test) - NOT yet published to `go-zk-circuits`'s live
 * manifest (see the handoff doc's "What's NOT ready yet" #2), so this test
 * bundles its own copy rather than fetching one. `mdl_4claims_mixed_disclosure.json`
 * is the crate's own `test-vectors/` fixture, copied verbatim.
 */
@RunWith(AndroidJUnit4::class)
class VegaZkVectorTest {

    companion object {
        private const val PROVER_KEY_RESOURCE = "zk-cred-vega/vega-mc-p256-v1-prover-key.bin.zst"
        private const val VERIFIER_KEY_RESOURCE = "zk-cred-vega/vega-mc-p256-v1-verifier-key.bin.zst"
        private const val TEST_VECTOR_RESOURCE = "zk-cred-vega/mdl_4claims_mixed_disclosure.json"

        /**
         * The setup keys' own uncompressed size (confirmed via `dump_setup`'s
         * own printed byte counts at generation time) - `Zstd.getFrameContentSize`
         * already reads this from the frame header, so this is only a sanity
         * floor, mirroring [LongfellowZkVectorTest]'s own decompression
         * convention.
         */
        private const val MIN_EXPECTED_KEY_SIZE = 100_000_000L
    }

    private fun loadResource(name: String): ByteArray {
        val stream = javaClass.classLoader!!.getResourceAsStream(name)
            ?: error("test resource not found: $name")
        return stream.use { it.readBytes() }
    }

    /**
     * The vendored UniFFI bindings' `&[u8]` parameters need a DIRECT
     * `ByteBuffer` - same requirement as [LongfellowZkProofSystem]'s own
     * `directByteBuffer`.
     */
    private fun directByteBuffer(bytes: ByteArray): ByteBuffer =
        ByteBuffer.allocateDirect(bytes.size).put(bytes).apply { flip() }

    private fun loadCompressedResource(name: String): ByteArray {
        val compressed = loadResource(name)
        val size = Zstd.getFrameContentSize(compressed)
        check(size >= MIN_EXPECTED_KEY_SIZE) { "zstd frame content size ($size) smaller than expected for a real setup key" }
        return Zstd.decompress(compressed, size.toInt())
    }

    /**
     * Decompresses and deserializes the prover key in its own call frame -
     * the ~110MB decompressed `ByteArray` becomes unreachable the instant
     * this function returns, rather than staying live for the rest of the
     * test method alongside the verifier key's own ~110MB array. The test
     * process's heap growth limit is 256MB; holding both decompressed keys
     * live at once (confirmed via a real `OutOfMemoryError` on-device before
     * this fix) exceeds that, even though each key alone fits comfortably -
     * neither key needs the other's raw bytes once its own native handle
     * exists, so there's no reason to hold both.
     */
    private fun loadProverKey() = uniffi.zk_cred_vega.deserializeProverKey(directByteBuffer(loadCompressedResource(PROVER_KEY_RESOURCE)))

    /** See [loadProverKey]'s doc comment for why this is its own function. */
    private fun loadVerifierKey() = uniffi.zk_cred_vega.deserializeVerifierKey(directByteBuffer(loadCompressedResource(VERIFIER_KEY_RESOURCE)))

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private data class TestVector(
        val claims: List<FfiClaim>,
        val disclosedElementIdentifiers: List<String>,
        val ecdsaWitness: FfiEcdsaWitness,
        val msoBody: FfiMsoBodyWitness,
    )

    private fun loadTestVector(): TestVector {
        val json = Json.parseToJsonElement(String(loadResource(TEST_VECTOR_RESOURCE))).jsonObject

        val disclosedIdentifiers = mutableListOf<String>()
        val claims = json["claims"]!!.jsonArray.map { claimJson ->
            val obj = claimJson.jsonObject
            val disclose = obj["disclose"]!!.jsonPrimitive.boolean
            if (disclose) disclosedIdentifiers.add(obj["element_identifier"]!!.jsonPrimitive.content)
            FfiClaim(
                issuerSignedItemBytes = hexToBytes(obj["issuer_signed_item_bytes_hex"]!!.jsonPrimitive.content),
                disclose = disclose,
                digestId = obj["digest_id"]!!.jsonPrimitive.content.toUInt(),
            )
        }

        val ecdsa = json["ecdsa_witness"]!!.jsonObject
        val ecdsaWitness = FfiEcdsaWitness(
            qx = hexToBytes(ecdsa["qx_hex"]!!.jsonPrimitive.content),
            qy = hexToBytes(ecdsa["qy_hex"]!!.jsonPrimitive.content),
            r = hexToBytes(ecdsa["r_hex"]!!.jsonPrimitive.content),
            s = hexToBytes(ecdsa["s_hex"]!!.jsonPrimitive.content),
            sInv = hexToBytes(ecdsa["s_inv_hex"]!!.jsonPrimitive.content),
        )

        val mso = json["mso_body"]!!.jsonObject
        val msoBody = FfiMsoBodyWitness(
            deviceX = hexToBytes(mso["device_x_hex"]!!.jsonPrimitive.content),
            deviceY = hexToBytes(mso["device_y_hex"]!!.jsonPrimitive.content),
            signedTs = mso["signed_ts"]!!.jsonPrimitive.content.toByteArray(Charsets.US_ASCII),
            validFromTs = mso["valid_from_ts"]!!.jsonPrimitive.content.toByteArray(Charsets.US_ASCII),
            validUntilTs = mso["valid_until_ts"]!!.jsonPrimitive.content.toByteArray(Charsets.US_ASCII),
        )

        return TestVector(claims, disclosedIdentifiers, ecdsaWitness, msoBody)
    }

    /**
     * Full round trip against the real crate: `prep_prove` -> `prove` ->
     * `verify`, confirming the proof verifies and that disclosed/undisclosed
     * claims come back exactly as the test vector declared them (real
     * plaintext for `family_name`/`given_name`, all-zero for
     * `birth_date`/`age_over_18`) - mirrors the crate's own
     * `tests/real_mdoc_fixtures.rs` but from Kotlin, through the actual
     * `#[uniffi::export]` boundary.
     */
    @Test
    fun proveAndVerify_realMdocVector_succeeds() {
        val vector = loadTestVector()

        val proveResult = loadProverKey().let { proverKey ->
            val prepState = prepProve(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody)
            prove(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody, prepState)
        }

        assertTrue("proof must be non-empty", proveResult.proofBytes.isNotEmpty())
        assertTrue("nextState must be non-empty", proveResult.nextState.isNotEmpty())

        val verifyResult = verify(loadVerifierKey(), proveResult.proofBytes)

        assertArrayEquals(vector.ecdsaWitness.qx, verifyResult.qx)
        assertArrayEquals(vector.ecdsaWitness.qy, verifyResult.qy)
        assertArrayEquals(vector.msoBody.deviceX, verifyResult.deviceX)
        assertArrayEquals(vector.msoBody.deviceY, verifyResult.deviceY)
        assertEquals(vector.claims.size, verifyResult.claims.size)

        for ((index, claim) in vector.claims.withIndex()) {
            val disclosed = verifyResult.claims[index]
            assertEquals("claim $index disclosed flag", claim.disclose, disclosed.disclosed)
            assertEquals("claim $index digestId", claim.digestId, disclosed.digestId)
            if (claim.disclose) {
                assertTrue("claim $index should have real plaintext when disclosed", disclosed.plaintext.isNotEmpty())
            } else {
                assertFalse(
                    "claim $index plaintext should be all-zero when undisclosed",
                    disclosed.plaintext.any { it != 0.toByte() },
                )
            }
        }
    }

    /**
     * Confirms fold-and-reuse works: a second `prove` call using the first
     * call's own `nextState` (skipping `prep_prove`) still produces a
     * verifiable proof - exactly the reuse path
     * [org.siros.sdk.credentials.ZkProofResult.nextState]/
     * [org.siros.sdk.credentials.ZkProofSystem.generateProof]'s `priorState`
     * exist for.
     */
    @Test
    fun prove_reusingPriorState_stillVerifies() {
        val vector = loadTestVector()

        val secondProve = loadProverKey().let { proverKey ->
            val prepState = prepProve(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody)
            val firstProve = prove(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody, prepState)
            prove(proverKey, vector.claims, vector.ecdsaWitness, vector.msoBody, firstProve.nextState)
        }

        val verifyResult = verify(loadVerifierKey(), secondProve.proofBytes)
        assertArrayEquals(vector.ecdsaWitness.qx, verifyResult.qx)
    }
}
