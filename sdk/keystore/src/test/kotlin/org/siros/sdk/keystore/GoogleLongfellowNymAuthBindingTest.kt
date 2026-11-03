// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.nio.ByteBuffer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import uniffi.nymauth_native.LongfellowCircuitParams
import uniffi.nymauth_native.NymAuthNativeException as NativeException
import uniffi.nymauth_native.NymAuthRefusal as NativeRefusal

/** The Google Longfellow binding's glue (the native library itself does not load on the JVM; see the instrumented test). */
class GoogleLongfellowNymAuthBindingTest {

    private fun request(params: Map<String, JsonPrimitive>) = NymAuthProveRequest(
        NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM, "nymauth-longfellow-mdoc-v1", "sha256:aa", JsonObject(params),
        ByteBuffer.allocate(4).asReadOnlyBuffer(), ByteArray(1), ByteArray(16), ByteArray(32), ByteArray(32),
        "2026-10-20T12:00:00Z", "0000-00-00", "9999-12-31", ByteArray(32), ByteArray(64), ByteArray(32), ByteArray(32),
    )

    private val good = mapOf(
        "hash_circuit_id" to JsonPrimitive(HASH_ID),
        "sig_circuit_id" to JsonPrimitive(SIG_ID),
        "block_enc_hash" to JsonPrimitive("6983"),
        "block_enc_sig" to JsonPrimitive(4679),
    )

    @Test
    fun `serves longfellow-nymauth as google-longfellow-zk`() {
        assertEquals(NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM, GoogleLongfellowNymAuthBinding.system)
        assertEquals("google-longfellow-zk", GoogleLongfellowNymAuthBinding.implementation)
    }

    @Test
    fun `is the default for longfellow-nymauth, and ISRG is one swap away`() {
        val default = UniffiNymAuthNativeProver()
        assertEquals("google-longfellow-zk", default.implementationFor(NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM))
        assertEquals("zk-cred-vega", default.implementationFor(NymAuthCircuitZkAdapter.VEGA_SYSTEM))
        val isrg = UniffiNymAuthNativeProver.withBindings(ZkCredLongfellowNymAuthBinding)
        assertEquals("zk-cred-longfellow", isrg.implementationFor(NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM))
        assertEquals("zk-cred-vega", isrg.implementationFor(NymAuthCircuitZkAdapter.VEGA_SYSTEM))
    }

    @Test
    fun `params come from the descriptor, numbers as strings or numbers`() {
        assertEquals(
            LongfellowCircuitParams(blockEncHash = 6983u, blockEncSig = 4679u, hashCircuitId = HASH_ID, sigCircuitId = SIG_ID),
            GoogleLongfellowNymAuthBinding.params(request(good)),
        )
    }

    @Test
    fun `a missing or malformed parameter is an invalid circuit`() {
        val broken = listOf(
            good - "hash_circuit_id",
            good - "sig_circuit_id",
            good - "block_enc_hash",
            good - "block_enc_sig",
            good + ("hash_circuit_id" to JsonPrimitive(5)),
            good + ("block_enc_hash" to JsonPrimitive("-1")),
            good + ("block_enc_sig" to JsonPrimitive("4679.5")),
            good + ("block_enc_sig" to JsonPrimitive("99999999999")),
        )
        for (p in broken) {
            val e = assertThrows(NymAuthNativeException::class.java) { GoogleLongfellowNymAuthBinding.params(request(p)) }
            assertEquals(p.toString(), NymAuthNativeErrorKind.INVALID_CIRCUIT, e.kind)
        }
    }

    @Test
    fun `every library error maps to its kind, with no message of the library`() {
        val cases = listOf(
            NativeException.InvalidInput() to NymAuthNativeErrorKind.INVALID_INPUT,
            NativeException.InvalidCircuit() to NymAuthNativeErrorKind.INVALID_CIRCUIT,
            NativeException.UnsupportedCircuit() to NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT,
            NativeException.ProverFailed() to NymAuthNativeErrorKind.PROVER_FAILED,
            NativeException.ProofInvalid() to NymAuthNativeErrorKind.PROOF_INVALID,
            NativeException.Mismatch() to NymAuthNativeErrorKind.MISMATCH,
            NativeException.Internal() to NymAuthNativeErrorKind.INTERNAL,
        )
        for ((native, kind) in cases) {
            val e = GoogleLongfellowNymAuthBinding.mapped(native)
            assertEquals(kind, e.kind)
            assertNull(e.refusal)
            assertEquals("nymauth native prover: $kind", e.message)
        }
    }

    @Test
    fun `every refusal keeps its reason`() {
        val reasons = mapOf(
            NativeRefusal.SEED_MISMATCH to NymAuthRefusal.SEED_MISMATCH,
            NativeRefusal.ISSUER_SIGNATURE to NymAuthRefusal.ISSUER_SIGNATURE,
            NativeRefusal.DEVICE_SIGNATURE to NymAuthRefusal.DEVICE_SIGNATURE,
            NativeRefusal.CREDENTIAL to NymAuthRefusal.CREDENTIAL,
            NativeRefusal.UNSATISFIED to NymAuthRefusal.UNSATISFIED,
        )
        assertEquals("every refusal of the library is covered", NativeRefusal.entries.toSet(), reasons.keys)
        for ((native, sdk) in reasons) {
            val e = GoogleLongfellowNymAuthBinding.mapped(NativeException.Refused(native))
            assertEquals(NymAuthNativeErrorKind.REFUSED, e.kind)
            assertEquals(sdk, e.refusal)
        }
    }

    private companion object {
        const val HASH_ID = "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729"
        const val SIG_ID = "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb"
    }
}
