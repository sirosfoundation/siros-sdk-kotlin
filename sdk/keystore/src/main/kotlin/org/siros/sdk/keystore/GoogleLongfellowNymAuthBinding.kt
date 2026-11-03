// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.nio.ByteBuffer
import kotlinx.serialization.json.JsonPrimitive
import timber.log.Timber
import uniffi.nymauth_native.LongfellowCircuitParams
import uniffi.nymauth_native.LongfellowProveRequest
import uniffi.nymauth_native.LongfellowProver
import uniffi.nymauth_native.NymAuthNativeException as NativeException
import uniffi.nymauth_native.NymAuthRefusal as NativeRefusal

/**
 * The Longfellow nymauth binding over nymauth-native (`native/nymauth-native`): the nym_auth mdoc circuits on
 * Google's longfellow-zk Rust runtime (`61a8a73`), through community-demo's `nym-longfellow`, the code its verifier
 * runs. The default for `longfellow-nymauth`; [ZkCredLongfellowNymAuthBinding] (ISRG) is the alternative
 * (`UniffiNymAuthNativeProver.withBindings(ZkCredLongfellowNymAuthBinding)`). Proofs are about 344 kB against
 * zk-cred-longfellow's 619 kB, and each implementation verifies the other's.
 *
 * `load` builds the resident prover from the decompressed circuit, the descriptor's `block_enc_hash`,
 * `block_enc_sig`, `hash_circuit_id` and `sig_circuit_id`, and the artifact hash; the library loads only its approved
 * build. `prove` hands the request over field for field; the library checks the inputs (including that `e2` is the
 * DeviceAuthentication digest of the transcript) and the holder's data before it proves, and zeroes its copies of
 * the seed. Every error becomes a [NymAuthNativeException] with no message of the library.
 */
object GoogleLongfellowNymAuthBinding : NymAuthBinding {
    override val system: String = NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM
    override val implementation: String = IMPLEMENTATION

    override fun load(request: NymAuthProveRequest): AutoCloseable = try {
        LongfellowProver.load(bytes(request.circuit), params(request), request.artifactHash)
    } catch (e: NativeException) {
        throw mapped(e)
    }

    override fun prove(handle: AutoCloseable, request: NymAuthProveRequest): NymAuthProveResponse {
        val seed = request.secretSeed.copyOf()
        return try {
            val proved = (handle as LongfellowProver).prove(
                LongfellowProveRequest(
                    issuerSigned = request.issuerSigned,
                    secretSeed = seed,
                    issuerKeyX = request.issuerKeyX,
                    issuerKeyY = request.issuerKeyY,
                    time = request.time,
                    earliest = request.earliest,
                    cutoff = request.cutoff,
                    challengeDigest = request.challengeDigest,
                    deviceSignature = request.deviceSignature,
                    verifierInput = request.verifierInput,
                    transcriptSeed = request.transcriptSeed,
                ),
            )
            val m = proved.metrics
            Timber.d("nymauth-native Longfellow: witness %.0f ms, prove %.0f ms, heap %s MB", m.witnessMs, m.proveMs, m.heapMb)
            NymAuthProveResponse(proved.proof, proved.pseudonym)
        } catch (e: NativeException) {
            throw mapped(e)
        } finally {
            seed.fill(0)
        }
    }

    /** The implementation id ([NymAuthBinding.implementation]). */
    const val IMPLEMENTATION: String = "google-longfellow-zk"

    /** The descriptor's parameters as the library takes them; a missing or malformed one is an invalid circuit. */
    internal fun params(request: NymAuthProveRequest): LongfellowCircuitParams {
        val p = request.circuitParams
        fun text(key: String) = (p[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT)
        fun number(key: String): UInt = (p[key] as? JsonPrimitive)?.content?.toUIntOrNull()
            ?: throw NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT)
        return LongfellowCircuitParams(
            blockEncHash = number("block_enc_hash"),
            blockEncSig = number("block_enc_sig"),
            hashCircuitId = text("hash_circuit_id"),
            sigCircuitId = text("sig_circuit_id"),
        )
    }

    /** The library's error as the SDK's: the kind, and for a refusal its reason; never a message. */
    internal fun mapped(e: NativeException): NymAuthNativeException = when (e) {
        is NativeException.InvalidInput -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_INPUT)
        is NativeException.InvalidCircuit -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT)
        is NativeException.UnsupportedCircuit -> NymAuthNativeException(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT)
        is NativeException.Refused -> NymAuthNativeException(
            NymAuthNativeErrorKind.REFUSED,
            when (e.refusal) {
                NativeRefusal.SEED_MISMATCH -> NymAuthRefusal.SEED_MISMATCH
                NativeRefusal.ISSUER_SIGNATURE -> NymAuthRefusal.ISSUER_SIGNATURE
                NativeRefusal.DEVICE_SIGNATURE -> NymAuthRefusal.DEVICE_SIGNATURE
                NativeRefusal.CREDENTIAL -> NymAuthRefusal.CREDENTIAL
                NativeRefusal.UNSATISFIED -> NymAuthRefusal.UNSATISFIED
            },
        )
        is NativeException.ProverFailed -> NymAuthNativeException(NymAuthNativeErrorKind.PROVER_FAILED)
        is NativeException.ProofInvalid -> NymAuthNativeException(NymAuthNativeErrorKind.PROOF_INVALID)
        is NativeException.Mismatch -> NymAuthNativeException(NymAuthNativeErrorKind.MISMATCH)
        is NativeException.Internal -> NymAuthNativeException(NymAuthNativeErrorKind.INTERNAL)
    }

    /** The circuit's bytes (a copy: the buffer is the caller's). */
    private fun bytes(circuit: ByteBuffer): ByteArray {
        val src = circuit.duplicate()
        return ByteArray(src.remaining()).also { src.get(it) }
    }
}
