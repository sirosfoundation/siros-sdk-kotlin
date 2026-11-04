// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.nio.ByteBuffer
import kotlinx.serialization.json.JsonObject

/**
 * The proving ABI of the `nymauth-*` circuits, as the circuit authors define it (`SPEC.md` of their
 * `nym-auth-circuits` archive: §3 and §L3-L6 for Longfellow, §V3-V5 for Vega): one narrow call that takes
 * the verified circuit bytes and the already-assembled inputs and returns the proof and the pseudonym.
 *
 * This is the seam where native code is needed and none is shipped yet: the vendored `zk_cred_longfellow`
 * and `zk_cred_vega` bindings expose the generic mdoc/age circuits only, with no entry point that builds the
 * nymauth witnesses (Longfellow's hash-circuit semantic bits and signature-circuit ECDSA trace, Vega's table
 * and core witness) or runs the two-circuit / multi-circuit proof. The circuit authors' reference
 * implementations (`longfellow/reference`, `vega/reference`) are Rust. Until a binding implements this
 * interface the [NymAuthCircuitZkAdapter] refuses every request; it never substitutes another proof.
 *
 * An implementation must not log or retain any argument: [NymAuthProveRequest.secretSeed] is the issuer-delivered
 * seed and the circuit input is private.
 */
fun interface NymAuthNativeProver {
    /**
     * Proves [request]; any failure is an exception, which [CatalogCircuitZkProver] turns into a refusal. A failure of
     * the binding itself is a [NymAuthNativeException].
     */
    suspend fun prove(request: NymAuthProveRequest): NymAuthProveResponse
}

/**
 * An optional extension of [NymAuthNativeProver] for a prover that keeps native state resident between proofs (Vega's
 * keys and Longfellow's loaded circuits are hundreds of MB): the adapter tells it when to let go.
 */
interface ResidentNymAuthNativeProver : NymAuthNativeProver {
    /** Drops the resident native state (memory pressure, the host leaving the foreground). Never throws. */
    fun release()

    /** Drops the resident native state if it belongs to the circuit [circuitId] (a retired one). Never throws. */
    fun releaseCircuit(circuitId: String)
}

/** The coarse reason a native prover refused to make a proof (never the broken rule, never a value). */
enum class NymAuthRefusal { SEED_MISMATCH, ISSUER_SIGNATURE, DEVICE_SIGNATURE, CREDENTIAL, UNSATISFIED }

/** The kinds of failure a native nymauth binding reports: a superset of the Vega and the Longfellow error types. */
enum class NymAuthNativeErrorKind {
    /** An argument has the wrong size, format or range (Vega `InvalidInput`, Longfellow `InvalidInput`). */
    INVALID_INPUT,

    /** The circuit artifact is malformed or past its budget (Vega `InvalidShapes`, Longfellow `Circuit`). */
    INVALID_CIRCUIT,

    /**
     * The circuit is well formed but not one this build knows (Vega `UnknownCircuit`, whose message is the shapes'
     * digest; Longfellow `UnsupportedCircuit`): this app version does not support this circuit build.
     */
    UNSUPPORTED_CIRCUIT,

    /** The inputs break a rule; see [NymAuthRefusal] (Vega `Refused{code}`, Longfellow `Credential` and `Unsatisfied`). */
    REFUSED,

    /** The prover failed (Vega `ProverFailed`, Longfellow `Prover`). */
    PROVER_FAILED,

    /** The proof does not verify (Vega `ProofInvalid`, Longfellow `Verification`). */
    PROOF_INVALID,

    /** The proof verifies, but not for the named values (Vega `Mismatch`). */
    MISMATCH,

    /** A bug in the binding (Vega `Internal`, a caught panic). */
    INTERNAL,
}

/**
 * What a [NymAuthNativeProver] throws for a failure of the binding. It carries a [kind] and, for [NymAuthNativeErrorKind.REFUSED],
 * a coarse [refusal], and NO message: the bindings' own messages can hold a circuit digest or a rule, and
 * nothing of them is kept. A binding's glue maps its own error type here (see [vega] and [longfellow]).
 */
class NymAuthNativeException(val kind: NymAuthNativeErrorKind, val refusal: NymAuthRefusal? = null) :
    Exception("nymauth native prover: $kind" + (refusal?.let { " ($it)" } ?: "")) {

    companion object {
        /** The Vega binding's error by variant name and, for `Refused`, its coarse `code` (`SeedMismatch`, ...). */
        fun vega(variant: String, refusedCode: String? = null): NymAuthNativeException = when (variant) {
            "InvalidInput" -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_INPUT)
            "InvalidShapes" -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT)
            "UnknownCircuit" -> NymAuthNativeException(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT)
            "Refused" -> NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, refusalOf(refusedCode))
            "ProverFailed" -> NymAuthNativeException(NymAuthNativeErrorKind.PROVER_FAILED)
            "ProofInvalid" -> NymAuthNativeException(NymAuthNativeErrorKind.PROOF_INVALID)
            "Mismatch" -> NymAuthNativeException(NymAuthNativeErrorKind.MISMATCH)
            else -> NymAuthNativeException(NymAuthNativeErrorKind.INTERNAL)
        }

        /** The Longfellow binding's `NymAuthError` by variant name. */
        fun longfellow(variant: String): NymAuthNativeException = when (variant) {
            "InvalidInput" -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_INPUT)
            "Circuit" -> NymAuthNativeException(NymAuthNativeErrorKind.INVALID_CIRCUIT)
            "UnsupportedCircuit" -> NymAuthNativeException(NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT)
            "Credential" -> NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, NymAuthRefusal.CREDENTIAL)
            "Unsatisfied" -> NymAuthNativeException(NymAuthNativeErrorKind.REFUSED, NymAuthRefusal.UNSATISFIED)
            "Prover" -> NymAuthNativeException(NymAuthNativeErrorKind.PROVER_FAILED)
            "Verification" -> NymAuthNativeException(NymAuthNativeErrorKind.PROOF_INVALID)
            else -> NymAuthNativeException(NymAuthNativeErrorKind.INTERNAL)
        }

        private fun refusalOf(code: String?) = when (code) {
            "SeedMismatch" -> NymAuthRefusal.SEED_MISMATCH
            "IssuerSignature" -> NymAuthRefusal.ISSUER_SIGNATURE
            "DeviceSignature" -> NymAuthRefusal.DEVICE_SIGNATURE
            "Credential" -> NymAuthRefusal.CREDENTIAL
            // A code this build does not know is still a refusal; it is not guessed at.
            else -> NymAuthRefusal.UNSATISFIED
        }
    }
}

/**
 * What [NymAuthNativeProver.prove] receives. Everything here is derived by the SDK from the stored
 * credential, the verifier's request and the device signer; the native side does not parse the request.
 *
 * @property system The catalog `system` of the circuit: [NymAuthCircuitZkAdapter.LONGFELLOW_SYSTEM] or
 *   [NymAuthCircuitZkAdapter.VEGA_SYSTEM].
 * @property circuitParams The catalog descriptor's `params` (Longfellow: `block_enc_hash`, `block_enc_sig`,
 *   `hash_circuit_id`, `sig_circuit_id`), verbatim.
 * @property circuit The decompressed circuit artifact, its hash verified against the catalog (Longfellow:
 *   the two LFC2 circuits, signature then hash; Vega: the bincode `(STEP, CORE)` shapes, from which the native
 *   side derives its keys). Read-only; do not retain it past the call.
 * @property issuerSigned The credential's `IssuerSigned` structure as CBOR.
 * @property secretSeed The 16-byte issuer-delivered `secret_seed`, already checked against `ssc`.
 * @property issuerKeyX Big-endian x of the issuer key Q (the `x5chain` leaf), 32 bytes.
 * @property time `T`: `YYYY-MM-DDThh:mm:ssZ`, 20 ASCII characters.
 * @property earliest `E`: `YYYY-MM-DD`, `0000-00-00` for no lower bound.
 * @property cutoff `C`: `YYYY-MM-DD`, `9999-12-31` for no upper bound.
 * @property challengeDigest `e2`: SHA-256 of the COSE `Signature1` message the device key signed.
 * @property deviceSignature The device key's ES256 signature on that message, `r || s`, 64 bytes.
 * @property verifierInput `SHA-256(verifier_id)`, 32 bytes.
 * @property transcriptSeed The SessionTranscript the proof is bound to (Longfellow's Fiat-Shamir seed).
 */
class NymAuthProveRequest(
    val system: String,
    val circuitId: String,
    /** The catalog artifact hash the [circuit] bytes were verified against: with [circuitId], what a resident native state is keyed by. */
    val artifactHash: String,
    val circuitParams: JsonObject,
    val circuit: ByteBuffer,
    val issuerSigned: ByteArray,
    val secretSeed: ByteArray,
    val issuerKeyX: ByteArray,
    val issuerKeyY: ByteArray,
    val time: String,
    val earliest: String,
    val cutoff: String,
    val challengeDigest: ByteArray,
    val deviceSignature: ByteArray,
    val verifierInput: ByteArray,
    val transcriptSeed: ByteArray,
) {
    override fun toString() = "NymAuthProveRequest(redacted)"
}

/** What [NymAuthNativeProver.prove] returns: the proof bytes as the circuit's own verifier reads them, and the pseudonym it reports. */
class NymAuthProveResponse(val proof: ByteArray, val pseudonym: ByteArray) {
    override fun toString() = "NymAuthProveResponse(redacted)"
}


