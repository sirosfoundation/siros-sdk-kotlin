// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.COSE_ALG_ES256
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.NymSeedKind
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.ZkArtifactException
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.credentials.ZkCircuitDescriptor
import org.siros.sdk.keystore.mdoc.MdocCose
import org.siros.sdk.credentials.mdoc.MdocCbor
import timber.log.Timber

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
 * interface a [CatalogCircuitZkProver] refuses every request; it never substitutes another proof.
 *
 * An implementation must not log or retain any argument: [NymAuthProveRequest.secretSeed] is the issuer-delivered
 * seed and the circuit input is private.
 */
fun interface NymAuthNativeProver {
    /** Proves [request]; any failure is an exception, which [CatalogCircuitZkProver] turns into a refusal. */
    suspend fun prove(request: NymAuthProveRequest): NymAuthProveResponse
}

/**
 * What [NymAuthNativeProver.prove] receives. Everything here is derived by the SDK from the stored
 * credential, the verifier's request and the device signer; the native side does not parse the request.
 *
 * @property system The catalog `system` of the circuit: [CatalogCircuitZkProver.LONGFELLOW_SYSTEM] or
 *   [CatalogCircuitZkProver.VEGA_SYSTEM].
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

/**
 * The circuit decoded from the catalog and kept resident: the verified, decompressed artifact. Closing it
 * drops the reference; the memory is the garbage collector's (Longfellow circuits are about 1 MB, Vega
 * shapes 12-23 MB, far below a prover key).
 */
private class LoadedNymAuthCircuit(val descriptor: ZkCircuitDescriptor, @Volatile var bytes: ByteBuffer?) : AutoCloseable {
    override fun close() {
        bytes = null
    }
}

/**
 * The real [CircuitZkProver]: proves a `circuit_zk` request with a circuit of the go-zk-circuits catalog.
 *
 * What it does itself, in this order, refusing (an [CircuitZkError.AccessDenied], never a fallback to the
 * fake prover) at the first thing it cannot do:
 * 1. Only what the `nymauth-*` circuits prove is accepted: one `pseudonym-v1-sha256` with the config the
 *    circuit was built for and at most one `age_check` with only `ge`/`le`; the credential an mdoc.
 * 2. The circuit's catalog descriptor is fetched and must be the one the presenter chose, published, not
 *    deprecated, of a supported system ([LONGFELLOW_SYSTEM], [VEGA_SYSTEM]) and of format `mdoc`.
 * 3. The artifact is downloaded with its SHA-256 verified ([ZkCircuitClient.downloadArtifact]), decompressed,
 *    and the decompressed bytes checked against the catalog's `uncompressed.hash`; it stays resident in
 *    [residency] (one at a time) until released.
 * 4. The device key signs the challenge through the [org.siros.sdk.credentials.ZkWitnessSigner]; the digest of
 *    exactly the signed bytes is `e2`. The key never reaches this class.
 * 5. The inputs are assembled (issuer key, `T`, `E`, `C`, verifier input) and handed to [native].
 * 6. The pseudonym [native] reports must equal the one [NymPseudonym] derives from the same inputs;
 *    anything else (a circuit that disagrees with the rulebook, a corrupted run) is refused.
 *
 * What it does not do: build the circuit witnesses and run the proof system. That is [native], see
 * [NymAuthNativeProver]; with none supplied every request is refused. SD-JWT VC credentials and circuits are
 * refused too: the presenter holds mdoc credentials, and the SD-JWT challenge needs the request's nonce,
 * client id and origin, which [CircuitZkProveInput] does not carry.
 */
class CatalogCircuitZkProver(
    private val circuitClient: ZkCircuitClient,
    /** Builds the witnesses and proves; null means this build has no native prover and every request is refused. */
    private val native: NymAuthNativeProver? = null,
    /** Keeps the loaded circuit; share one with the other proof systems to hold a single prover at a time. */
    private val residency: ZkProverResidency = ZkProverResidency(),
    private val clock: Clock = Clock.systemUTC(),
    /** Decompresses a downloaded artifact; replaceable only because the zstd binding is native. */
    private val decompress: (ByteArray, ZkCircuitDescriptor) -> ByteBuffer = ::decompressZkCircuitArtifact,
) : CircuitZkProver {

    /** Whether a native prover is wired in; false means every request is refused. */
    val canProve: Boolean get() = native != null

    /** Drops the resident circuit; see [ZkProverResidency.release]. */
    fun releaseProvers() {
        residency.release()
    }

    override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
        val native = native ?: run {
            Timber.w("circuit_zk: no nymauth native prover is wired in; refusing")
            throw refuse()
        }

        // 1. What the circuits prove.
        val pseudonymFn = input.plan.functions.singleOrNull { it.id == PseudonymFunctionHandler.functionId } ?: throw refuse()
        val ageFn = input.plan.functions.filter { it.id == AgeCheckFunctionHandler.functionId }.also { if (it.size > 1) throw refuse() }.firstOrNull()
        if (input.plan.functions.any { it !== pseudonymFn && it !== ageFn }) throw refuse()
        val config = (pseudonymFn.params["config"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw refuse()
        if (config != SUPPORTED_CONFIG) throw refuse()
        val info = NymPseudonym.describe(config)
        if (info == null || info.seedKind != NymSeedKind.SECRET || info.userValue || !info.verifierId || info.verifierContext) throw refuse()
        val witness = input.witnesses[pseudonymFn.handle] ?: throw refuse()
        val seed = witness.secretSeed?.takeIf { it.size == SECRET_SEED_BYTES } ?: throw refuse()
        val verifierId = input.verifierId ?: throw refuse()
        val (earliest, cutoff) = ageBounds(ageFn)

        // 2. The circuit.
        val descriptor = circuitClient.fetchCircuit(input.circuit.circuitId) ?: throw refuse()
        if (!isSupported(descriptor, input)) throw refuse()
        val artifact = descriptor.artifact ?: throw refuse()

        val document = try {
            MdocCbor.parseStoredCredential(input.credentialBytes)
        } catch (e: Exception) {
            throw refuse()
        }
        val issuerAuth = document.issuerSigned.issuerAuth
        val issuerKey = issuerKey(issuerAuth) ?: throw refuse()
        val issuerSigned = encodeIssuerSigned(document)

        // 3. Load (or reuse) the verified circuit, 4. sign the challenge, 5. prove.
        val residencyKey = "${descriptor.system}:${descriptor.id}:${artifact.hash}"
        val time = Instant.now(clock).truncatedTo(ChronoUnit.SECONDS)
        val timeText = time.toString().also { if (it.length != TIME_CHARS) throw refuse() }

        val verifierInput = sha256(verifierId.toByteArray(Charsets.UTF_8))
        val deviceAuthBytes = MdocDeviceResponseBuilder.buildDeviceAuthentication(document.docType, input.sessionTranscript)
        val response = residency.use(
            key = residencyKey,
            load = { loadCircuit(descriptor) },
            block = { loaded ->
                val circuit = loaded.bytes ?: throw refuse()
                // Signed only now: the device key is not asked until the circuit is loaded and verified.
                var challengeDigest: ByteArray? = null
                val signed = MdocCose.sign1Detached("ES256", deviceAuthBytes) { toBeSigned ->
                    // e2 is the digest of exactly what the key signs, not of a second construction of it.
                    challengeDigest = sha256(toBeSigned)
                    input.signer.sign(COSE_ALG_ES256, toBeSigned)
                }
                val deviceSignature = signed[3].GetByteString()
                val e2 = challengeDigest
                if (deviceSignature.size != SIGNATURE_BYTES || e2 == null) throw refuse()
                val seedCopy = seed.copyOf()
                try {
                    native.prove(
                        NymAuthProveRequest(
                            system = descriptor.system,
                            circuitId = descriptor.id,
                            circuitParams = descriptor.params,
                            circuit = circuit.asReadOnlyBuffer(),
                            issuerSigned = issuerSigned,
                            secretSeed = seedCopy,
                            issuerKeyX = issuerKey.first,
                            issuerKeyY = issuerKey.second,
                            time = timeText,
                            earliest = earliest,
                            cutoff = cutoff,
                            challengeDigest = e2,
                            deviceSignature = deviceSignature,
                            verifierInput = verifierInput,
                            transcriptSeed = input.sessionTranscript,
                        ),
                    )
                } finally {
                    seedCopy.fill(0)
                }
            },
        )

        // 6. The circuit's pseudonym must be the rulebook's.
        val expected = NymPseudonym.derive(config = config, seed = seed, verifierId = verifierId)
        val agrees = MessageDigest.isEqual(expected, response.pseudonym)
        response.pseudonym.fill(0)
        if (!agrees || response.proof.isEmpty()) throw refuse()

        val results = LinkedHashMap<String, ResultValue>()
        results[pseudonymFn.handle] = ResultValue.Pseudonym(expected)
        if (ageFn != null) results[ageFn.handle] = ResultValue.Predicate
        return CircuitZkProveOutput(proof = response.proof, results = results, proofTime = time)
    }

    private fun refuse() = CircuitZkError.AccessDenied(CircuitZkStep.PROVE)

    /** The descriptor is the chosen, published, current circuit of a system and format this prover can drive. */
    private fun isSupported(descriptor: ZkCircuitDescriptor, input: CircuitZkProveInput): Boolean {
        val format = (descriptor.params["format"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        val configuration = (descriptor.params["configuration"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        return descriptor.id == input.circuit.circuitId &&
            descriptor.system == input.circuit.system &&
            descriptor.system in SUPPORTED_SYSTEMS &&
            descriptor.published && descriptor.deprecatedAt == null &&
            format == "mdoc" && configuration == SUPPORTED_CONFIG &&
            descriptor.artifact != null
    }

    private suspend fun loadCircuit(descriptor: ZkCircuitDescriptor): LoadedNymAuthCircuit {
        val compressed = try {
            circuitClient.downloadArtifact(descriptor)
        } catch (e: ZkArtifactException) {
            throw refuse()
        }
        val bytes = decompress(compressed, descriptor)
        val expected = descriptor.artifact?.uncompressed?.hash?.removePrefix("sha256:")
        val digest = MessageDigest.getInstance("SHA-256").apply { update(bytes.duplicate()) }.digest()
        // The catalog publishes the decompressed hash for every nymauth circuit; one without it is not trusted.
        if (expected.isNullOrEmpty() || !hex(digest).equals(expected, ignoreCase = true)) {
            Timber.w("circuit_zk: decompressed circuit '${descriptor.id}' does not match the catalog hash")
            throw refuse()
        }
        return LoadedNymAuthCircuit(descriptor, bytes)
    }

    /** `E` and `C` of the `age_check` (inclusive bounds); the open ends are `0000-00-00` and `9999-12-31`. */
    private fun ageBounds(age: CircuitZkFunction?): Pair<String, String> {
        if (age == null) return NO_LOWER_BOUND to NO_UPPER_BOUND
        // A parameter this circuit does not prove must not be silently dropped.
        if (age.params.keys.any { it != "ge" && it != "le" }) throw refuse()
        fun bound(key: String): String? {
            val p = age.params[key] ?: return null
            val text = (p as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw refuse()
            val date = try { LocalDate.parse(text) } catch (e: DateTimeParseException) { throw refuse() }
            // The circuit compares ten ASCII characters: only a four-digit year is representable.
            if (date.year !in 1..9998 || date.toString() != text) throw refuse()
            return text
        }
        val ge = bound("ge")
        val le = bound("le")
        if (ge == null && le == null) throw refuse()
        return (ge ?: NO_LOWER_BOUND) to (le ?: NO_UPPER_BOUND)
    }

    /** The issuer key Q: the P-256 key of the `x5chain` leaf, as 32-byte big-endian coordinates. */
    private fun issuerKey(issuerAuth: CBORObject): Pair<ByteArray, ByteArray>? {
        val leaf = MdocCose.extractX5Chain(issuerAuth).firstOrNull() ?: return null
        val key = try {
            CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(leaf)).publicKey as? ECPublicKey
        } catch (e: Exception) {
            null
        } ?: return null
        if (key.params.order.bitLength() != 256 || key.params.curve.field.fieldSize != 256) return null
        return unsigned32(key.w.affineX) to unsigned32(key.w.affineY)
    }

    private fun unsigned32(v: java.math.BigInteger): ByteArray {
        val raw = v.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        require(raw.size <= 32)
        return ByteArray(32 - raw.size) + raw
    }

    /** `IssuerSigned` = `{nameSpaces, issuerAuth}`; the items keep their original encoding, the digests depend on it. */
    private fun encodeIssuerSigned(document: org.siros.sdk.credentials.mdoc.DocumentMdoc): ByteArray {
        val nameSpaces = CBORObject.NewMap()
        for ((ns, items) in document.issuerSigned.nameSpaces) {
            val array = CBORObject.NewArray()
            items.forEach { array.Add(it.original) }
            nameSpaces[CBORObject.FromObject(ns)] = array
        }
        val issuerSigned = CBORObject.NewMap()
        issuerSigned[CBORObject.FromObject("nameSpaces")] = nameSpaces
        issuerSigned[CBORObject.FromObject("issuerAuth")] = document.issuerSigned.issuerAuth
        return issuerSigned.EncodeToBytes()
    }

    private fun sha256(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data)

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    companion object {
        /** Catalog `system` of the Longfellow `nymauth-longfellow-*` circuits. */
        const val LONGFELLOW_SYSTEM = "longfellow-nymauth"

        /** Catalog `system` of the Vega `nymauth-vega-*` circuits. */
        const val VEGA_SYSTEM = "vega-nymauth"

        /** The only pseudonym configuration the `nymauth-*` circuits are built for. */
        const val SUPPORTED_CONFIG = "known-offender-matching-ssc"

        private val SUPPORTED_SYSTEMS = setOf(LONGFELLOW_SYSTEM, VEGA_SYSTEM)
        private const val SECRET_SEED_BYTES = 16
        private const val SIGNATURE_BYTES = 64
        private const val TIME_CHARS = 20
        private const val NO_LOWER_BOUND = "0000-00-00"
        private const val NO_UPPER_BOUND = "9999-12-31"
    }
}
