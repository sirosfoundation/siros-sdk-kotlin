// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import java.time.Instant
import java.time.LocalDate
import java.time.format.DateTimeParseException
import org.siros.sdk.credentials.CircuitZkCircuit
import org.siros.sdk.credentials.CircuitZkCircuitSource
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkPresentation
import org.siros.sdk.credentials.CircuitZkPresentationCodec
import org.siros.sdk.credentials.CircuitZkRequestValidator
import org.siros.sdk.credentials.CircuitZkVerdict
import org.siros.sdk.credentials.IssuerKeySet
import org.siros.sdk.credentials.NymPseudonym
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.SirosException
import org.siros.sdk.credentials.ZkWitnessSigner
import org.siros.sdk.credentials.mdoc.DocumentMdoc
import org.siros.sdk.credentials.mdoc.MdocCbor
import timber.log.Timber

/**
 * Why a `circuit_zk` presentation was not produced. A refusal carries no
 * description and nothing that identifies a rule or a reason: the rulebook
 * answers with `access_denied` and no `error_description`, and what a verifier
 * could learn from a reason (that a predicate is false, say) must not leave
 * the wallet.
 */
sealed class CircuitZkError(message: String, errorCode: String) : SirosException(message, errorCode = errorCode) {
    /** The request is malformed in a way that is independent of the holder's data. */
    class InvalidRequest internal constructor() : CircuitZkError("circuit_zk request invalid", "circuit_zk_invalid_request")

    /** Everything else: answered with `access_denied`, no description. */
    class AccessDenied internal constructor(
        /** The step that refused. Internal: for local diagnostics and tests, never part of the message. */
        internal val step: CircuitZkStep,
    ) : CircuitZkError("circuit_zk request refused", "circuit_zk_access_denied")
}

/** The steps of [CircuitZkPresenter.present], in order. Internal. */
internal enum class CircuitZkStep { VALIDATE, DOCTYPE, NAMESPACE, WITNESS, COMMITMENT, PREDICATE, CIRCUIT, PROVE, BUILD }

/** What kind of wallet-held private input a function needs. */
enum class CircuitZkWitnessKind {
    /** The holder's `private_seed` for the credential's type. */
    PRIVATE_SEED,

    /** The user-supplied value. */
    USER_VALUE,

    /** Something the wallet does not hold; no default provider can supply it. */
    NOT_HELD_BY_WALLET,
}

/**
 * The private inputs for one planned function. Never logged or inspected by
 * the presenter; [toString] is redacted.
 */
class CircuitZkFunctionWitness(val privateSeed: ByteArray? = null, val userValue: ByteArray? = null) {
    override fun toString() = "CircuitZkFunctionWitness(redacted)"
}

/** Supplies the wallet-held private inputs a function needs, or null when it cannot. */
interface CircuitZkWitnessProvider {
    /** The witness for [function], or null when [needs] includes something this provider cannot supply. */
    fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String): CircuitZkFunctionWitness?

    /** Whether [psc] is the commitment this provider's `private_seed` has for [credentialType]. */
    fun privateSeedMatches(credentialType: String, psc: ByteArray): Boolean
}

/** The default provider: the K-S `private_seed` per credential type, and the user-supplied value if any. */
class HolderWitnessProvider internal constructor(
    private val seeds: PrivateSeed,
    private val userValue: ByteArray? = null,
) : CircuitZkWitnessProvider {
    override fun witness(function: CircuitZkFunction, needs: Set<CircuitZkWitnessKind>, credentialType: String): CircuitZkFunctionWitness? {
        if (CircuitZkWitnessKind.NOT_HELD_BY_WALLET in needs) return null
        if (CircuitZkWitnessKind.USER_VALUE in needs && userValue == null) return null
        return CircuitZkFunctionWitness(
            privateSeed = if (CircuitZkWitnessKind.PRIVATE_SEED in needs) seeds.derive(credentialType) else null,
            userValue = if (CircuitZkWitnessKind.USER_VALUE in needs) userValue else null,
        )
    }

    override fun privateSeedMatches(credentialType: String, psc: ByteArray) = seeds.matchesCommitment(credentialType, psc)
}

/**
 * The per-function part of the presenter, looked up by function id in a
 * registry, so another function is another handler.
 */
interface CircuitZkFunctionHandler {
    /** The function id this handles. */
    val functionId: String

    /** The wallet-held private inputs [function] needs. */
    fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind>

    /** The data-dependent check of [function] against the credential; false means no presentation. */
    fun holds(function: CircuitZkFunction, credential: DocumentMdoc): Boolean
}

/** `pseudonym-v1-sha256`: needs the private seed (and a user value where the config takes one). */
object PseudonymFunctionHandler : CircuitZkFunctionHandler {
    override val functionId = "pseudonym-v1-sha256"

    override fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind> {
        val info = (function.params["config"] as? kotlinx.serialization.json.JsonPrimitive)
            ?.takeIf { it.isString }?.content?.let(NymPseudonym::describe)
            ?: return setOf(CircuitZkWitnessKind.NOT_HELD_BY_WALLET)
        return buildSet {
            if (info.holderPrivateSeed) add(CircuitZkWitnessKind.PRIVATE_SEED) else add(CircuitZkWitnessKind.NOT_HELD_BY_WALLET)
            if (info.userValue) add(CircuitZkWitnessKind.USER_VALUE)
        }
    }

    override fun holds(function: CircuitZkFunction, credential: DocumentMdoc) = true
}

/**
 * The value of the element [name] in the credential's own doctype namespace (the namespace a nym_auth
 * credential carries its claims in, and the one the circuit binds), or null when that namespace or element
 * is absent or the element occurs more than once there. The same element name in another namespace is
 * never consulted, so a pre-check cannot read a different value than the circuit proves.
 */
internal fun doctypeElement(document: DocumentMdoc, name: String): CBORObject? {
    val matches = document.issuerSigned.nameSpaces[document.docType].orEmpty().filter { it.item.elementIdentifier == name }
    return matches.singleOrNull()?.item?.elementValue
}

/** `age_check`: `birth_date` must lie within `ge`..`le`. Needs no private input from the wallet. */
object AgeCheckFunctionHandler : CircuitZkFunctionHandler {
    override val functionId = "age_check"

    override fun witnessNeeds(function: CircuitZkFunction): Set<CircuitZkWitnessKind> = emptySet()

    override fun holds(function: CircuitZkFunction, credential: DocumentMdoc): Boolean {
        val birth = birthDate(credential) ?: return false
        val ge = bound(function, "ge")
        val le = bound(function, "le")
        if (ge == null && le == null) return false
        return (ge == null || !birth.isBefore(ge)) && (le == null || !birth.isAfter(le))
    }

    private fun bound(function: CircuitZkFunction, key: String): LocalDate? {
        val s = (function.params[key] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        return try { LocalDate.parse(s) } catch (e: DateTimeParseException) { null }
    }

    private fun birthDate(credential: DocumentMdoc): LocalDate? {
        val value = doctypeElement(credential, "birth_date") ?: return null
        val text = if (value.isTagged) value.UntagOne() else value
        if (text.type != CBORType.TextString) return null
        return try { LocalDate.parse(text.AsString()) } catch (e: DateTimeParseException) { null }
    }
}

/** Input of [CircuitZkProver.prove]. The witness values are private: the prover must not log them. */
class CircuitZkProveInput(
    val circuit: CircuitZkCircuit,
    val plan: CircuitZkPlan,
    val credentialBytes: ByteArray,
    val sessionTranscript: ByteArray,
    /** The opaque verifier id, as resolved by the caller; null when no planned function uses one. */
    val verifierId: String?,
    val verifierContext: String?,
    /** Private inputs per function handle. */
    val witnesses: Map<String, CircuitZkFunctionWitness>,
    val signer: ZkWitnessSigner,
)

/** Output of [CircuitZkProver.prove]. */
class CircuitZkProveOutput(
    val proof: ByteArray,
    /** One result per planned function handle. */
    val results: Map<String, ResultValue>,
    /** The time the circuit used for validity checks, when it checks validity. */
    val proofTime: Instant? = null,
)

/** The proof system behind the presenter; its ABI is not defined here. */
interface CircuitZkProver {
    /** Whether this prover is a fake that produces no real proof. */
    val isFake: Boolean get() = false

    /** Proves [input]. A refusal or failure is an exception; the presenter turns any into a silent refusal. */
    suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput
}

/**
 * Answers a validated `circuit_zk` request: assembles and encodes the
 * `CircuitZkPresentation` for the `vp_token`. Modelled on [ZkMdocPresentation]:
 * the device key never comes here (a proof that binds one calls the
 * [ZkWitnessSigner]), and [releaseProvers] drops resident prover memory.
 *
 * Every step fails closed with a [CircuitZkError] that carries no
 * description, and no private input is logged.
 */
class CircuitZkPresenter(
    private val prover: CircuitZkProver,
    private val circuits: CircuitZkCircuitSource,
    private val validator: CircuitZkRequestValidator,
    private val witnessProvider: CircuitZkWitnessProvider,
    handlers: List<CircuitZkFunctionHandler> = listOf(PseudonymFunctionHandler, AgeCheckFunctionHandler),
    private val residency: ZkProverResidency? = null,
    private val serving: org.siros.sdk.credentials.CircuitZkServing? = org.siros.sdk.credentials.SharedCircuitZkServing,
) {
    private val handlersById = handlers.associateBy { it.functionId }

    /** True when the prover is a fake: a host reports this in its capability descriptor. */
    val usesFakeProver: Boolean get() = prover.isFake

    /** See [ZkMdocPresentation.releaseProvers]. */
    fun releaseProvers() {
        residency?.release()
    }

    /** One request. */
    class Request(
        /** The stored credential bytes (an mdoc, as the wallet persists it). */
        val credentialBytes: ByteArray,
        val plan: CircuitZkPlan,
        /** The opaque `verifier_id`, already resolved by a verifier-id source. */
        val verifierId: String?,
        val verifierContext: String? = null,
        /** The session transcript the proof is bound to, built by the caller. */
        val sessionTranscript: ByteArray,
    )

    /** A presentation: the `vp_token` entry, its results, and the circuit used. */
    class Result(
        /** base64url, no padding, of the CBOR `CircuitZkPresentation`. */
        val base64Url: String,
        val results: Map<String, ResultValue>,
        val circuitId: String,
    )

    /**
     * Validates, proves and assembles.
     *
     * @throws CircuitZkError.InvalidRequest for a request that is malformed independently of the holder's data.
     * @throws CircuitZkError.AccessDenied for every other refusal, with no description.
     */
    suspend fun present(request: Request, signer: ZkWitnessSigner): Result {
        try {
            return presentInternal(request, signer)
        } catch (e: CircuitZkError) {
            throw e
        } catch (e: kotlinx.coroutines.CancellationException) {
            // A cancelled or timed-out caller gets cancellation, not a refusal.
            throw e
        } catch (e: Exception) {
            // Any failure of a collaborator (prover, witness provider, circuit source) is a silent refusal.
            Timber.w("circuit_zk presentation failed (${e.javaClass.simpleName})")
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
        }
    }

    private suspend fun presentInternal(request: Request, signer: ZkWitnessSigner): Result {
        val plan = request.plan
        if (plan.functions.isEmpty() || plan.functions.map { it.handle }.toSet().size != plan.functions.size) {
            throw CircuitZkError.InvalidRequest()
        }
        val document = try {
            MdocCbor.parseStoredCredential(request.credentialBytes)
        } catch (e: Exception) {
            throw CircuitZkError.InvalidRequest()
        }
        val functionHandlers = plan.functions.map { handlersById[it.id] ?: throw CircuitZkError.InvalidRequest() }

        // 1. Defence in depth: the validator already ran at matching time.
        if (validator.validate(plan) !is CircuitZkVerdict.Ok) refuse(CircuitZkStep.VALIDATE)

        // 2. The credential must be the type the plan asked for.
        val wanted = ((plan.raw["meta"] as? kotlinx.serialization.json.JsonObject)?.get("doctype_value")
            as? kotlinx.serialization.json.JsonPrimitive)?.content
        if (wanted == null || wanted != document.docType) refuse(CircuitZkStep.DOCTYPE)

        // 2b. Fail closed on the namespace the circuit binds. A nym_auth credential carries its claims in the
        // namespace named by its doctype, and the circuit reads birth_date and ssc from that one; it does not
        // check that no other namespace holds an attribute of the same name. So the doctype namespace must be
        // present and the only one: a credential with a decoy or extra namespace is never proved.
        if (document.issuerSigned.nameSpaces.keys != setOf(document.docType)) refuse(CircuitZkStep.NAMESPACE)

        // 3. Wallet-held private inputs; a function whose witness cannot be supplied is refused.
        val witnesses = LinkedHashMap<String, CircuitZkFunctionWitness>()
        val needs = LinkedHashMap<String, Set<CircuitZkWitnessKind>>()
        for ((function, handler) in plan.functions.zip(functionHandlers)) {
            val n = handler.witnessNeeds(function)
            needs[function.handle] = n
            witnesses[function.handle] = witnessProvider.witness(function, n, document.docType) ?: refuse(CircuitZkStep.WITNESS)
        }

        // 4. The commitment in the credential must be the one this wallet derives.
        if (needs.values.any { CircuitZkWitnessKind.PRIVATE_SEED in it }) {
            val psc = elementBytes(document, "psc") ?: refuse(CircuitZkStep.COMMITMENT)
            if (!witnessProvider.privateSeedMatches(document.docType, psc)) refuse(CircuitZkStep.COMMITMENT)
        }

        // 5. Data-dependent predicates: a false one means no presentation.
        for ((function, handler) in plan.functions.zip(functionHandlers)) {
            if (!handler.holds(function, document)) refuse(CircuitZkStep.PREDICATE)
        }

        // 6. A circuit that fits the plan.
        val circuit = circuits.circuits().firstOrNull { it.supports(plan, document.docType, serving) } ?: refuse(CircuitZkStep.CIRCUIT)

        // 7. Prove.
        val output = prover.prove(
            CircuitZkProveInput(
                circuit = circuit,
                plan = plan,
                credentialBytes = request.credentialBytes,
                sessionTranscript = request.sessionTranscript,
                verifierId = request.verifierId,
                verifierContext = request.verifierContext,
                witnesses = witnesses,
                signer = signer,
            ),
        )
        if (output.results.keys != plan.functions.map { it.handle }.toSet()) refuse(CircuitZkStep.PROVE)

        // 8. Assemble and encode.
        val keySet = issuerKeySet(document) ?: refuse(CircuitZkStep.BUILD)
        val presentation = CircuitZkPresentation(
            circuitId = circuit.circuitId,
            proof = output.proof,
            issuerKeySet = keySet,
            proofTime = output.proofTime,
            results = output.results,
        )
        presentation.requireResultHandles(plan.functions.map { it.handle }.toSet())
        return Result(CircuitZkPresentationCodec.encodeBase64Url(presentation), presentation.results, circuit.circuitId)
    }

    private fun refuse(step: CircuitZkStep): Nothing {
        Timber.w("circuit_zk presentation refused (step=$step)")
        throw CircuitZkError.AccessDenied(step)
    }

    private fun elementBytes(document: DocumentMdoc, name: String): ByteArray? {
        val v = doctypeElement(document, name) ?: return null
        return if (v.type == CBORType.ByteString) v.GetByteString() else null
    }

    /** The Document Signer certificate chain: `issuerAuth`'s unprotected header `x5chain` (label 33). */
    private fun issuerKeySet(document: DocumentMdoc): IssuerKeySet? {
        val auth = document.issuerSigned.issuerAuth
        if (auth.type != CBORType.Array || auth.size() < 2) return null
        val unprotected = auth[1]
        if (unprotected.type != CBORType.Map) return null
        val x5chain: CBORObject = unprotected[CBORObject.FromObject(33)] ?: return null
        val certs = when (x5chain.type) {
            CBORType.ByteString -> listOf(x5chain.GetByteString())
            CBORType.Array -> (0 until x5chain.size()).map { i ->
                if (x5chain[i].type != CBORType.ByteString) return null
                x5chain[i].GetByteString()
            }
            else -> return null
        }
        return certs.takeIf { it.isNotEmpty() }?.let { IssuerKeySet.DerCertificates(it) }
    }
}

/**
 * A prover that produces no real proof, for tests and development. It
 * computes the pseudonym with [NymPseudonym] for the configs whose witness
 * the wallet can supply (those on the holder's `private_seed`), reports the
 * predicates as `true` (the presenter has already checked them), and puts a
 * recognisable dummy in `proof`. It refuses everything else.
 *
 * Never registered by default: a host gets one only by calling [optIn], and
 * [isFake] (reported through [CircuitZkPresenter.usesFakeProver]) says so.
 */
class FakeCircuitZkProver private constructor() : CircuitZkProver {
    override val isFake: Boolean get() = true

    override suspend fun prove(input: CircuitZkProveInput): CircuitZkProveOutput {
        val results = LinkedHashMap<String, ResultValue>()
        for (function in input.plan.functions) {
            results[function.handle] = when (function.id) {
                PseudonymFunctionHandler.functionId -> {
                    val config = (function.params["config"] as? kotlinx.serialization.json.JsonPrimitive)?.content
                        ?: throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
                    val info = NymPseudonym.describe(config)
                    val witness = input.witnesses[function.handle]
                    val seed = witness?.privateSeed
                    if (info == null || !info.holderPrivateSeed || seed == null) throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
                    ResultValue.Pseudonym(
                        NymPseudonym.derive(
                            config = config,
                            seed = seed,
                            proverInput = if (info.userValue) witness.userValue else null,
                            verifierId = if (info.verifierId) input.verifierId else null,
                            verifierContext = if (info.verifierContext) input.verifierContext else null,
                        ),
                    )
                }
                AgeCheckFunctionHandler.functionId -> ResultValue.Predicate
                else -> throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE)
            }
        }
        return CircuitZkProveOutput(proof = DUMMY_PROOF.copyOf(), results = results)
    }

    companion object {
        /** The recognisable dummy placed in `proof`. */
        val DUMMY_PROOF: ByteArray = "FAKE-CIRCUIT-ZK-PROOF-NOT-A-PROOF".toByteArray(Charsets.US_ASCII)

        /** The only way to get a fake prover: an explicit opt-in, for tests and development only. */
        fun optIn(): FakeCircuitZkProver = FakeCircuitZkProver()
    }
}
