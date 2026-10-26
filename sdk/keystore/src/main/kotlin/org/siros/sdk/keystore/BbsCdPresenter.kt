// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CircuitZkRequestValidator
import org.siros.sdk.credentials.CircuitZkResponseValidator
import org.siros.sdk.credentials.CircuitZkVerdict
import org.siros.sdk.credentials.ResultValue
import org.siros.sdk.credentials.RulebookCircuitZkValidator
import org.siros.sdk.credentials.ZkWitnessSigner
import timber.log.Timber
import uniffi.nymauth_native.BbsDeviceSigner
import uniffi.nymauth_native.BbsHandover
import uniffi.nymauth_native.BbsProver
import uniffi.nymauth_native.NymAuthNativeException as NativeException

/**
 * The OpenID4VPHandover values of a request (OpenID4VP 1.0 B.2.6.1), which the BBS statement's audience binds:
 * `client_id`, `nonce`, `response_uri` and, for `direct_post.jwt`, the RFC 7638 thumbprint of the response-encryption key.
 */
class BbsCdHandover(
    val clientId: String,
    val nonce: String,
    val responseUri: String,
    val jwkThumbprint: String?,
) {
    override fun toString() = "BbsCdHandover($clientId)"
}

/**
 * What a [BbsCdBinding] proves: the `zkp_req` query [credentialQueryId] of the verified [requestObject], from the stored
 * `bbs_cd` [credential] (JSON: `format`, `schema_id`, `issuer_params`, `signature`, `messages`), with the device key
 * [devicePublicKey] (SEC1 P-256) signing through [signer] (ES256 over the ecdsa-pop device message; raw `r || s`).
 */
class BbsCdProveRequest(
    val requestObject: JsonObject,
    val credentialQueryId: String,
    val handover: BbsCdHandover,
    val credential: String,
    val devicePublicKey: ByteArray,
    val signer: ZkWitnessSigner,
    /** ecdsa-pop on one thread per core; one thread when false. */
    val parallel: Boolean = false,
) {
    override fun toString() = "BbsCdProveRequest(redacted)"
}

/** Where the time and memory of one presentation went (the binding's own measurements; null when it has none). */
class BbsCdMetrics(
    val proveMs: Double,
    val totalMs: Double,
    /** The device key's signature inside ecdsa-pop (the key store's time). */
    val deviceSignMs: Double,
    val heapMb: Double?,
    /** The BBS envelope (the presentation's `proof`). */
    val proofBytes: Long,
    val presentationBytes: Long,
    val threads: Int,
)

/** One `bbs_cd` presentation: the `ZkpPresentation` (CBOR) and what it shows. */
class BbsCdProveResponse(
    val presentation: ByteArray,
    val systemId: String,
    val pseudonymHandle: String,
    /** The 48-byte G1 point (`prf` `hashdh-bls12381g1`). */
    val pseudonym: ByteArray,
    val predicateHandles: List<String>,
    val metrics: BbsCdMetrics?,
) {
    override fun toString() = "BbsCdProveResponse($systemId)"
}

/**
 * One implementation of the nym_auth attestation's `bbs_cd` presentation (rulebook v0.4), pluggable as the circuit systems'
 * [NymAuthBinding]s are: [systemId] and [proofSystem] say what it answers, [implementation] which code (for logs and
 * benchmark records; never sent to verifiers). Throws a [NymAuthNativeException] for its own errors, and the signer's own
 * exception as the signer threw it.
 */
interface BbsCdBinding {
    val systemId: String
    val proofSystem: String
    val implementation: String

    /** Blocking: the presenter calls it off the caller's dispatcher. */
    fun prove(request: BbsCdProveRequest): BbsCdProveResponse
}

/**
 * The SDK's `bbs_cd` binding: nymauth-native's `BbsProver` (community-demo's nym-bbs on sirosfoundation/bbs-cd-plugins 0.1,
 * the code its BBS verifier runs). The device key never reaches native code: the one ecdsa-pop signature is asked of the
 * request's [ZkWitnessSigner] (ES256), and native code checks it against the device key before using it. An exception of the
 * signer (the user cancelled, the key was invalidated) is rethrown as the signer threw it. The date-range tables are built
 * once, on first use.
 */
object NymAuthNativeBbsCdBinding : BbsCdBinding {
    override val systemId: String = SYSTEM_ID
    override val proofSystem: String = PROOF_SYSTEM
    override val implementation: String = "nymauth-native"

    /** The rulebook's `system_id` and proof system of the nym_auth `bbs_cd` scheme. */
    const val SYSTEM_ID: String = "urn:mms:bbs-cd:nym_auth:v1"
    const val PROOF_SYSTEM: String = "bbs-cd-plugins-v0.1"

    private val prover: BbsProver by lazy { BbsProver.load() }

    override fun prove(request: BbsCdProveRequest): BbsCdProveResponse {
        val signer = Signer(request.signer)
        val out = try {
            prover.prove(
                request.requestObject.toString(),
                request.credentialQueryId,
                BbsHandover(request.handover.clientId, request.handover.nonce, request.handover.responseUri, request.handover.jwkThumbprint),
                request.credential,
                request.devicePublicKey,
                signer,
                request.parallel,
            )
        } catch (e: NativeException) {
            signer.failure?.let { throw it }
            throw GoogleLongfellowNymAuthBinding.mapped(e)
        }
        val m = out.metrics
        Timber.d("nymauth-native BBS: prove %.0f ms (device %.1f ms), heap %s MB", m.proveMs, m.deviceSignMs, m.heapMb)
        return BbsCdProveResponse(
            presentation = out.presentation,
            systemId = out.systemId,
            pseudonymHandle = out.pseudonymHandle,
            pseudonym = out.pseudonym,
            predicateHandles = out.predicateHandles,
            metrics = BbsCdMetrics(
                proveMs = m.proveMs,
                totalMs = m.totalMs,
                deviceSignMs = m.deviceSignMs,
                heapMb = m.heapMb,
                proofBytes = m.proofBytes.toLong(),
                presentationBytes = m.presentationBytes.toLong(),
                threads = m.threads.toInt(),
            ),
        )
    }

    /**
     * The request's signer as native code's device signer. Native code calls it on its own thread, once; the signer
     * suspends (a biometric prompt), so it runs to completion here. Its exception is kept for [prove] to rethrow, and native
     * code only learns that signing failed.
     */
    private class Signer(private val signer: ZkWitnessSigner) : BbsDeviceSigner {
        @Volatile var failure: Throwable? = null

        override fun sign(message: ByteArray): ByteArray = try {
            runBlocking { signer.sign(org.siros.sdk.credentials.COSE_ALG_ES256, message) }
        } catch (e: Throwable) {
            failure = e
            throw NativeException.Internal()
        }
    }
}

/**
 * Presents the nym_auth attestation's `bbs_cd` encoding for one planned `zkp_req` query, the counterpart of
 * [CircuitZkPresenter] for the BBS scheme:
 *
 * 1. the plan is the `bbs_cd` source format and passes the rulebook's data-independent rules ([validator]);
 * 2. the request offers [BbsCdBinding.systemId] in `system_id_values` (fail closed: no list offers nothing) and, when it
 *    lists proof systems, [BbsCdBinding.proofSystem];
 * 3. the binding proves (off the caller's dispatcher); it checks the birth date before the device is asked, so an unmet age
 *    range signs nothing;
 * 4. the `vp_token` it makes passes the SDK's own response checks ([CircuitZkResponseValidator]) before it is returned.
 *
 * Every refusal is a [CircuitZkError.AccessDenied] (answered with `access_denied`); the signer's own exception and
 * cancellation pass through unchanged.
 */
class BbsCdPresenter(
    private val binding: BbsCdBinding = NymAuthNativeBbsCdBinding,
    private val validator: CircuitZkRequestValidator = RulebookCircuitZkValidator(),
) {
    /** One request. */
    class Request(
        val plan: CircuitZkPlan,
        val requestObject: JsonObject,
        val handover: BbsCdHandover,
        val credential: String,
        val devicePublicKey: ByteArray,
        val parallel: Boolean = false,
    ) {
        override fun toString() = "BbsCdPresenter.Request(redacted)"
    }

    /** A presentation: the `vp_token` array element and what it carries. */
    class Result(
        /** base64url(CBOR `ZkpPresentation`): the element of the `vp_token`'s query array. */
        val json: JsonPrimitive,
        val systemId: String,
        val results: Map<String, ResultValue>,
        val metrics: BbsCdMetrics?,
        /** [BbsCdBinding.implementation]. */
        val implementation: String,
    ) {
        override fun toString() = "BbsCdPresenter.Result($systemId)"
    }

    /** The implementation that proves. */
    val implementation: String get() = binding.implementation

    suspend fun present(request: Request, signer: ZkWitnessSigner): Result {
        val plan = request.plan
        if (plan.sourceFormat != SOURCE_FORMAT) throw CircuitZkError.AccessDenied(CircuitZkStep.VALIDATE)
        val verdict = validator.validate(plan)
        if (verdict is CircuitZkVerdict.AccessDenied) {
            Timber.d("bbs_cd request refused (%s)", verdict.ruleId)
            throw CircuitZkError.AccessDenied(CircuitZkStep.VALIDATE)
        }
        val offeredIds = plan.circuitFilter?.circuitIds
        val offeredProofSystems = plan.circuitFilter?.proofSystems
        val offered = offeredIds != null && binding.systemId in offeredIds &&
            (offeredProofSystems == null || binding.proofSystem in offeredProofSystems)
        if (!offered) throw CircuitZkError.AccessDenied(CircuitZkStep.CIRCUIT)
        val queryId = (plan.raw["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw CircuitZkError.AccessDenied(CircuitZkStep.VALIDATE)

        val proved = try {
            withContext(Dispatchers.Default) {
                binding.prove(
                    BbsCdProveRequest(
                        requestObject = request.requestObject,
                        credentialQueryId = queryId,
                        handover = request.handover,
                        credential = request.credential,
                        devicePublicKey = request.devicePublicKey,
                        signer = signer,
                        parallel = request.parallel,
                    ),
                )
            }
        } catch (e: NymAuthNativeException) {
            throw CircuitZkError.AccessDenied(CircuitZkStep.PROVE, reasonOf(e))
        }

        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(proved.presentation)
        val vpToken = JsonObject(mapOf(queryId to JsonArray(listOf(JsonPrimitive(token)))))
        CircuitZkResponseValidator.validate(plan, vpToken.toString())?.let {
            Timber.w("bbs_cd presentation does not pass the response checks (%s)", it.code)
            throw CircuitZkError.AccessDenied(CircuitZkStep.BUILD)
        }
        if (proved.systemId != binding.systemId) throw CircuitZkError.AccessDenied(CircuitZkStep.BUILD)
        val results = LinkedHashMap<String, ResultValue>()
        results[proved.pseudonymHandle] = ResultValue.Pseudonym(proved.pseudonym)
        proved.predicateHandles.forEach { results[it] = ResultValue.Predicate }
        return Result(JsonPrimitive(token), proved.systemId, results, proved.metrics, binding.implementation)
    }

    private fun reasonOf(e: NymAuthNativeException): CircuitZkRefusalReason = when (e.kind) {
        NymAuthNativeErrorKind.INVALID_INPUT -> CircuitZkRefusalReason.INVALID_INPUT
        NymAuthNativeErrorKind.INVALID_CIRCUIT -> CircuitZkRefusalReason.INVALID_CIRCUIT
        NymAuthNativeErrorKind.UNSUPPORTED_CIRCUIT -> CircuitZkRefusalReason.CIRCUIT_UNSUPPORTED_BY_APP
        NymAuthNativeErrorKind.REFUSED -> when (e.refusal) {
            NymAuthRefusal.UNSATISFIED -> CircuitZkRefusalReason.UNSATISFIED
            NymAuthRefusal.DEVICE_SIGNATURE -> CircuitZkRefusalReason.DEVICE_SIGNATURE
            NymAuthRefusal.CREDENTIAL -> CircuitZkRefusalReason.CREDENTIAL
            NymAuthRefusal.ISSUER_SIGNATURE -> CircuitZkRefusalReason.ISSUER_SIGNATURE
            NymAuthRefusal.SEED_MISMATCH -> CircuitZkRefusalReason.SEED_MISMATCH
            null -> CircuitZkRefusalReason.GENERIC
        }
        NymAuthNativeErrorKind.PROVER_FAILED -> CircuitZkRefusalReason.PROVER_FAILED
        NymAuthNativeErrorKind.PROOF_INVALID -> CircuitZkRefusalReason.PROOF_INVALID
        NymAuthNativeErrorKind.MISMATCH -> CircuitZkRefusalReason.MISMATCH
        NymAuthNativeErrorKind.INTERNAL -> CircuitZkRefusalReason.INTERNAL
    }

    private companion object {
        const val SOURCE_FORMAT = "bbs_cd"
    }
}
