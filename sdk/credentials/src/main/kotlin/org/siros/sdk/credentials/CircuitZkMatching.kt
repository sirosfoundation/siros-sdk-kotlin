// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/** One function of a `circuit_zk` request: its id, the handle its result is returned under, and its raw parameters. */
data class CircuitZkFunction(
    val id: String,
    val handle: String,
    val params: JsonObject = JsonObject(emptyMap()),
)

/**
 * One entry of a request's circuit list: a null [system] matches any proof
 * system, a null [circuitId] any circuit id. The verifier's two independent
 * lists (`circuit_proof_system_values`, `circuit_id_values`) are expressed as
 * their pairs: a circuit is admitted when its system is in the first list AND
 * its id in the second, which is "some pair admits it", and a list the
 * verifier did not send is a null on every pair.
 */
data class CircuitZkCircuitRef(val system: String?, val circuitId: String?) {
    /** Whether [circuit] is the circuit this entry names (its id, or one of its aliases). */
    fun admits(circuit: CircuitZkCircuit): Boolean =
        (system == null || system == circuit.system) &&
            (circuitId == null || circuitId == circuit.circuitId || circuitId in circuit.aliases)
}

/**
 * What a `circuit_zk` credential query asks for, as plain data: the matcher's
 * plan, without its types. [circuitFilter] is the verifier's own list of
 * acceptable circuits: null means the verifier named none (any circuit fits),
 * and an EMPTY list means it named an empty list, which no circuit satisfies
 * (the matcher's reading). [raw] is the credential query the plan was made from.
 */
data class CircuitZkPlan(
    val functions: List<CircuitZkFunction>,
    val circuitFilter: List<CircuitZkCircuitRef>? = null,
    val raw: JsonObject = JsonObject(emptyMap()),
)

/** Result of [CircuitZkPlanner.plan]. */
sealed interface CircuitZkPlanResult {
    /** The query is a well-formed `circuit_zk` request. */
    class Plan(val plan: CircuitZkPlan) : CircuitZkPlanResult

    /** It is not. The wallet matches nothing. */
    object InvalidRequest : CircuitZkPlanResult
}

/**
 * Turns a `circuit_zk` credential query into a [CircuitZkPlan]. The default
 * implementation, backed by the shared matcher, is [SharedCircuitZkPlanner];
 * tests use a fake.
 */
fun interface CircuitZkPlanner {
    /** May throw; the matcher treats that as [CircuitZkPlanResult.InvalidRequest]. */
    fun plan(credentialQuery: JsonObject, clientMetadata: JsonObject?): CircuitZkPlanResult
}

/**
 * The wallet's verdict on a plan. [AccessDenied.ruleId] is for local logs and
 * tests only and never leaves the wallet.
 */
sealed interface CircuitZkVerdict {
    /** The plan is satisfiable. */
    object Ok : CircuitZkVerdict

    /** The plan is not; the request is answered with access-denied. */
    class AccessDenied(val ruleId: String? = null) : CircuitZkVerdict
}

/** Where the rulebook's satisfiability rules run in the wallet. Injected. */
fun interface CircuitZkRequestValidator {
    /** The verdict for [plan]. */
    fun validate(plan: CircuitZkPlan): CircuitZkVerdict

    companion object {
        /** Accepts every plan, until real rules are injected. */
        val PERMISSIVE = CircuitZkRequestValidator { CircuitZkVerdict.Ok }
    }
}

/**
 * A circuit this wallet can prove with. [functions] is null when the catalog
 * does not say which functions the circuit supports, in which case no
 * function filtering applies to it.
 *
 * [credentialType] and [capabilities] are opaque strings passed to the matcher
 * when the circuit is registered (siros-dc-matcher 0.9.0) and never read by
 * the SDK. [credentialType] restricts the circuit to a request naming that
 * doctype or vct. [capabilities] is the catalog's `capabilities` object as a
 * JSON string; when present the matcher applies its capability rule and reads
 * neither [functions] nor [credentialType]. A value the matcher cannot parse
 * leaves the circuit not offered. Both null: the circuit is registered as
 * before.
 */
data class CircuitZkCircuit(
    val system: String,
    val circuitId: String,
    val docTypes: Set<String>,
    val functions: Set<String>? = null,
    val aliases: Set<String> = emptySet(),
    val credentialType: String? = null,
    val capabilities: String? = null,
) {
    /**
     * Whether this circuit can prove [plan] for a credential of [docType]: the
     * doctype is one it serves, it is in the verifier's circuit list (if any),
     * and it supports every planned function (if it declares any).
     */
    fun supports(plan: CircuitZkPlan, docType: String): Boolean =
        docType in docTypes && CircuitZkMatching.fits(this, plan)
}

/** The circuits the wallet can prove with, from the circuit catalog. */
fun interface CircuitZkCircuitSource {
    /** The current circuits. */
    fun circuits(): List<CircuitZkCircuit>

    companion object {
        /**
         * The circuits of a catalog [manifest]: published, not deprecated.
         * `functions`, when a descriptor's `params` carries a string array of
         * that name, is the circuit's declared function set; otherwise null.
         */
        fun fromManifest(manifest: ZkManifest): List<CircuitZkCircuit> = manifest.circuits
            .filter { it.published && it.deprecatedAt == null }
            .map { d ->
                CircuitZkCircuit(
                    system = d.system,
                    circuitId = d.id,
                    docTypes = d.docTypes.toSet(),
                    functions = (d.params["functions"] as? JsonArray)
                        ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }?.toSet(),
                    aliases = d.aliases.toSet(),
                    capabilities = d.capabilities?.toString(),
                )
            }
    }
}

/** The document types served through `circuit_zk`: the doctypes of every circuit. */
fun CircuitZkCircuitSource.docTypes(): Set<String> = circuits().flatMapTo(HashSet()) { it.docTypes }

/**
 * Everything the matcher needs to answer a `circuit_zk` query. Absent
 * (null) means the feature is off, and a `circuit_zk` query matches nothing.
 */
class CircuitZkSupport(
    val planner: CircuitZkPlanner,
    val validator: CircuitZkRequestValidator = CircuitZkRequestValidator.PERMISSIVE,
    val circuits: CircuitZkCircuitSource,
)

internal object CircuitZkMatching {
    /**
     * The credentials matching one `circuit_zk` [query], with the plan; fails
     * closed: any planner or validator failure, an invalid plan, or no fitting
     * circuit means no candidates, never a fallback.
     */
    fun match(
        query: JsonObject,
        clientMetadata: JsonObject?,
        credentials: List<StoredCredential>,
        support: CircuitZkSupport,
    ): Pair<CircuitZkPlan?, List<StoredCredential>> {
        val plan = try {
            when (val r = support.planner.plan(query, clientMetadata)) {
                is CircuitZkPlanResult.Plan -> r.plan
                CircuitZkPlanResult.InvalidRequest -> return null to emptyList()
            }
        } catch (e: Exception) {
            return null to emptyList()
        }
        val verdict = try {
            support.validator.validate(plan)
        } catch (e: Exception) {
            return plan to emptyList()
        }
        if (verdict !is CircuitZkVerdict.Ok) return plan to emptyList()

        val fitting = try {
            support.circuits.circuits().filter { fits(it, plan) }
        } catch (e: Exception) {
            emptyList()
        }
        val docTypes = fitting.flatMapTo(HashSet()) { it.docTypes }
        val wantedDoctype = ((query["meta"] as? JsonObject)?.get("doctype_value") as? JsonPrimitive)?.contentOrNull
        val matched = credentials.filter { cred ->
            cred.format.equals("mso_mdoc", ignoreCase = true) && run {
                val docType = CredentialUtils.parseMdocDocument(cred)?.docType ?: cred.metadata?.doctype
                docType != null && docType in docTypes && (wantedDoctype == null || wantedDoctype == docType)
            }
        }
        return plan to matched
    }

    internal fun fits(circuit: CircuitZkCircuit, plan: CircuitZkPlan): Boolean {
        val filter = plan.circuitFilter
        // Null: the verifier named no circuits. An empty list is a list nothing is in.
        if (filter != null && filter.none { it.admits(circuit) }) return false
        val declared = circuit.functions ?: return true
        return plan.functions.all { it.id in declared }
    }
}
