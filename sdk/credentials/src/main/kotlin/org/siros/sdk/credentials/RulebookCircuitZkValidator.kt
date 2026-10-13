// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/**
 * The verifier-id types the wallet can resolve a `verifier_id` for. A
 * `verifier_id_type` outside this registry is unsatisfiable. The wallet does
 * not hardcode what verifiers are called: the default is the rulebook's two
 * current values, and a deployment registers whatever its sources support.
 */
fun interface VerifierIdTypes {
    /** Whether a verifier-id source is registered for [type]. */
    fun isRegistered(type: String): Boolean

    companion object {
        /** The rulebook v0.3 values: `semantic` and `x509_san_dns`. */
        val RULEBOOK_DEFAULT: VerifierIdTypes = of(setOf("semantic", "x509_san_dns"))

        /** A fixed set of types. */
        fun of(types: Set<String>): VerifierIdTypes = VerifierIdTypes { it in types }
    }
}

/** What the rules may consult besides the plan itself. */
class CircuitZkRuleEnv(val verifierIdTypes: VerifierIdTypes, val circuits: CircuitZkCircuitSource?)

/** A rule over the whole plan: [holds] false makes the request unsatisfiable, reported as [id]. */
class CircuitZkPlanRule(val id: String, val holds: (CircuitZkPlan, CircuitZkRuleEnv) -> Boolean)

/** A rule over one function item of the plan. */
class CircuitZkFunctionRule(val id: String, val holds: (CircuitZkFunction, CircuitZkRuleEnv) -> Boolean)

/**
 * The rules of one function id: at most [maxItems] items per request (null =
 * unlimited, rule id [countRuleId]) and the [rules] each item must satisfy.
 */
class CircuitZkFunctionRules(
    val maxItems: Int?,
    val countRuleId: String,
    val rules: List<CircuitZkFunctionRule>,
)

/**
 * A named, data-driven rule set. A function id that is a key of [functions]
 * is a known function; any other function id is unsatisfiable. New functions
 * and credential types add entries; the validator does not change.
 */
class CircuitZkRuleSet(
    val planRules: List<CircuitZkPlanRule>,
    val functions: Map<String, CircuitZkFunctionRules>,
) {
    companion object {
        const val PSEUDONYM = "pseudonym-v1-sha256"
        const val AGE_CHECK = "age_check"

        /** How a pseudonym config uses `verifier_input` and `verifier_context` (rulebook v0.3). */
        class PseudonymConfig(val id: String, val usesVerifierInput: Boolean, val requiresVerifierContext: Boolean)

        /** The four rulebook v0.3 configurations. */
        val RULEBOOK_PSEUDONYM_CONFIGS: List<PseudonymConfig> = listOf(
            PseudonymConfig("known-offender-matching-ssc", usesVerifierInput = true, requiresVerifierContext = false),
            PseudonymConfig("known-offender-matching-psc", usesVerifierInput = true, requiresVerifierContext = false),
            PseudonymConfig("account-recovery-ssc", usesVerifierInput = true, requiresVerifierContext = true),
            PseudonymConfig("user-managed-pseudonym-xsite-ssc", usesVerifierInput = false, requiresVerifierContext = false),
        )

        private const val MIN_SPAN_DAYS = 365L
        private const val MAX_CONTEXT_BYTES = 64

        /** The rules of rulebook v0.3. [pseudonymConfigs] is the set of configurations this wallet supports. */
        fun rulebookV03(pseudonymConfigs: List<PseudonymConfig> = RULEBOOK_PSEUDONYM_CONFIGS): CircuitZkRuleSet {
            val byId = pseudonymConfigs.associateBy { it.id }
            return CircuitZkRuleSet(
                planRules = listOf(
                    CircuitZkPlanRule("meta-vct-values-reserved") { plan, _ ->
                        ((plan.raw["meta"] as? JsonObject)?.containsKey("vct_values")) != true
                    },
                    CircuitZkPlanRule("holder-binding-false") { plan, _ ->
                        val v = plan.raw["require_cryptographic_holder_binding"]
                        v == null || (v is JsonPrimitive && !v.isString && v.booleanOrNull == true)
                    },
                    CircuitZkPlanRule("function-not-declared") { plan, env -> functionsDeclared(plan, env) },
                ),
                functions = mapOf(
                    PSEUDONYM to CircuitZkFunctionRules(
                        maxItems = 1,
                        countRuleId = "pseudonym-count",
                        rules = listOf(
                            CircuitZkFunctionRule("pseudonym-config-unsupported") { f, _ ->
                                str(f.params, "config")?.let { it in byId } == true
                            },
                            CircuitZkFunctionRule("verifier-context-required") { f, _ ->
                                val cfg = byId[str(f.params, "config")] ?: return@CircuitZkFunctionRule true
                                !cfg.requiresVerifierContext || f.params.containsKey("verifier_context")
                            },
                            CircuitZkFunctionRule("verifier-context-forbidden") { f, _ ->
                                val cfg = byId[str(f.params, "config")] ?: return@CircuitZkFunctionRule true
                                cfg.requiresVerifierContext || !f.params.containsKey("verifier_context")
                            },
                            CircuitZkFunctionRule("verifier-context-length") { f, _ ->
                                if (!f.params.containsKey("verifier_context")) return@CircuitZkFunctionRule true
                                val bytes = str(f.params, "verifier_context")?.toByteArray(Charsets.UTF_8)?.size
                                bytes != null && bytes in 1..MAX_CONTEXT_BYTES
                            },
                            CircuitZkFunctionRule("verifier-id-type-required") { f, _ ->
                                val cfg = byId[str(f.params, "config")] ?: return@CircuitZkFunctionRule true
                                !cfg.usesVerifierInput || f.params.containsKey("verifier_id_type")
                            },
                            CircuitZkFunctionRule("verifier-id-type-forbidden") { f, _ ->
                                val cfg = byId[str(f.params, "config")] ?: return@CircuitZkFunctionRule true
                                cfg.usesVerifierInput || !f.params.containsKey("verifier_id_type")
                            },
                            CircuitZkFunctionRule("verifier-id-type-unregistered") { f, env ->
                                if (!f.params.containsKey("verifier_id_type")) return@CircuitZkFunctionRule true
                                str(f.params, "verifier_id_type")?.let { env.verifierIdTypes.isRegistered(it) } == true
                            },
                        ),
                    ),
                    AGE_CHECK to CircuitZkFunctionRules(
                        maxItems = 1,
                        countRuleId = "age-check-count",
                        rules = listOf(
                            CircuitZkFunctionRule("age-check-no-bounds") { f, _ ->
                                f.params.containsKey("ge") || f.params.containsKey("le")
                            },
                            CircuitZkFunctionRule("age-check-bad-date") { f, _ ->
                                listOf("ge", "le").all { !f.params.containsKey(it) || date(f.params, it) != null }
                            },
                            CircuitZkFunctionRule("age-check-le-before-ge") { f, _ ->
                                val ge = date(f.params, "ge")
                                val le = date(f.params, "le")
                                ge == null || le == null || !le.isBefore(ge)
                            },
                            CircuitZkFunctionRule("age-check-span-short") { f, _ ->
                                val ge = date(f.params, "ge")
                                val le = date(f.params, "le")
                                // le - ge + 1, in calendar days.
                                ge == null || le == null || ChronoUnit.DAYS.between(ge, le) + 1 >= MIN_SPAN_DAYS
                            },
                        ),
                    ),
                ),
            )
        }

        private fun str(params: JsonObject, key: String): String? =
            (params[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

        /** An RFC 3339 `full-date` (`YYYY-MM-DD`), or null. */
        private fun date(params: JsonObject, key: String): LocalDate? {
            val s = str(params, key) ?: return null
            if (s.length != 10) return null
            return try {
                LocalDate.parse(s)
            } catch (e: DateTimeParseException) {
                null
            }
        }

        /**
         * When some circuit fits the plan's doctype and circuit list, at least
         * one of them must support every function: it declares none (no
         * function filtering) or declares all of them.
         */
        private fun functionsDeclared(plan: CircuitZkPlan, env: CircuitZkRuleEnv): Boolean {
            val source = env.circuits ?: return true
            val doctype = ((plan.raw["meta"] as? JsonObject)?.get("doctype_value") as? JsonPrimitive)?.content
            val relevant = source.circuits().filter { c ->
                (doctype == null || doctype in c.docTypes) &&
                    (plan.circuitFilter.isNullOrEmpty() || plan.circuitFilter.any { ref ->
                        (ref.system == null || ref.system == c.system) &&
                            (ref.circuitId == c.circuitId || ref.circuitId in c.aliases)
                    })
            }
            if (relevant.isEmpty()) return true
            return relevant.any { c -> c.functions == null || plan.functions.all { it.id in c.functions } }
        }
    }
}

/**
 * The wallet-side satisfiability rules for a planned `circuit_zk` request:
 * the rulebook's data-independent MUST rules, as a [CircuitZkRuleSet].
 * Whether a predicate holds for the holder's `birth_date` is data-dependent
 * and is checked when proving, not here.
 *
 * Every failure is [CircuitZkVerdict.AccessDenied]. Its `ruleId` is for local
 * logs and tests; it must never reach the verifier.
 */
class RulebookCircuitZkValidator(
    private val rules: CircuitZkRuleSet = CircuitZkRuleSet.rulebookV03(),
    verifierIdTypes: VerifierIdTypes = VerifierIdTypes.RULEBOOK_DEFAULT,
    circuits: CircuitZkCircuitSource? = null,
) : CircuitZkRequestValidator {
    private val env = CircuitZkRuleEnv(verifierIdTypes, circuits)

    override fun validate(plan: CircuitZkPlan): CircuitZkVerdict {
        for (rule in rules.planRules) {
            if (!rule.holds(plan, env)) return CircuitZkVerdict.AccessDenied(rule.id)
        }
        for (function in plan.functions) {
            if (function.id !in rules.functions) return CircuitZkVerdict.AccessDenied("unknown-function")
        }
        for ((id, entry) in rules.functions) {
            val items = plan.functions.filter { it.id == id }
            val max = entry.maxItems
            if (max != null && items.size > max) return CircuitZkVerdict.AccessDenied(entry.countRuleId)
            for (item in items) {
                for (rule in entry.rules) {
                    if (!rule.holds(item, env)) return CircuitZkVerdict.AccessDenied(rule.id)
                }
            }
        }
        return CircuitZkVerdict.Ok
    }
}
