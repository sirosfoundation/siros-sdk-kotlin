// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/**
 * What the rules may consult besides the plan itself. There is deliberately no `verifier_id_type`
 * registry: a request no longer carries the member (the wallet picks the type itself) and one that
 * still does is accepted and ignored.
 */
class CircuitZkRuleEnv(val circuits: CircuitZkCircuitSource?)

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
    /** This rule set plus the function [id] with [rules]. */
    fun withFunction(id: String, rules: CircuitZkFunctionRules): CircuitZkRuleSet = CircuitZkRuleSet(planRules, functions + (id to rules))

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
         * function filtering) or declares all of them. This is a satisfiability rule shared with the other SDKs'
         * vectors; whether a circuit declaring none is ever offered is decided by [CircuitZkMatching] (it is not). A circuit constrained
         * by the matcher ([CircuitZkCircuit.constrainedByMatcher]) is not
         * subject to this legacy check.
         */
        private fun functionsDeclared(plan: CircuitZkPlan, env: CircuitZkRuleEnv): Boolean {
            val source = env.circuits ?: return true
            val doctype = ((plan.raw["meta"] as? JsonObject)?.get("doctype_value") as? JsonPrimitive)?.content
            val relevant = source.circuits().filter { c ->
                (doctype == null || doctype in c.docTypes) &&
                    (plan.circuitFilter == null || plan.circuitFilter.admits(c))
            }
            if (relevant.isEmpty()) return true
            // A matcher-constrained circuit's legacy `functions` are not read (as in CircuitZkMatching.fits).
        return relevant.any { c -> c.constrainedByMatcher || c.functions == null || plan.functions.all { it.id in c.functions } }
        }
    }
}

/**
 * The wallet-side satisfiability rules for a planned `circuit_zk` request:
 * the rulebook's data-independent MUST rules, as a [CircuitZkRuleSet].
 * Whether a predicate holds for the holder's `birth_date` is data-dependent
 * and is checked when proving, not here.
 *
 * A `verifier_id_type` member in a pseudonym item is neither checked nor refused.
 *
 * Every failure is [CircuitZkVerdict.AccessDenied]. Its `ruleId` is for local
 * logs and tests; it must never reach the verifier.
 */
class RulebookCircuitZkValidator(
    private val rules: CircuitZkRuleSet = CircuitZkRuleSet.rulebookV03(),
    circuits: CircuitZkCircuitSource? = null,
) : CircuitZkRequestValidator {
    private val env = CircuitZkRuleEnv(circuits)

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
