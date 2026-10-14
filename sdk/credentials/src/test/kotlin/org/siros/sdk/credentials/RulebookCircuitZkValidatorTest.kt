package org.siros.sdk.credentials

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** [RulebookCircuitZkValidator] against `spec/circuit-zk-validator-vectors.json`; see `spec/circuit-zk-validator-vectors.md`. */
class RulebookCircuitZkValidatorTest {
    private val file: JsonObject by lazy {
        // Gradle runs unit tests with the module directory as the working directory.
        val f = File("../../spec/circuit-zk-validator-vectors.json")
        require(f.isFile) { "vector file not found at ${f.absolutePath}" }
        Json.parseToJsonElement(f.readText()).jsonObject
    }

    private fun planOf(j: JsonObject): CircuitZkPlan = CircuitZkPlan(
        functions = j["functions"]!!.jsonArray.map {
            val o = it.jsonObject
            CircuitZkFunction(o["id"]!!.jsonPrimitive.content, o["handle"]!!.jsonPrimitive.content, o["params"]!!.jsonObject)
        },
        circuitFilter = j["circuit_filter"]?.jsonArray?.map { it.jsonObject }?.let { pairs ->
            // The vectors list the pairs; the plan keeps the two lists they are made of.
            val systems = pairs.mapNotNull { it["system"]?.jsonPrimitive?.content }.distinct()
            CircuitZkCircuitFilter(
                systems.takeIf { it.isNotEmpty() },
                pairs.map { it["circuit_id"]!!.jsonPrimitive.content }.distinct(),
            )
        },
        raw = j["query"]!!.jsonObject,
    )

    private fun validatorFor(options: JsonObject?): RulebookCircuitZkValidator {
        val types = options?.get("registered_verifier_id_types")?.jsonArray?.map { it.jsonPrimitive.content }
            ?: file["default_registered_verifier_id_types"]!!.jsonArray.map { it.jsonPrimitive.content }
        val circuits = options?.get("circuits")?.jsonArray?.map {
            val o = it.jsonObject
            CircuitZkCircuit(
                system = o["system"]!!.jsonPrimitive.content,
                circuitId = o["circuit_id"]!!.jsonPrimitive.content,
                docTypes = o["doc_types"]!!.jsonArray.map { d -> d.jsonPrimitive.content }.toSet(),
                functions = (o["functions"] as? JsonArray)?.map { f -> f.jsonPrimitive.content }?.toSet(),
            )
        }
        return RulebookCircuitZkValidator(
            verifierIdTypes = VerifierIdTypes.of(types.toSet()),
            circuits = circuits?.let { c -> CircuitZkCircuitSource { c } },
        )
    }

    @Test
    fun `every vector gives its verdict`() {
        val cases = file["cases"]!!.jsonArray
        assertTrue(cases.size >= 60)
        for (e in cases) {
            val c = e.jsonObject
            val verdict = validatorFor(c["options"]?.jsonObject).validate(planOf(c["plan"]!!.jsonObject))
            val expected = c["verdict"]!!.jsonObject
            if (expected["ok"]?.jsonPrimitive?.boolean == true) {
                assertTrue(c["name"]!!.jsonPrimitive.content, verdict === CircuitZkVerdict.Ok)
            } else {
                assertTrue(c["name"]!!.jsonPrimitive.content, verdict is CircuitZkVerdict.AccessDenied)
                assertEquals(c["name"]!!.jsonPrimitive.content, expected["access_denied"]!!.jsonPrimitive.content, (verdict as CircuitZkVerdict.AccessDenied).ruleId)
            }
        }
    }

    @Test
    fun `every rule id has a failing vector and the file has passing ones`() {
        val cases = file["cases"]!!.jsonArray.map { it.jsonObject }
        val failing = cases.mapNotNull { it["verdict"]!!.jsonObject["access_denied"]?.jsonPrimitive?.content }.toSet()
        val allRuleIds = setOf(
            "meta-vct-values-reserved", "holder-binding-false", "function-not-declared", "unknown-function",
            "pseudonym-count", "age-check-count", "pseudonym-config-unsupported", "verifier-context-required",
            "verifier-context-forbidden", "verifier-context-length", "verifier-id-type-required",
            "verifier-id-type-forbidden", "verifier-id-type-unregistered", "age-check-no-bounds",
            "age-check-bad-date", "age-check-le-before-ge", "age-check-span-short",
        )
        assertEquals(allRuleIds, failing)
        assertTrue(cases.any { it["verdict"]!!.jsonObject["ok"] != null })
    }

    @Test
    fun `the rule set is data - a new function and a new config need no validator change`() {
        val base = CircuitZkRuleSet.rulebookV03()
        val extended = CircuitZkRuleSet(
            planRules = base.planRules,
            functions = base.functions + ("my_fn" to CircuitZkFunctionRules(1, "my-fn-count", listOf(
                CircuitZkFunctionRule("my-fn-needs-x") { f, _ -> f.params.containsKey("x") },
            ))),
        )
        val v = RulebookCircuitZkValidator(extended)
        val plan = { fns: List<CircuitZkFunction> -> CircuitZkPlan(fns, raw = JsonObject(emptyMap())) }
        assertTrue(v.validate(plan(listOf(CircuitZkFunction("my_fn", "h", Json.parseToJsonElement("""{"x":1}""").jsonObject)))) === CircuitZkVerdict.Ok)
        assertEquals("my-fn-needs-x", (v.validate(plan(listOf(CircuitZkFunction("my_fn", "h")))) as CircuitZkVerdict.AccessDenied).ruleId)
        assertEquals("unknown-function", (RulebookCircuitZkValidator().validate(plan(listOf(CircuitZkFunction("my_fn", "h")))) as CircuitZkVerdict.AccessDenied).ruleId)

        val onlyXsite = CircuitZkRuleSet.rulebookV03(CircuitZkRuleSet.RULEBOOK_PSEUDONYM_CONFIGS.filter { it.id.startsWith("user-managed") })
        val fn = CircuitZkFunction(CircuitZkRuleSet.PSEUDONYM, "n", Json.parseToJsonElement("""{"config":"known-offender-matching-ssc","verifier_id_type":"semantic"}""").jsonObject)
        assertEquals("pseudonym-config-unsupported", (RulebookCircuitZkValidator(onlyXsite).validate(plan(listOf(fn))) as CircuitZkVerdict.AccessDenied).ruleId)
    }

    @Test
    fun `the default configs are the NymPseudonym table`() {
        assertEquals(NymPseudonym.configs.keys, CircuitZkRuleSet.RULEBOOK_PSEUDONYM_CONFIGS.map { it.id }.toSet())
    }

    @Test
    fun `an empty plan with no query members is satisfiable`() {
        assertTrue(RulebookCircuitZkValidator().validate(CircuitZkPlan(emptyList())) === CircuitZkVerdict.Ok)
    }

    @Test
    fun `a matcher-constrained circuit is not subject to the legacy functions check, an unconstrained one is`() {
        val rules = CircuitZkRuleSet(
            planRules = CircuitZkRuleSet.rulebookV03().planRules,
            functions = mapOf("my_fn" to CircuitZkFunctionRules(1, "my-fn-count", emptyList())),
        )
        val plan = CircuitZkPlan(
            listOf(CircuitZkFunction("my_fn", "h")),
            raw = Json.parseToJsonElement("""{"meta":{"doctype_value":"d.1"}}""").jsonObject,
        )
        fun verdict(c: CircuitZkCircuit) = RulebookCircuitZkValidator(rules, circuits = CircuitZkCircuitSource { listOf(c) }).validate(plan)
        val stale = setOf("other_fn")
        assertTrue(verdict(CircuitZkCircuit("s", "c", setOf("d.1"), functions = stale, capabilities = "{}")) === CircuitZkVerdict.Ok)
        assertTrue(verdict(CircuitZkCircuit("s", "c", setOf("d.1"), functions = stale, credentialType = "t")) === CircuitZkVerdict.Ok)
        val denied = verdict(CircuitZkCircuit("s", "c", setOf("d.1"), functions = stale))
        assertEquals("function-not-declared", (denied as CircuitZkVerdict.AccessDenied).ruleId)
        assertTrue(verdict(CircuitZkCircuit("s", "c", setOf("d.1"), functions = setOf("my_fn"))) === CircuitZkVerdict.Ok)
    }
}
