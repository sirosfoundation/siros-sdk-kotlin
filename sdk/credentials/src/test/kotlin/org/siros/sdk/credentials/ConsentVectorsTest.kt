// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import java.io.File
import java.time.LocalDate
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** [ConsentRequests] against `spec/circuit-zk-consent-vectors.json`; see `spec/circuit-zk-consent-vectors.md`. */
class ConsentVectorsTest {
    private val file: JsonObject by lazy {
        val f = File("../../spec/circuit-zk-consent-vectors.json")
        require(f.isFile) { "vector file not found at ${f.absolutePath}" }
        Json.parseToJsonElement(f.readText()).jsonObject
    }

    private fun str(e: JsonElement?): String? = (e as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull

    private fun runCase(c: JsonObject): PresentationConsentRequest? {
        val input = c["input"]!!.jsonObject
        val trust = input["trust"]!!.jsonObject
        val verifierId = str(input["verifier_id"])
        val queries = input["queries"]!!.jsonArray.map { q ->
            val o = q.jsonObject
            val plan = CircuitZkPlan(o["plan"]!!.jsonArray.map {
                val f = it.jsonObject
                CircuitZkFunction(f["id"]!!.jsonPrimitive.content, f["handle"]!!.jsonPrimitive.content, f["params"]!!.jsonObject)
            })
            val cred = o["credential"]!!.jsonObject
            // The wallet resolves a verifier_id only for a plan that uses one.
            val needsId = plan.functions.any {
                it.id == CircuitZkRuleSet.PSEUDONYM || CircuitZkLegacyDisclosure.parse(it)?.pseudonym == true
            }
            ConsentRequests.Query(plan, CredentialRef(str(cred["name"]), str(cred["issuer"])), if (needsId) verifierId else null)
        }
        return ConsentRequests.build(
            queries = queries,
            trust = ConsentRequests.Trust(
                str(trust["entity_name"]), str(trust["framework"]), str(trust["identifier"]),
                (trust["intermediary_risk"] as? JsonPrimitive)?.booleanOrNull == true,
            ),
            verifiedClientIdDisplayName = str(input["verified_client_id_display_name"]),
            attestedOrigin = str(input["attested_origin"])!!,
            verifierIdType = str(input["verifier_id_type"]),
            today = LocalDate.parse(c["today"]!!.jsonPrimitive.content),
            locale = "en",
        )
    }

    private fun JsonObjectBuilderScope.nullable(k: String, v: String?) = put(k, if (v == null) JsonNull else JsonPrimitive(v))

    private fun form(f: AgeForm): JsonObject = buildJsonObject {
        when (f) {
            is AgeForm.Between -> {
                put("kind", "between"); put("from", f.from); put("to", f.to); put("min_years", f.minYears); put("max_years", f.maxYears)
            }
            is AgeForm.AtLeast -> { put("kind", "at_least"); put("years", f.years) }
            is AgeForm.AtMost -> { put("kind", "at_most"); put("years", f.years) }
        }
    }

    private fun item(i: ConsentItem): JsonObject = buildJsonObject {
        when (i) {
            is ConsentItem.Pseudonym -> {
                put("kind", "pseudonym"); put("config", i.config); put("scope", i.scope.wire)
                put("remappable_by_issuer", i.remappableByIssuer); put("cross_site", i.crossSite)
                nullable("verifier_id", i.verifierId); nullable("verifier_context", i.verifierContext)
            }
            is ConsentItem.AgeRange -> {
                put("kind", "age_range"); nullable("ge", i.ge); nullable("le", i.le); put("form", form(i.form))
            }
            is ConsentItem.Claim -> { put("kind", "claim"); put("name", i.name) }
            is ConsentItem.LegacyPseudonym -> { put("kind", "legacy_pseudonym"); nullable("verifier_context", i.verifierContext) }
        }
    }

    private fun json(r: PresentationConsentRequest): JsonObject = buildJsonObject {
        put("verifier", buildJsonObject {
            put("label", r.verifier.label)
            nullable("trust_framework", r.verifier.trustFramework); nullable("trust_identifier", r.verifier.trustIdentifier)
            nullable("verifier_id", r.verifier.verifierId); nullable("verifier_id_type", r.verifier.verifierIdType)
            put("intermediary_risk", r.verifier.intermediaryRisk)
        })
        put("entries", buildJsonArray {
            r.entries.forEach { e ->
                add(buildJsonObject {
                    put("credential", buildJsonObject { nullable("name", e.credential.name); nullable("issuer", e.credential.issuer) })
                    put("items", buildJsonArray { e.items.forEach { add(item(it)) } })
                })
            }
        })
        put("request_signed", r.requestSigned)
    }

    @Test
    fun everyVectorBuildsTheExpectedRequestItemForItem() {
        val cases = file["cases"]!!.jsonArray.map { it.jsonObject }
        assertTrue(cases.size >= 30)
        for (c in cases) {
            val name = c["name"]!!.jsonPrimitive.content
            val expected = c["expected"]!!.jsonObject
            val actual = runCase(c)
            if (expected["refused"] != null) {
                assertNull("$name: must be refused", actual)
            } else {
                assertEquals(name, expected["request"]!!.jsonObject, json(actual ?: error("$name: unexpectedly refused")))
            }
        }
    }
}

private typealias JsonObjectBuilderScope = kotlinx.serialization.json.JsonObjectBuilder
