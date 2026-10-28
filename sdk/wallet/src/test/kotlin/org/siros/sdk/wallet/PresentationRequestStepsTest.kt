// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.serialization.json.JsonObject
import org.siros.sdk.credentials.CircuitZkFunction
import org.siros.sdk.credentials.CircuitZkPlan
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.StoredCredential

/** How many consent steps a request needs: a request that discloses no claims is one step, anything else is unchanged. */
class PresentationRequestStepsTest {
    private val cred = StoredCredential(id = 1L, format = "mso_mdoc", raw = "r", batchId = 1L, instanceId = 0)

    private fun fn(id: String, params: JsonObject = JsonObject(emptyMap())) = CircuitZkFunction(id = id, handle = "h-$id", params = params)

    private fun plan(vararg ids: String) = CircuitZkPlan(functions = ids.map { fn(it) })

    private fun result(queryId: String, format: String?, claims: List<List<String>>, plan: CircuitZkPlan? = null) =
        CredentialMatcher.MatchResult(queryId = queryId, format = format, candidates = listOf(cred), requestedClaims = claims, circuitZkPlan = plan)

    /** What the matcher builds for a circuit_zk query: format zkp_req, requestedClaims always empty, the work is in the plan. */
    private fun zk(queryId: String, plan: CircuitZkPlan?) = result(queryId, "zkp_req", emptyList(), plan)

    private fun request(
        vararg results: CredentialMatcher.MatchResult,
        satisfiableOptions: List<CredentialMatcher.SatisfiableOption> = emptyList(),
    ) = PresentationRequest(
        verifierName = "v",
        matchResults = results.toList(),
        candidates = listOf(cred),
        satisfiableOptions = satisfiableOptions,
    )

    @Test
    fun aZkpReqRequestDisclosesNothingAndIsOneStep() {
        val r = request(zk("q", plan("pseudonym")))
        assertTrue(r.disclosesNoClaims)
        assertEquals(1, r.consentStepCount)
        // Several zkp_req queries (a pseudonym and an age proof) are still one step.
        val two = request(zk("q1", plan("pseudonym")), zk("q2", plan("age_check")))
        assertTrue(two.disclosesNoClaims)
        assertEquals(1, two.consentStepCount)
    }

    @Test
    fun anyRequestThatCanDiscloseDataKeepsAllItsSteps() {
        // A claim-listing query: preview + one selection per query + summary.
        val withClaims = request(result("q", "mso_mdoc", listOf(listOf("org.iso.18013.5.1", "family_name"))))
        assertFalse(withClaims.disclosesNoClaims)
        assertEquals(3, withClaims.consentStepCount)
        // A query without claims in another format may ask for the whole credential: NOT skipped.
        val wholeCredential = request(result("q", "dc+sd-jwt", emptyList()))
        assertFalse(wholeCredential.disclosesNoClaims)
        assertEquals(3, wholeCredential.consentStepCount)
        // A zkp_req query next to a disclosing one is not skipped either.
        val mixed = request(zk("a", plan("pseudonym")), result("b", "mso_mdoc", listOf(listOf("ns", "x"))))
        assertFalse(mixed.disclosesNoClaims)
        assertEquals(4, mixed.consentStepCount)
        // An empty request is not "discloses nothing".
        assertFalse(request().disclosesNoClaims)
        assertEquals(2, request().consentStepCount)
    }

    @Test
    fun aPlanThatDisclosesClaimsKeepsEveryStepWhateverRequestedClaimsSays() {
        // requestedClaims is empty for every circuit_zk query; the legacy claim disclosure (and so mso_mdoc_zk-style age-over-18 and
        // any ZK mdoc with claims) lives in the plan's functions.
        val legacyClaims = CircuitZkPlan(functions = listOf(fn("zk-claim-disclosure-v1")))
        for ((label, req) in listOf(
            "legacy claim disclosure" to request(zk("q", legacyClaims)),
            "legacy disclosure beside a pseudonym" to request(zk("q", plan("pseudonym", "zk-claim-disclosure-v1"))),
            "an unknown function" to request(zk("q", plan("some-future-function"))),
            "an empty plan" to request(zk("q", CircuitZkPlan(functions = emptyList()))),
            "no plan at all" to request(zk("q", null)),
            "one disclosing query among proofs" to request(zk("a", plan("pseudonym")), zk("b", legacyClaims)),
        )) {
            assertFalse(label, req.disclosesNoClaims)
            assertEquals(label, req.consentMatchResults.size + 2, req.consentStepCount)
        }
    }

    private fun unmatched(queryId: String) =
        CredentialMatcher.MatchResult(queryId = queryId, format = "mso_mdoc", candidates = emptyList(), requestedClaims = listOf(listOf("ns", "given_name")))

    @Test
    fun aQueryTheWalletCouldNotMatchGetsNoStepAndNoCard() {
        // gdc: one dcql_query with five alternatives (mdl, photoid, pid_1_5, pid_1_8, pid_mdoc) asking for the same claims;
        // the wallet holds only pid_1_8. The stepper must not iterate the four others.
        val matched = result("pid_1_8", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val r = request(unmatched("mdl"), unmatched("photoid"), unmatched("pid_1_5"), matched, unmatched("pid_mdoc"))
        assertEquals(listOf("pid_1_8"), r.consentMatchResults.map { it.queryId })
        // preview + one claim step + summary
        assertEquals(3, r.consentStepCount)
        // five listed alternatives remain visible to the matcher's consumers
        assertEquals(5, r.matchResults.size)
    }

    @Test
    fun noMatchAtAllIsPreviewAndSummaryOnly_andUnmatchedZkpQueriesDoNotBlockTheSkip() {
        assertEquals(2, request(unmatched("a"), unmatched("b")).consentStepCount)
        // a zkp_req alternative that matched, beside alternatives that did not: still a request that discloses nothing
        val z = zk("pid_1_8", plan("pseudonym"))
        val r = request(unmatched("mdl"), z, unmatched("photoid"))
        assertTrue(r.disclosesNoClaims)
        assertEquals(1, r.consentStepCount)
    }

    // ── credential_sets alternatives: exclusiveChoiceGroups / activeConsentMatchResults ──
    //
    // Bug found live (gdc e2e, nym_auth): one required credential_sets entry, five
    // single-credential alternatives (mdl, photoid, pid_1_5, pid_1_8, pid_mdoc_id) -
    // "present exactly one, your choice". The wallet held credentials for three of
    // them (pid_1_8, pid_mdoc, pid_mdoc_id). consentMatchResults (above) already
    // drops the two the wallet could not match at all, but did nothing about the
    // three that DID match: the consent screen showed all three as independent,
    // freely-checkable claim-selection steps, so the user selected claims from all
    // three and sent them in one presentation - a union across alternatives the
    // verifier never asked for and declared mutually exclusive.

    private fun option(optionIndex: Int, vararg queryIds: String, credentialSetIndex: Int = 0) =
        CredentialMatcher.SatisfiableOption(credentialSetIndex = credentialSetIndex, optionIndex = optionIndex, queryIds = queryIds.toList())

    @Test
    fun exclusiveChoiceGroupsIsEmptyWithoutAmbiguity() {
        // No credential_sets at all - satisfiableOptions is never populated.
        assertTrue(request(result("q", "mso_mdoc", listOf(listOf("ns", "x")))).exclusiveChoiceGroups.isEmpty())

        // The gdc scenario where only ONE of the five alternatives matched at all
        // (the companion test above): nothing to choose between.
        val matched = result("pid_1_8", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val r = request(
            unmatched("mdl"), unmatched("photoid"), unmatched("pid_1_5"), matched, unmatched("pid_mdoc"),
            satisfiableOptions = listOf(option(3, "pid_1_8")),
        )
        assertTrue(r.exclusiveChoiceGroups.isEmpty())
    }

    @Test
    fun exclusiveChoiceGroupsFindsTheAmbiguousCredentialSet() {
        // The actual bug: three of the five alternatives are each individually satisfiable.
        val a = result("pid_1_8", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val b = result("pid_mdoc", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val c = result("pid_mdoc_id", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val r = request(
            unmatched("mdl"), unmatched("photoid"), a, b, c,
            satisfiableOptions = listOf(option(3, "pid_1_8"), option(4, "pid_mdoc"), option(5, "pid_mdoc_id")),
        )

        val groups = r.exclusiveChoiceGroups
        assertEquals(1, groups.size)
        assertEquals(0, groups[0].credentialSetIndex)
        assertEquals(setOf("pid_1_8", "pid_mdoc", "pid_mdoc_id"), groups[0].options.flatMap { it.queryIds }.toSet())
    }

    @Test
    fun activeConsentMatchResultsExcludesEveryAlternativeUntilOneIsChosen() {
        val a = result("pid_1_8", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val b = result("pid_mdoc", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val c = result("pid_mdoc_id", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val r = request(a, b, c, satisfiableOptions = listOf(option(3, "pid_1_8"), option(4, "pid_mdoc"), option(5, "pid_mdoc_id")))

        // Nothing chosen yet: the bug this closes is exactly "every alternative is
        // active at once" - the fix must make that none, not all three.
        assertTrue(r.activeConsentMatchResults(emptyMap()).isEmpty())

        // Choosing pid_mdoc yields exactly that one query - never a union with the
        // other two, whatever they individually matched.
        assertEquals(listOf("pid_mdoc"), r.activeConsentMatchResults(mapOf(0 to 4)).map { it.queryId })
        assertEquals(listOf("pid_1_8"), r.activeConsentMatchResults(mapOf(0 to 3)).map { it.queryId })
    }

    @Test
    fun activeConsentMatchResultsLeavesQueriesOutsideAnyAmbiguousSetAlone() {
        // An ambiguous set next to an ordinary, unconstrained query: the unrelated
        // query is part of every presentation regardless of the choice above.
        val a = result("pid_1_8", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val b = result("pid_mdoc", "mso_mdoc", listOf(listOf("ns", "given_name")))
        val unrelated = result("other", "dc+sd-jwt", listOf(listOf("x")))
        val r = request(a, b, unrelated, satisfiableOptions = listOf(option(0, "pid_1_8"), option(1, "pid_mdoc")))

        assertEquals(setOf("other"), r.activeConsentMatchResults(emptyMap()).map { it.queryId }.toSet())
        assertEquals(setOf("pid_1_8", "other"), r.activeConsentMatchResults(mapOf(0 to 0)).map { it.queryId }.toSet())
    }
}
