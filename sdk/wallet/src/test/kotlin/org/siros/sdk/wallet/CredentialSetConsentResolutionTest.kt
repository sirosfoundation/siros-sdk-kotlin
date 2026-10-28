// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.StoredCredential

/**
 * Regression tests for a Copilot review on #353 (the credential_sets exclusivity fix):
 * downstream of [PresentationRequest.activeConsentMatchResults], the SirosWallet.kt handlers that
 * actually build the consent payload / zkp_req proof selection only receive bare credential ids
 * (`onCredentialSelectionRequired: List<Long>`), never which DCQL query each one was chosen to
 * answer - so they used to re-derive it with a naive "first query in list order that lists this
 * id as a candidate" scan, which can attribute the WRONG alternative's claims (or circuit_zk plan)
 * to a selected credential, or wrongly refuse a perfectly valid choice. These three functions
 * replace that scan.
 */
class CredentialSetConsentResolutionTest {
    private fun cred(id: Long) = StoredCredential(id = id, format = "mso_mdoc", raw = "r-$id", batchId = id, instanceId = 0)

    private fun result(queryId: String, claims: List<List<String>>, vararg candidateIds: Long) =
        CredentialMatcher.MatchResult(queryId = queryId, format = "mso_mdoc", candidates = candidateIds.map { cred(it) }, requestedClaims = claims)

    private fun option(optionIndex: Int, vararg queryIds: String, credentialSetIndex: Int = 0) =
        CredentialMatcher.SatisfiableOption(credentialSetIndex = credentialSetIndex, optionIndex = optionIndex, queryIds = queryIds.toList())

    private fun credentialSet(vararg options: List<String>, required: Boolean = true) =
        CredentialMatcher.CredentialSetQuery(options = options.toList(), required = required)

    // ── credentialSetChoiceIsValid ──

    @Test
    fun noCredentialSetsAlwaysValidates() {
        assertTrue(credentialSetChoiceIsValid(null, emptyList(), emptySet()))
        assertTrue(credentialSetChoiceIsValid(emptyList(), emptyList(), setOf("whatever")))
    }

    @Test
    fun exactlyOneWholeOptionIsValid() {
        val sets = listOf(credentialSet(listOf("a"), listOf("b")))
        val options = listOf(option(0, "a"), option(1, "b"))
        assertTrue(credentialSetChoiceIsValid(sets, options, setOf("a")))
        assertTrue(credentialSetChoiceIsValid(sets, options, setOf("b")))
    }

    @Test
    fun aPartialMultiElementOptionIsInvalid() {
        // [[a,b]]: answering only "a" is not "the option [a,b]" - a multi-credential
        // alternative must be answered whole or not at all.
        val sets = listOf(credentialSet(listOf("a", "b")))
        val options = listOf(option(0, "a", "b"))
        assertTrue(credentialSetChoiceIsValid(sets, options, setOf("a", "b")))
        assertTrue("a partial answer must be refused", !credentialSetChoiceIsValid(sets, options, setOf("a")))
    }

    @Test
    fun answeringMoreThanOneOptionAtOnceIsInvalid() {
        // The union-across-alternatives bug this whole mechanism exists to close, re-checked
        // server-side: [[a],[b]], answering BOTH a and b at once is never a single valid choice.
        val sets = listOf(credentialSet(listOf("a"), listOf("b")))
        val options = listOf(option(0, "a"), option(1, "b"))
        assertTrue(!credentialSetChoiceIsValid(sets, options, setOf("a", "b")))
    }

    @Test
    fun aRequiredSetWithNothingAnsweredIsInvalid_optionalIsFine() {
        val required = listOf(credentialSet(listOf("a"), listOf("b"), required = true))
        assertTrue(!credentialSetChoiceIsValid(required, emptyList(), emptySet()))
        val optional = listOf(credentialSet(listOf("a"), listOf("b"), required = false))
        assertTrue(credentialSetChoiceIsValid(optional, emptyList(), emptySet()))
    }

    // ── resolveActiveQueryPerCredential ──

    @Test
    fun distinctCredentialsResolveTrivially() {
        val qa = result("a", listOf(listOf("ns", "x")), 1L)
        val qb = result("b", listOf(listOf("ns", "y")), 2L)
        val resolved = resolveActiveQueryPerCredential(listOf(qa, qb), listOf(1L, 2L))
        assertEquals(mapOf(1L to qa, 2L to qb), resolved)
    }

    @Test
    fun oneCredentialAnsweringTwoEquivalentQueriesResolvesToEither() {
        // Same claims requested by both - a physical credential legitimately disclosed under two
        // query ids at once (or proving two circuit_zk functions off one credential).
        val qa = result("a", listOf(listOf("ns", "x")), 9L)
        val qb = result("b", listOf(listOf("ns", "x")), 9L)
        val resolved = resolveActiveQueryPerCredential(listOf(qa, qb), listOf(9L))
        assertEquals(mapOf(9L to qa), resolved) // "first" of the equivalent answers - either is correct
    }

    @Test
    fun oneCredentialAnsweringTwoQueriesWithDifferentClaimsFailsClosed() {
        // Copilot #353, finding 1: the SAME stored credential is a candidate of two active
        // (both genuinely chosen) queries that ask for DIFFERENT claims. Nothing here knows which
        // claim set the consent screen actually showed for this credential - must refuse, never
        // silently pick one (the old `matchResults.firstOrNull{...}` scan would have picked
        // whichever query happened to come first in list order).
        val qa = result("a", listOf(listOf("ns", "given_name")), 9L)
        val qb = result("b", listOf(listOf("ns", "birth_date")), 9L)
        assertNull(resolveActiveQueryPerCredential(listOf(qa, qb), listOf(9L)))
    }

    @Test
    fun aSelectedIdNoActiveQueryClaimsFailsClosed() {
        val qa = result("a", listOf(listOf("ns", "x")), 1L)
        assertNull(resolveActiveQueryPerCredential(listOf(qa), listOf(404L)))
    }

    // ── circuitZkSelectionByQuery ──

    @Test
    fun aChosenAlternativeWithADistinctCredentialNoLongerNeedsTheOtherAlternativesAnswered() {
        // Copilot #353, finding 1 (zkp_req half): "declines a valid choice backed by distinct
        // credentials". [[a],[b]], distinct credentials 1 and 2; the user chose "b" only -
        // selectedIds = [2]. The OLD implementation iterated every entry of `results` (including
        // the UNCHOSEN "a") and failed the whole request because "a" had no pick. It must now
        // succeed, answering only the query actually chosen.
        val qa = result("a", emptyList(), 1L)
        val qb = result("b", emptyList(), 2L)
        val sets = listOf(credentialSet(listOf("a"), listOf("b")))
        val options = listOf(option(0, "a"), option(1, "b"))

        val selection = circuitZkSelectionByQuery(listOf(qa, qb), listOf(2L), sets, options)
        assertEquals(listOf(qb to 2L), selection)
    }

    @Test
    fun oneCredentialAnsweringTwoQueriesAtOnceIsReportedForBoth() {
        // "a credential may answer several queries": a single id valid for two co-active
        // (non-alternative) circuit_zk queries proves both off the one credential.
        val qa = result("a", emptyList(), 7L)
        val qb = result("b", emptyList(), 7L)
        val selection = circuitZkSelectionByQuery(listOf(qa, qb), listOf(7L))
        assertEquals(setOf(qa to 7L, qb to 7L), selection?.toSet())
    }

    @Test
    fun theSameCredentialAnsweringTwoAlternativesAtOnceIsRefused() {
        // Copilot #353, finding 1 (zkp_req half): "select both alternatives if they share a
        // credential". [[a],[b]], but the wallet's only matching credential (9) happens to
        // satisfy BOTH alternatives. selectedIds = [9] looks like it answers both "a" and "b" at
        // once by id-coverage alone - credentialSetChoiceIsValid must catch that this is never a
        // single valid option and refuse, rather than silently selecting both.
        val qa = result("a", emptyList(), 9L)
        val qb = result("b", emptyList(), 9L)
        val sets = listOf(credentialSet(listOf("a"), listOf("b")))
        val options = listOf(option(0, "a"), option(1, "b"))

        assertNull(circuitZkSelectionByQuery(listOf(qa, qb), listOf(9L), sets, options))
    }

    @Test
    fun noSelectionIsRefused() {
        val qa = result("a", emptyList(), 1L)
        assertNull(circuitZkSelectionByQuery(listOf(qa), emptyList()))
    }
}
