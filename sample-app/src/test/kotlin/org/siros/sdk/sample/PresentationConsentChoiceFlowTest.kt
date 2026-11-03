// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.wallet.PresentationRequest

/**
 * The UX redesign that moved an [PresentationRequest.ExclusiveChoiceGroup]'s "pick one of these
 * alternatives" choice onto [PresentationConsentScreen]'s own first/preview step, instead of a later
 * step the user had to click through to even discover the choice existed (live gdc e2e feedback,
 * leifj - see [PreviewStep]'s doc comment for the full bug report).
 *
 * These test the pure pieces of that redesign directly: [presentationTotalSteps] no longer reserves a
 * step per ambiguous entry, [allExclusiveGroupsChosen] gates Next/Share across any number of
 * independent entries (not just the first/only one), [formatDisplayLabel] gives two identically-named
 * options (nym_auth's live "PID"/"PID" collision) something that actually tells them apart, and
 * [credentialDisplayMode] (added, then corrected, across two rounds of Copilot review of #359) keeps
 * a choice option identifiable when it has no displayable credential card, while keeping a genuinely
 * unmatched query invisible, exactly as before. The surrounding Compose rendering itself is
 * exercised on-device, not here.
 */
class PresentationConsentChoiceFlowTest {

    private fun group(credentialSetIndex: Int, vararg optionQueryIds: List<String>) =
        PresentationRequest.ExclusiveChoiceGroup(
            credentialSetIndex = credentialSetIndex,
            options = optionQueryIds.mapIndexed { i, ids ->
                CredentialMatcher.SatisfiableOption(credentialSetIndex = credentialSetIndex, optionIndex = i, queryIds = ids)
            },
        )

    // ── presentationTotalSteps: a choice no longer gets its own step ────

    @Test
    fun `an unambiguous request still gets preview + per-query claim step + summary`() {
        // disclosesNoClaims=false, 2 active queries: 1 (preview) + 2 (claims) + 1 (summary) = 4.
        // Before this fix the formula also added exclusiveGroups.size - this asserts the step count
        // is EXACTLY 4, not 4 plus however many ambiguous groups happen to exist elsewhere.
        assertEquals(4, presentationTotalSteps(disclosesNoClaims = false, activeResultsCount = 2))
    }

    @Test
    fun `a disclosesNoClaims request is a single step regardless of active query count`() {
        assertEquals(1, presentationTotalSteps(disclosesNoClaims = true, activeResultsCount = 3))
    }

    @Test
    fun `an empty request is still preview + summary`() {
        assertEquals(2, presentationTotalSteps(disclosesNoClaims = false, activeResultsCount = 0))
    }

    // ── allExclusiveGroupsChosen: gates advancing past the preview step ──

    @Test
    fun `no ambiguous groups means nothing blocks advancing`() {
        assertTrue(allExclusiveGroupsChosen(exclusiveGroups = emptyList(), chosenOptionIndex = emptyMap()))
    }

    @Test
    fun `a single unresolved group blocks advancing`() {
        val groups = listOf(group(0, listOf("mdl"), listOf("pid_1_8"), listOf("pid_mdoc_id")))
        assertFalse(allExclusiveGroupsChosen(groups, chosenOptionIndex = emptyMap()))
    }

    @Test
    fun `a single resolved group unblocks advancing`() {
        val groups = listOf(group(0, listOf("mdl"), listOf("pid_1_8"), listOf("pid_mdoc_id")))
        assertTrue(allExclusiveGroupsChosen(groups, chosenOptionIndex = mapOf(0 to 1)))
    }

    /**
     * Nym_auth's mechanism supports more than one independent ambiguous entry in the same request
     * (different `credential_sets` entries) even though its live case only has one - this is the
     * design brief's explicit "handle more than one gracefully" requirement. A choice for group 0
     * must never be mistaken for a choice covering group 1 too.
     */
    @Test
    fun `with two independent groups both must be resolved before advancing`() {
        val groups = listOf(
            group(0, listOf("mdl"), listOf("pid_1_8"), listOf("pid_mdoc_id")),
            group(1, listOf("photoid"), listOf("student_id")),
        )
        assertFalse("only group 0 chosen", allExclusiveGroupsChosen(groups, chosenOptionIndex = mapOf(0 to 1)))
        assertFalse("only group 1 chosen", allExclusiveGroupsChosen(groups, chosenOptionIndex = mapOf(1 to 0)))
        assertTrue("both chosen", allExclusiveGroupsChosen(groups, chosenOptionIndex = mapOf(0 to 1, 1 to 0)))
    }

    @Test
    fun `a choice recorded under the wrong credentialSetIndex does not count`() {
        val groups = listOf(group(0, listOf("mdl"), listOf("pid_1_8")))
        // Keyed 1, not 0 - e.g. a stale entry left over from a differently-shaped prior request.
        assertFalse(allExclusiveGroupsChosen(groups, chosenOptionIndex = mapOf(1 to 0)))
    }

    // ── ambiguousQueryIds: which queries are covered by a choice section, not the plain overview ──

    @Test
    fun `ambiguousQueryIds unions every option across every group`() {
        val groups = listOf(
            group(0, listOf("mdl"), listOf("pid_1_8"), listOf("pid_mdoc_id")),
            group(1, listOf("photoid"), listOf("student_id")),
        )
        assertEquals(
            setOf("mdl", "pid_1_8", "pid_mdoc_id", "photoid", "student_id"),
            ambiguousQueryIds(groups),
        )
    }

    @Test
    fun `ambiguousQueryIds is empty with no groups`() {
        assertTrue(ambiguousQueryIds(emptyList()).isEmpty())
    }

    // ── formatDisplayLabel: distinguishing options that share a display name ────

    /**
     * Found live (gdc e2e, nym_auth): `pid_1_8` (an SD-JWT PID) and `pid_mdoc_id` (an mdoc PID) both
     * display as "PID", and the old `ChooseCredentialOptionStep` built its option label purely from
     * `metadata?.name`, so the choice screen read "mDL" / "PID" / "PID" - no basis to tell the last
     * two apart. This format label is what now rides alongside each option's card specifically to
     * close that gap, so it must never collapse two different formats onto the same text.
     */
    @Test
    fun `an SD-JWT PID and an mdoc PID no longer read identically`() {
        val sdJwtLabel = formatDisplayLabel("dc+sd-jwt")
        val mdocLabel = formatDisplayLabel("mso_mdoc")
        assertFalse("'$sdJwtLabel' must differ from '$mdocLabel'", sdJwtLabel == mdocLabel)
    }

    @Test
    fun `every known format maps to a distinct label`() {
        val formats = listOf("mso_mdoc", "mso_mdoc_zk", "dc+sd-jwt", "vc+sd-jwt", "jwt_vc_json", "jwp")
        val labels = formats.map { formatDisplayLabel(it) }
        // mso_mdoc/mso_mdoc_zk and dc+sd-jwt/vc+sd-jwt are deliberately synonyms (same presentation
        // shape) - what must never happen is an mdoc-family format and an SD-JWT-family format (or
        // any other pair) collapsing onto the same label.
        val distinctFamilies = setOf(
            formatDisplayLabel("mso_mdoc"),
            formatDisplayLabel("dc+sd-jwt"),
            formatDisplayLabel("jwt_vc_json"),
            formatDisplayLabel("jwp"),
        )
        assertEquals(4, distinctFamilies.size)
        assertEquals(formatDisplayLabel("mso_mdoc"), formatDisplayLabel("mso_mdoc_zk"))
        assertEquals(formatDisplayLabel("dc+sd-jwt"), formatDisplayLabel("vc+sd-jwt"))
        assertEquals(6, labels.size)
    }

    @Test
    fun `an unrecognized format falls back to itself rather than a misleading label`() {
        assertEquals("some-future-format", formatDisplayLabel("some-future-format"))
    }

    // ── credentialDisplayFallback: an option must stay identifiable even with no card to show ──

    private fun cred(id: Long, batchId: Long, instanceId: Int) =
        StoredCredential(id = id, format = "mso_mdoc", raw = "r", batchId = batchId, instanceId = instanceId)

    private fun matchResult(queryId: String, candidates: List<StoredCredential>) =
        CredentialMatcher.MatchResult(queryId = queryId, format = "mso_mdoc", candidates = candidates, requestedClaims = emptyList())

    private fun mode(mr: CredentialMatcher.MatchResult) =
        credentialDisplayMode(mr, presentationHistory = emptyList(), availableKeyIds = emptySet())

    @Test
    fun `a normal batch with its instance-zero member shows the normal card`() {
        val mr = matchResult("mdl", listOf(cred(1, batchId = 10, instanceId = 0)))
        assertEquals(CredentialDisplayMode.CARD, mode(mr))
    }

    /**
     * Copilot review on #359: `CredentialUtils.groupForDisplay` drops a whole batch group when none
     * of its members is the instanceId-0 "visible" one - e.g. after `SirosWallet.deleteCredential`
     * removed just that copy while sibling copies (instanceId 1+) are still live, still matched this
     * query, and are still in [matchResult.candidates]. `ExclusiveChoiceSection` renders one radio
     * option per query id regardless, so without this fallback that option would be enabled with
     * nothing identifying it.
     */
    @Test
    fun `a batch that lost its instance-zero member falls back to the query id, not nothing`() {
        val mr = matchResult("pid_mdoc_id", listOf(cred(2, batchId = 20, instanceId = 1)))
        assertEquals(CredentialDisplayMode.FALLBACK_LABEL, mode(mr))
    }

    /**
     * A second Copilot review on #359 caught the first fix conflating this with the case above: with
     * five alternatives (mdl, photoid, pid_1_5, pid_1_8, pid_mdoc_id) but only three actual matches,
     * the two unmatched queries have empty `candidates` and are still in `request.matchResults` (only
     * `consentMatchResults` filters them out) - before credentialDisplayMode existed they were
     * silently invisible in the plain overview, and must stay that way, never surfaced as a bare
     * query id next to the choice section.
     */
    @Test
    fun `a query with no candidates at all stays hidden, not falls back`() {
        val mr = matchResult("photoid", emptyList())
        assertEquals(CredentialDisplayMode.HIDDEN, mode(mr))
    }
}
