// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.CredentialMatcher

/**
 * Validates that [resolvedQueryIds] - the DCQL queries a credential selection actually answers -
 * forms a complete, non-overlapping answer to the request: every query in [allQueryIds] that is
 * NOT a member of any `credential_sets` option is unconstrained - mandatory, exactly as if there
 * were no `credential_sets` at all - and must be answered; every `credential_sets` entry's
 * answered queries must be EXACTLY one of its satisfiable options, never a partial one (missing
 * part of a multi-credential alternative) and never more than one option's queries at once (the
 * union-across-alternatives bug [PresentationRequest.activeConsentMatchResults] exists to close
 * on the consent-UI side - re-checked here as defence in depth, the same "never trust a round
 * trip alone" pattern `ConsentGuard` applies elsewhere in this module: the consent step is
 * trusted to narrow correctly, but is not the only thing enforcing it). A required entry with no
 * option fully answered also fails; an optional one does not.
 *
 * Each entry is validated independently of every OTHER entry's own resolution, even when a query
 * id happens to be a nominal member of more than one `credential_sets` entry (legal: nothing in
 * OID4VP 1.0 §6.2 forbids two entries sharing a query id). Checking "does any entry's required
 * option id set equal [resolvedQueryIds] intersected with that entry's own member ids" - this
 * function's first version - breaks for exactly that overlap: answering `b` for set `[[b]]`'s sake
 * also makes `b` appear in set `[[a],[b,c]]`'s intersection, inflating its apparent answer to
 * `{a,b}`, which matches neither of ITS OWN options even though `a` alone is a perfectly valid
 * choice for it. Checking "does EXACTLY ONE of this entry's own options have ALL its query ids
 * present in resolvedQueryIds" instead tolerates that overlap (extra ids belonging to another
 * entry's answer never disqualify an option that is itself fully satisfied) while still catching
 * the union bug (more than one of THIS entry's own options fully present at once) and a partial
 * multi-credential option (not yet fully present).
 *
 * This also catches the one case id-based attribution genuinely cannot resolve on its own: a
 * single stored credential that happens to be a valid candidate of two DIFFERENT alternatives of
 * the same set. Both then look "answered" from the selected ids alone, which is never a single
 * valid option, so this fails and the caller must refuse rather than guess which alternative (and
 * so which claims) was actually meant.
 */
internal fun credentialSetChoiceIsValid(
    credentialSets: List<CredentialMatcher.CredentialSetQuery>?,
    satisfiableOptions: List<CredentialMatcher.SatisfiableOption>,
    allQueryIds: Set<String>,
    resolvedQueryIds: Set<String>,
): Boolean {
    val constrainedQueryIds = credentialSets.orEmpty().flatMap { it.options.flatten() }.toSet()
    // Every query outside any credential_sets option is unconstrained - mandatory. Checked first
    // and unconditionally (even when credentialSets itself is null/empty, where EVERY query is
    // unconstrained): silently answering only some of several otherwise-independent, equally
    // mandatory queries must never look like success just because none of them happens to be
    // part of a credential_sets entry.
    if (!allQueryIds.minus(constrainedQueryIds).all { it in resolvedQueryIds }) return false
    if (credentialSets.isNullOrEmpty()) return true

    val optionsByIndex = satisfiableOptions.groupBy { it.credentialSetIndex }
    return credentialSets.indices.all { index ->
        val fullyCovered = optionsByIndex[index].orEmpty().filter { option -> option.queryIds.all { it in resolvedQueryIds } }
        when {
            fullyCovered.size > 1 -> false // more than one of THIS entry's own alternatives answered at once
            fullyCovered.isEmpty() -> !credentialSets[index].required
            else -> true
        }
    }
}

/**
 * For each of [selectedIds], the single ACTIVE query (a member of [activeQueries]) whose
 * `requestedClaims`/`circuitZkPlan` should govern what is disclosed/proved for it - needed because
 * `onCredentialSelectionRequired` only reports bare credential ids, never which query the consent
 * screen resolved each one against (see PresentationConsentScreen.kt's `onAccept`, which flattens
 * to `List<Long>`). Usually trivial: a credential id is normally the candidate of exactly one
 * active query. A credential id answering MORE than one active query is fine provided every one of
 * them asks for the same thing (one physical credential legitimately disclosed under more than one
 * query id, or proving more than one circuit_zk function at once) - any one of them is then an
 * equally correct answer. Returns null for a selected id that cannot be attributed this way: either
 * no active query claims it (should not happen - [selectedIds] was supposed to come from
 * [activeQueries]'s own candidates) or it answers two active queries that are NOT equivalent this
 * way (different `requestedClaims` or `circuitZkPlan`) - the one case this cannot resolve on its
 * own, since nothing downstream of [PresentationRequest.activeConsentMatchResults] knows which of
 * the two claim sets the user actually consented to for that specific credential. Fail closed
 * rather than guess wrong.
 */
internal fun resolveActiveQueryPerCredential(
    activeQueries: List<CredentialMatcher.MatchResult>,
    selectedIds: List<Long>,
): Map<Long, CredentialMatcher.MatchResult>? {
    val result = LinkedHashMap<Long, CredentialMatcher.MatchResult>()
    for (id in selectedIds) {
        val candidates = activeQueries.filter { r -> r.candidates.any { it.id == id } }
        if (candidates.isEmpty()) return null
        val distinctAnswers = candidates.distinctBy { it.requestedClaims to it.circuitZkPlan }
        if (distinctAnswers.size > 1) return null
        result[id] = candidates.first()
    }
    return result
}

/**
 * The credential for EACH query of a zkp_req request that [selectedIds] actually answers - not
 * necessarily every query in [results]: a required `credential_sets` entry with several
 * alternatives only needs the ONE the consent step resolved, and [selectedIds] only carries
 * credentials for the queries that step decided were active (see
 * [PresentationRequest.activeConsentMatchResults]) - requiring a pick for every OTHER,
 * deliberately-unchosen alternative too (as this used to, by iterating every entry of [results]
 * rather than just the answered ones) wrongly refused a perfectly valid choice.
 * [credentialSets]/[satisfiableOptions] are cross-checked via [credentialSetChoiceIsValid]: null
 * when the answered queries are not exactly one whole option per credential_sets entry - including
 * the case where the same credential happens to satisfy two different alternatives at once, which
 * looks answerable here but is never a valid single choice.
 */
internal fun circuitZkSelectionByQuery(
    results: List<CredentialMatcher.MatchResult>,
    selectedIds: List<Long>,
    credentialSets: List<CredentialMatcher.CredentialSetQuery>? = null,
    satisfiableOptions: List<CredentialMatcher.SatisfiableOption> = emptyList(),
): List<Pair<CredentialMatcher.MatchResult, Long>>? {
    if (selectedIds.isEmpty()) return null
    val selected = selectedIds.toSet()
    val active = results.filter { r -> r.candidates.any { it.id in selected } }
    if (active.isEmpty()) return null
    val allQueryIds = results.map { it.queryId }.toSet()
    if (!credentialSetChoiceIsValid(credentialSets, satisfiableOptions, allQueryIds, active.map { it.queryId }.toSet())) return null
    // In query order, prefer a credential no earlier query already took - "one credential may
    // answer several queries" is the fallback for when there are not enough distinct ones to go
    // around, not the default: with two credentials that both match both of two queries, the two
    // queries get answered by two DIFFERENT credentials (not query 1 silently exhausting every
    // query's answer with the same single credential, leaving the second one never actually used).
    val used = HashSet<Long>()
    return active.map { r ->
        val id = selectedIds.firstOrNull { id -> id !in used && r.candidates.any { it.id == id } }
            ?: selectedIds.firstOrNull { id -> r.candidates.any { it.id == id } }
            ?: return null
        used += id
        r to id
    }
}
