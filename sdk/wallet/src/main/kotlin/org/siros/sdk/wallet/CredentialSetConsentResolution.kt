// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import org.siros.sdk.credentials.CredentialMatcher

/**
 * Validates that [resolvedQueryIds] - the DCQL queries a credential selection actually answers -
 * forms a complete, non-overlapping answer to every `credential_sets` entry: each entry's
 * answered queries are EXACTLY one of its satisfiable options, never a partial one (missing part
 * of a multi-credential alternative) and never more than one option's queries at once (the
 * union-across-alternatives bug [PresentationRequest.activeConsentMatchResults] exists to close
 * on the consent-UI side - re-checked here as defence in depth, the same "never trust a round
 * trip alone" pattern `ConsentGuard` applies elsewhere in this module: the consent step is
 * trusted to narrow correctly, but is not the only thing enforcing it). A required entry with no
 * answered query at all also fails; an optional one does not.
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
    resolvedQueryIds: Set<String>,
): Boolean {
    if (credentialSets.isNullOrEmpty()) return true
    val optionsByIndex = satisfiableOptions.groupBy { it.credentialSetIndex }
    return credentialSets.indices.all { index ->
        val memberIds = credentialSets[index].options.flatten().toSet()
        val answered = resolvedQueryIds.intersect(memberIds)
        if (answered.isEmpty()) {
            !credentialSets[index].required
        } else {
            optionsByIndex[index].orEmpty().any { it.queryIds.toSet() == answered }
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
    if (!credentialSetChoiceIsValid(credentialSets, satisfiableOptions, active.map { it.queryId }.toSet())) return null
    return active.map { r ->
        val id = selectedIds.firstOrNull { id -> r.candidates.any { it.id == id } } ?: return null
        r to id
    }
}
