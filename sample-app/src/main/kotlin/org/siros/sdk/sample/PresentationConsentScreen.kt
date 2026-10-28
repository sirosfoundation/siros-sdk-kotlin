// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.credentials.ClaimMeta
import androidx.compose.ui.platform.LocalContext
import org.siros.sdk.credentials.ConsentItems
import org.siros.sdk.credentials.CredentialConsumptionPolicy
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.PredicateFunctions
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.wallet.PresentationConsentText
import org.siros.sdk.wallet.PresentationRequest

/**
 * Multi-step presentation consent screen with selective disclosure.
 *
 * Steps:
 * 1. Preview: verifier info, overview of what's requested, and - right here, not on a later screen - the
 *    pick-one-of-these-alternatives choice for every ambiguous [PresentationRequest.ExclusiveChoiceGroup] (see
 *    [PreviewStep]'s doc comment for why this moved off its own step).
 * 2. Per-credential: select which claims to disclose (for each active matched credential)
 * 3. Summary: confirm final selection before sharing
 *
 * A request that discloses no claims ([PresentationRequest.disclosesNoClaims], e.g. a `zkp_req` pseudonym or age proof) has only
 * step 1: nothing to select or confirm, so the user picks the credential and shares or declines.
 *
 * Decline is available on step 1 regardless of whether an ambiguous group has been resolved yet (gdc e2e feedback,
 * leifj: a user must be able to cancel "at the first screen" - deferring Decline past the choice would be exactly
 * the kind of screen this redesign removes).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PresentationConsentScreen(
    request: PresentationRequest,
    onAccept: (List<Long>) -> Unit,
    onDecline: () -> Unit,
    presentationHistory: List<PresentationRecord> = emptyList(),
    consumptionPolicy: CredentialConsumptionPolicy = CredentialConsumptionPolicy.NEVER_CONSUME,
    // Which kids the keystore can currently sign with - see
    // SirosWallet.availableKeyIds's doc comment. Without this, a credential
    // whose signing key was silently lost (a real, recurring bug found via
    // live testing) kept reporting "available" under NEVER_CONSUME forever,
    // right up until "Share" failed deep inside key selection.
    availableKeyIds: Set<String> = emptySet(),
    modifier: Modifier = Modifier,
) {
    // credential_sets options within the same required set are alternatives
    // (OID4VP 1.0 §6.2's "your choice" semantics), never an implicit union -
    // a set with more than one individually-satisfiable option needs the
    // user to pick exactly one before anything from it is shown or sent.
    // See PresentationRequest.exclusiveChoiceGroups's doc comment for the
    // live bug (gdc e2e, nym_auth) this closes: a 5-option single-credential
    // alternative set let the user select claims from 3 matching PID
    // variants at once and send all three in one presentation.
    val exclusiveGroups = remember(request.satisfiableOptions) { request.exclusiveChoiceGroups }
    // credentialSetIndex -> the chosen option's optionIndex. Deliberately
    // not pre-populated: PresentationRequest.activeConsentMatchResults
    // excludes every option of a group absent here, so nothing from an
    // ambiguous group counts until the user actually resolves it.
    val chosenOptionIndex = remember { mutableStateMapOf<Int, Int>() }
    // Not wrapped in `remember`: it must reflect every chosenOptionIndex
    // write immediately, and a `remember` keyed on anything but the
    // (mutable, unkeyable) map itself would risk serving a stale,
    // pre-choice value - silently reopening the union bug this exists to
    // close.
    val activeResults = request.activeConsentMatchResults(chosenOptionIndex)
    val activeQueryIds = activeResults.map { it.queryId }.toSet()

    // A query is unsatisfiable if every candidate that matched it has
    // already been used up under the active consumption policy, or has no
    // usable signing key left (see CredentialUtils.eligibleInstances) - the
    // SDK itself refuses to sign with an exhausted/keyless instance
    // regardless (defense in depth), but the user shouldn't be let all the
    // way to "Share" only to have it silently fail. Scoped to the active
    // (chosen) queries: an alternative the user didn't pick exhausting its
    // own copies must not block Share for the credential actually offered.
    val eligibleByQuery = remember(request, presentationHistory, consumptionPolicy, availableKeyIds) {
        CredentialUtils.eligibleInstancesByQuery(request.matchResults, consumptionPolicy, presentationHistory, availableKeyIds)
    }
    // Unscoped: PreviewStep is a plain overview of everything matched, shown
    // before any exclusive-choice-group is resolved, so it must not hide an
    // exhausted alternative just because nothing has excluded it yet.
    val previewExhaustedQueryIds = eligibleByQuery.filter { (mr, eligible) ->
        mr.candidates.isNotEmpty() && eligible.isEmpty()
    }.map { it.first.queryId }.toSet()
    // Scoped to the active (chosen) queries: gates Next/Share, so an
    // alternative the user didn't pick exhausting its own copies must not
    // block sharing the credential actually offered.
    val exhaustedQueryIds = previewExhaustedQueryIds.filter { it in activeQueryIds }.toSet()

    // preview (which now also resolves every ambiguous credential_sets entry
    // - see PreviewStep's doc comment) + (unless disclosesNoClaims) one
    // claim-selection step per active query and a final summary. Degenerates
    // to request.consentStepCount when there's no ambiguity (exclusiveGroups
    // empty => activeResults == consentMatchResults). No longer takes
    // exclusiveGroups.size into account AT ALL - deliberately: a choice no
    // longer gets its own step (see presentationTotalSteps's doc comment).
    val totalSteps = presentationTotalSteps(request.disclosesNoClaims, activeResults.size)
    var currentStep by remember { mutableStateOf(0) }
    // Whether every ambiguous credential_sets entry has been resolved -
    // gates the preview step's Next/Share button so the user can never
    // advance past step 0 (or share) with an ExclusiveChoiceGroup still
    // unresolved. Once true it stays true (chosenOptionIndex only grows),
    // so activeResults is already stable by the time a claim-selection or
    // summary step renders.
    val allGroupsChosen = allExclusiveGroupsChosen(exclusiveGroups, chosenOptionIndex)

    // Track per-credential claim disclosure selections
    // Key: "queryId:claimPath", Value: disclosed (true/false)
    val claimSelections = remember { mutableStateMapOf<String, Boolean>() }

    // Initialize selections: mandatory/always claims are always on, allowed start on
    remember(request) {
        request.matchResults.forEach { matchResult ->
            val cred = matchResult.candidates.firstOrNull()
            val claimMetaMap = cred?.metadata?.claims
                ?.associateBy { it.path.joinToString(".") } ?: emptyMap()
            matchResult.requestedClaims.flatten().distinct().forEach { claim ->
                val meta = claimMetaMap[claim]
                val key = "${matchResult.queryId}:$claim"
                val isRequired = meta?.mandatory == true || meta?.sd == "always"
                claimSelections[key] = isRequired || meta?.sd != "never"
            }
        }
        true
    }

    // Scaffold with the same TopAppBar treatment as every other sub-screen
    // (CredentialDetailScreen, QrScannerScreen, etc.) so this reads as part
    // of the wallet rather than a bare, unchromed overlay. No navigationIcon:
    // the Decline/Back buttons below already cover "leave this screen", and
    // a back arrow that did something different would be confusing.
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.presentation_consent_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            // Step indicator
            StepBar(currentStep = currentStep, totalSteps = totalSteps)

            Spacer(modifier = Modifier.height(16.dp))

            // Content area
            Box(modifier = Modifier.weight(1f)) {
                when {
                    currentStep == 0 -> PreviewStep(
                        request = request,
                        exhaustedQueryIds = previewExhaustedQueryIds,
                        presentationHistory = presentationHistory,
                        availableKeyIds = availableKeyIds,
                        exclusiveGroups = exclusiveGroups,
                        chosenOptionIndex = chosenOptionIndex,
                        onChoose = { credentialSetIndex, optionIndex -> chosenOptionIndex[credentialSetIndex] = optionIndex },
                    )
                    !request.disclosesNoClaims && currentStep <= activeResults.size -> {
                        val matchResult = activeResults[currentStep - 1]
                        ClaimSelectionStep(
                            matchResult = matchResult,
                            claimSelections = claimSelections,
                            presentationHistory = presentationHistory,
                            availableKeyIds = availableKeyIds,
                        )
                    }
                    else -> SummaryStep(activeResults, request, claimSelections, presentationHistory, availableKeyIds)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Navigation buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (currentStep == 0) {
                    OutlinedButton(
                        onClick = onDecline,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Icon(Icons.Filled.Close, null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Decline")
                    }
                } else {
                    OutlinedButton(
                        onClick = { currentStep-- },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Text("Back")
                    }
                }

                if (currentStep < totalSteps - 1) {
                    Button(
                        onClick = { currentStep++ },
                        // Only step 0 can have an unresolved ExclusiveChoiceGroup - every later
                        // step already requires allGroupsChosen to have been reached.
                        enabled = currentStep != 0 || allGroupsChosen,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Text("Next")
                    }
                } else {
                    Button(
                        onClick = {
                            onAccept(
                                eligibleByQuery
                                    .filter { (mr, _) -> mr.queryId in activeQueryIds }
                                    .flatMap { it.second }
                                    .map { it.id }
                                    .distinct(),
                            )
                        },
                        enabled = exhaustedQueryIds.isEmpty() && allGroupsChosen,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Icon(Icons.Filled.Check, null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Share")
                    }
                }
            }
        }
    }
}

/**
 * How many steps the stepped consent UI needs: the preview (which, unlike before, also resolves
 * every [PresentationRequest.ExclusiveChoiceGroup] - see [PreviewStep]'s doc comment for why a choice
 * no longer gets its own step), then (unless [disclosesNoClaims]) one claim-selection step per active
 * query and a final summary.
 *
 * Deliberately takes no `exclusiveGroups` parameter: the old formula was
 * `1 + exclusiveGroups.size + ...`, one extra step per ambiguous credential_sets entry. Dropping the
 * parameter here (not just not using it) is what makes it impossible for a future change to
 * reintroduce an extra step for a choice that no longer has one.
 */
internal fun presentationTotalSteps(disclosesNoClaims: Boolean, activeResultsCount: Int): Int =
    1 + if (disclosesNoClaims) 0 else activeResultsCount + 1

/**
 * Every query id that belongs to some option of an ambiguous credential_sets entry - across ALL of
 * [exclusiveGroups], not just the first: nym_auth's live case has exactly one, but the mechanism
 * supports any number of independent entries in the same request, each needing its own resolved
 * choice before anything in it is shown outside that choice's own section.
 */
internal fun ambiguousQueryIds(exclusiveGroups: List<PresentationRequest.ExclusiveChoiceGroup>): Set<String> =
    exclusiveGroups.flatMap { group -> group.options.flatMap { it.queryIds } }.toSet()

/**
 * Whether every [PresentationRequest.ExclusiveChoiceGroup] in [exclusiveGroups] has an entry in
 * [chosenOptionIndex] - keyed by `credentialSetIndex`, so a group is resolved only by a choice for
 * its OWN set, never by a choice made for a different one. Gates the preview step's Next/Share button:
 * true (vacuously) when there is nothing to choose, and only turns true for a request with N
 * independent ambiguous entries once all N have been picked, not just one of them.
 */
internal fun allExclusiveGroupsChosen(
    exclusiveGroups: List<PresentationRequest.ExclusiveChoiceGroup>,
    chosenOptionIndex: Map<Int, Int>,
): Boolean = exclusiveGroups.all { chosenOptionIndex[it.credentialSetIndex] != null }

// ── Step Bar ────────────────────────────────────────────────────────

@Composable
private fun StepBar(currentStep: Int, totalSteps: Int) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        repeat(totalSteps) { step ->
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(
                        if (step <= currentStep) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.outlineVariant,
                    ),
            )
        }
    }
}

// ── Step 1: Preview ─────────────────────────────────────────────────

/**
 * What a `disclosesNoClaims` (circuit_zk / zkp_req) match actually shares, in the SDK's own approved wording - the same
 * sentences the DC API consent dialog shows ([PresentationConsentText]), built from the plan alone: this transport resolves
 * a credential before circuit_zk's verifier-id machinery runs, so [ConsentItems.build] is given a placeholder id (unused for
 * display - only [verifierName] appears in the pseudonym sentence) rather than a real one. Every function of a
 * `disclosesNoClaims` plan is a pseudonym or an age_check (see [PresentationRequest.disclosesNoClaims]'s doc comment), both
 * of which [ConsentItems] models; a plan it cannot describe (an unmodelled pseudonym config) yields no line rather than a
 * guessed or blanket one.
 */
@Composable
private fun zkSummaryLines(result: CredentialMatcher.MatchResult, verifierName: String): List<String> {
    val context = LocalContext.current
    val items = result.circuitZkPlan?.let { p ->
        ConsentItems.build(p, verifierId = "unresolved-not-shown", today = java.time.LocalDate.now(java.time.ZoneOffset.UTC), predicates = PredicateFunctions.DEFAULT)
    }
    return items?.let { PresentationConsentText.forContext(context).renderItems(it, verifierName) }.orEmpty()
}

/**
 * Step 1: verifier identity, the overview of every matched credential, and - inline, for each
 * ambiguous [PresentationRequest.ExclusiveChoiceGroup] - the pick-one-of-these-alternatives choice
 * itself.
 *
 * This used to be two screens: a plain "overview of everything requested" (this content, minus the
 * choice) followed later by a separate "choose one of these" step. Live gdc e2e feedback (leifj):
 * for nym_auth's real case - one `credential_sets` entry with three individually-satisfiable
 * alternatives (mdl, pid_1_8, pid_mdoc_id) - that overview stacked all three candidates' full cards
 * ("4 data fields requested" / "5 data fields requested" / "6 data fields requested") with no way to
 * tell it was a choice rather than a union, and no way to decline until clicking through to the later
 * screen that revealed it was actually one-of-three. Showing the candidates and letting the user pick
 * among them now happens on the same screen, at the same place the cards already are, with Decline
 * (see the caller's bottom bar) available the whole time - never deferred to a screen the user hasn't
 * reached yet.
 */
@Composable
private fun PreviewStep(
    request: PresentationRequest,
    exhaustedQueryIds: Set<String> = emptySet(),
    presentationHistory: List<PresentationRecord> = emptyList(),
    availableKeyIds: Set<String> = emptySet(),
    exclusiveGroups: List<PresentationRequest.ExclusiveChoiceGroup> = emptyList(),
    chosenOptionIndex: Map<Int, Int> = emptyMap(),
    onChoose: (credentialSetIndex: Int, optionIndex: Int) -> Unit = { _, _ -> },
) {
    // Every query id that belongs to some option of an ambiguous group - rendered inside that
    // group's choice section below, never a second time in the plain overview loop.
    val ambiguousIds = remember(exclusiveGroups) { ambiguousQueryIds(exclusiveGroups) }
    val matchResultsById = remember(request.matchResults) { request.matchResults.associateBy { it.queryId } }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // Verifier identity - the screen title itself now lives in the
        // TopAppBar, so this just surfaces who's asking.
        val vName = request.verifierName
        // The verified identity (client_id/DID/certificate subject) a
        // trust evaluation actually vouches for - shown, labeled as such,
        // when there's no declared display name to show instead. Never
        // used to replace a real name: a verifier with no PDP-validated
        // name gets a checkable identifier, not something that reads like
        // a friendly name it never earned. See #218 - the backend no
        // longer trusts/caches an unvalidated client-supplied
        // client_metadata.client_name, so a nil name here is now common,
        // not just a rare edge case.
        val verifiedIdentity = request.trustResult?.identifier?.takeIf { vName == null }
        if (vName != null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    modifier = Modifier.size(32.dp),
                    tint = MaterialTheme.colorScheme.primary,
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = vName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        } else if (verifiedIdentity != null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    modifier = Modifier.size(32.dp),
                    tint = MaterialTheme.colorScheme.primary,
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(
                        text = stringResource(R.string.presentation_verified_identity),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = verifiedIdentity,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }

        val verifier = request.verifierName ?: request.trustResult?.identifier ?: "A verifier"
        Text(
            text = "$verifier is requesting the following credentials:",
            style = MaterialTheme.typography.bodyMedium,
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Overview of unambiguous matched credentials - reuses the exact same
        // CredentialCard as the main credential list (including its batch
        // "remaining copies" ribbon) rather than a separate, simpler-looking
        // representation that risked reading as a different credential.
        // Skips any query that belongs to an ambiguous group: those render
        // once each, inside that group's choice section below.
        request.matchResults.forEach { matchResult ->
            if (matchResult.queryId in ambiguousIds) return@forEach
            // One card representing the credential type this query matched,
            // not one per raw instance - a batch-issued credential can have
            // many interchangeable copies eligible for the same query (see
            // CredentialUtils.eligibleInstances), and the SDK - not the
            // user - picks which physical copy is actually used at share time.
            CredentialMatchSummary(
                request = request,
                matchResult = matchResult,
                presentationHistory = presentationHistory,
                availableKeyIds = availableKeyIds,
                isExhausted = matchResult.queryId in exhaustedQueryIds,
            )
        }

        // One choice section per ambiguous credential_sets entry - the user
        // must pick exactly one option before anything in it counts (see
        // PresentationRequest.exclusiveChoiceGroups's doc comment). Rendered
        // after the unconstrained overview above so an unambiguous "this is
        // what's being shared" reads first and "now pick one of these"
        // reads as its own, clearly-separate decision - not folded into the
        // same undifferentiated list that caused the original bug.
        exclusiveGroups.forEach { group ->
            Spacer(modifier = Modifier.height(8.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(8.dp))
            ExclusiveChoiceSection(
                request = request,
                group = group,
                matchResultsById = matchResultsById,
                chosen = chosenOptionIndex[group.credentialSetIndex],
                onChoose = { optionIndex -> onChoose(group.credentialSetIndex, optionIndex) },
                exhaustedQueryIds = exhaustedQueryIds,
                presentationHistory = presentationHistory,
                availableKeyIds = availableKeyIds,
            )
        }
    }
}

/**
 * The bare query id to show in place of a credential card for [matchResult], when
 * [CredentialUtils.groupForDisplay] has nothing displayable for its candidates even though the query
 * itself matched - e.g. a batch whose instanceId-0 member was deleted (`SirosWallet.deleteCredential`)
 * while other copies of the same batch remain ([CredentialUtils.groupForDisplay] drops a whole batch
 * group when none of its members is the instanceId-0 "visible" one, per its own doc comment).
 *
 * Found via Copilot review on #359: [ExclusiveChoiceSection] renders one [CredentialMatchSummary] per
 * option, and that option's `RadioButton` is still shown even when its summary has nothing to display
 * - before this, that left an enabled, unlabeled radio option with no way to tell what it was. The
 * original (pre-#359) `ChooseCredentialOptionStep` already fell back to the bare query id here; this
 * restores that fallback for every [CredentialMatchSummary] call site, not just the choice one - the
 * same gap existed, just less visibly (a silently-blank row rather than an unlabeled selectable one),
 * in the plain unconstrained overview too.
 *
 * Null when there IS a displayable candidate: the caller renders the normal card instead.
 */
internal fun credentialDisplayFallback(
    matchResult: CredentialMatcher.MatchResult,
    presentationHistory: List<PresentationRecord>,
    availableKeyIds: Set<String>,
): String? = matchResult.queryId.takeIf {
    CredentialUtils.groupForDisplay(matchResult.candidates, presentationHistory, availableKeyIds).isEmpty()
}

/**
 * One matched credential's preview content: its card, then either the circuit_zk summary lines or a
 * plain claim count, then an exhausted warning if any. Shared by [PreviewStep]'s unambiguous overview
 * and [ExclusiveChoiceSection]'s per-option rendering so the two never drift (a Copilot review on
 * #353 already caught the group/active-results recheck drifting once; this closes the same risk for
 * the two places that render a credential's summary).
 *
 * @param showFormatLabel Whether to append [formatDisplayLabel] after the summary line - on, only,
 *   inside an [ExclusiveChoiceGroup][PresentationRequest.ExclusiveChoiceGroup]'s choice: that is the
 *   one place two differently-formatted credentials can otherwise read as identical (live gdc e2e
 *   feedback, leifj: nym_auth's "mDL" / "PID" / "PID" options - `pid_1_8` (SD-JWT) and `pid_mdoc_id`
 *   (mdoc) share the display name "PID" with nothing else distinguishing them). Off in the plain
 *   overview, where every credential is its own, unambiguous card and a format label would be noise.
 */
@Composable
private fun CredentialMatchSummary(
    request: PresentationRequest,
    matchResult: CredentialMatcher.MatchResult,
    presentationHistory: List<PresentationRecord> = emptyList(),
    availableKeyIds: Set<String> = emptySet(),
    isExhausted: Boolean = false,
    showFormatLabel: Boolean = false,
) {
    val fallbackLabel = credentialDisplayFallback(matchResult, presentationHistory, availableKeyIds)
    if (fallbackLabel != null) {
        Text(
            text = fallbackLabel,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(vertical = 4.dp),
        )
        return
    }
    val grouped = CredentialUtils.groupForDisplay(matchResult.candidates, presentationHistory, availableKeyIds).first()
    CredentialCard(
        credential = grouped.credential,
        instances = grouped.instances,
        modifier = Modifier.padding(vertical = 4.dp),
    )
    if (request.disclosesNoClaims) {
        // What a circuit_zk / zkp_req proof actually shares: the SDK's own wording (pseudonym scoping, the age_check
        // predicate and its answer), never a blanket "nothing is shared" - a pseudonym is a persistent per-verifier
        // handle, the thing most worth telling the user about.
        zkSummaryLines(matchResult, request.verifierName ?: "This verifier").forEach { line ->
            Text(
                text = line,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp, bottom = 4.dp),
            )
        }
    } else {
        val claimCount = matchResult.requestedClaims.flatten().distinct().size
        Text(
            text = "$claimCount data fields requested",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp, bottom = if (showFormatLabel) 0.dp else 8.dp),
        )
    }
    if (showFormatLabel) {
        Text(
            text = formatDisplayLabel(grouped.credential.format),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(bottom = 8.dp),
        )
    }
    if (isExhausted) {
        Text(
            text = "No eligible copies remain - renew this credential in Settings",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.error,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 8.dp),
        )
    }
}

/**
 * A short, human-readable label for a credential format - shown ONLY beside an
 * [PresentationRequest.ExclusiveChoiceGroup]'s alternatives (see [CredentialMatchSummary]'s
 * `showFormatLabel` doc comment), where it is the one piece of information that tells apart two
 * options sharing the same display name. Not used elsewhere in this app's UI: see
 * AddCredentialScreen's `capabilityFlagsFor` doc comment for why a raw format string is otherwise
 * avoided (a user has no reason to know what "mDoc" or "SD-JWT" mean) - here, disambiguating the
 * choice outweighs that.
 */
internal fun formatDisplayLabel(format: String): String = when {
    format.equals("mso_mdoc", ignoreCase = true) || format.equals("mso_mdoc_zk", ignoreCase = true) -> "mdoc credential"
    format.equals("dc+sd-jwt", ignoreCase = true) || format.equals("vc+sd-jwt", ignoreCase = true) -> "SD-JWT credential"
    format.equals("jwt_vc_json", ignoreCase = true) -> "JWT VC credential"
    format.equals("jwp", ignoreCase = true) -> "JWP credential"
    else -> format
}

// ── Step 2: Per-Credential Claim Selection ──────────────────────────

@Composable
private fun ClaimSelectionStep(
    matchResult: CredentialMatcher.MatchResult,
    claimSelections: MutableMap<String, Boolean>,
    presentationHistory: List<PresentationRecord> = emptyList(),
    availableKeyIds: Set<String> = emptySet(),
) {
    val grouped = CredentialUtils.groupForDisplay(matchResult.candidates, presentationHistory, availableKeyIds).firstOrNull()
    val cred = grouped?.credential
    val claimMetaMap = cred?.metadata?.claims
        ?.associateBy { it.path.joinToString(".") } ?: emptyMap()
    val claims = matchResult.requestedClaims.flatten().distinct()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // Credential header
        if (grouped != null) {
            CredentialCard(
                credential = grouped.credential,
                instances = grouped.instances,
                modifier = Modifier.padding(bottom = 12.dp),
            )
        }

        Text(
            text = "Select which data to share:",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Claim toggles
        claims.forEach { claim ->
            val key = "${matchResult.queryId}:$claim"
            val meta = claimMetaMap[claim]
            val isRequired = meta?.mandatory == true || meta?.sd == "always"
            val isDisclosed = claimSelections[key] ?: true

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                shape = RoundedCornerShape(8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isDisclosed) MaterialTheme.colorScheme.surfaceVariant
                    else MaterialTheme.colorScheme.surface,
                ),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(
                        checked = isDisclosed,
                        onCheckedChange = { checked ->
                            if (!isRequired) {
                                claimSelections[key] = checked
                            }
                        },
                        enabled = !isRequired,
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = meta?.label ?: formatClaimName(claim),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                        )
                        if (isRequired) {
                            Text(
                                text = "Required",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        } else if (meta?.description != null) {
                            Text(
                                text = meta.description!!,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}

// ── Step 1b: Choose one of several alternative credentials (inline in Preview) ──

/**
 * One `credential_sets` entry with more than one satisfiable option - OID4VP 1.0 §6.2's "pick one of
 * these alternatives" case (see [PresentationRequest.exclusiveChoiceGroups]'s doc comment). Rendered
 * inline on [PreviewStep] (not its own step - see that function's doc comment for why), as a
 * radio-selectable list of full-size option cards: this is a genuine "the user picks one" choice,
 * never a check-everything-you-want list like [ClaimSelectionStep] - picking any other option here
 * must visibly deselect whichever one was picked before, and nothing is disclosed until the
 * presentation is actually shared.
 *
 * Each option shows its candidate(s) as the same [CredentialCard] the rest of the preview uses - not
 * a bare text label - plus [formatDisplayLabel]: nym_auth's live case has two of its three options
 * (`pid_1_8`, an SD-JWT PID, and `pid_mdoc_id`, an mdoc PID) sharing the display name "PID" with
 * nothing else to tell them apart, which is exactly the gap a text-only label (this function's
 * previous shape) could not close.
 */
@Composable
private fun ExclusiveChoiceSection(
    request: PresentationRequest,
    group: PresentationRequest.ExclusiveChoiceGroup,
    matchResultsById: Map<String, CredentialMatcher.MatchResult>,
    chosen: Int?,
    onChoose: (Int) -> Unit,
    exhaustedQueryIds: Set<String> = emptySet(),
    presentationHistory: List<PresentationRecord> = emptyList(),
    availableKeyIds: Set<String> = emptySet(),
) {
    Text(
        text = "Choose which credential to share:",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
    )
    Spacer(modifier = Modifier.height(4.dp))
    Text(
        text = "The verifier accepts any one of the following - only the one you pick will be shared.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(modifier = Modifier.height(12.dp))

    Column(Modifier.selectableGroup()) {
        group.options.forEach { option ->
            val selected = option.optionIndex == chosen
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp)
                    .selectable(
                        selected = selected,
                        onClick = { onChoose(option.optionIndex) },
                        role = Role.RadioButton,
                    ),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (selected) MaterialTheme.colorScheme.surfaceVariant
                    else MaterialTheme.colorScheme.surface,
                ),
                border = if (selected) BorderStroke(2.dp, MaterialTheme.colorScheme.primary) else null,
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    RadioButton(selected = selected, onClick = { onChoose(option.optionIndex) })
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        option.queryIds.forEach { queryId ->
                            val matchResult = matchResultsById[queryId] ?: return@forEach
                            CredentialMatchSummary(
                                request = request,
                                matchResult = matchResult,
                                presentationHistory = presentationHistory,
                                availableKeyIds = availableKeyIds,
                                isExhausted = queryId in exhaustedQueryIds,
                                showFormatLabel = true,
                            )
                        }
                    }
                }
            }
        }
    }
}

// ── Step 3: Summary ─────────────────────────────────────────────────

@Composable
private fun SummaryStep(
    activeResults: List<CredentialMatcher.MatchResult>,
    request: PresentationRequest,
    claimSelections: Map<String, Boolean>,
    presentationHistory: List<PresentationRecord> = emptyList(),
    availableKeyIds: Set<String> = emptySet(),
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        Icon(
            imageVector = Icons.Filled.Check,
            contentDescription = null,
            modifier = Modifier.size(32.dp),
            tint = MaterialTheme.colorScheme.primary,
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Ready to share",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
        )

        val verifier = request.verifierName ?: request.trustResult?.identifier ?: "the verifier"
        Text(
            text = "You will share the following with $verifier:",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(16.dp))

        activeResults.forEach { matchResult ->
            val grouped = CredentialUtils.groupForDisplay(matchResult.candidates, presentationHistory, availableKeyIds).firstOrNull()
                ?: return@forEach
            val cred = grouped.credential
            val claimMetaMap = cred.metadata?.claims
                ?.associateBy { it.path.joinToString(".") } ?: emptyMap()
            val disclosedClaims = matchResult.requestedClaims.flatten().distinct()
                .filter { claimSelections["${matchResult.queryId}:$it"] == true }

            CredentialCard(
                credential = cred,
                instances = grouped.instances,
                modifier = Modifier.padding(vertical = 4.dp),
            )
            if (disclosedClaims.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        disclosedClaims.forEach { claim ->
                            val meta = claimMetaMap[claim]
                            Text(
                                text = "✓ ${meta?.label ?: formatClaimName(claim)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}

/** Format a claim path like "given_name" or "address.street" for display. */
private fun formatClaimName(claim: String): String {
    return claim.split(".", "_")
        .joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
}
