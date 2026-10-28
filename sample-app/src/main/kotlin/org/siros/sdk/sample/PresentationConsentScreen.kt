// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

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
import org.siros.sdk.credentials.CredentialConsumptionPolicy
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.wallet.PresentationRequest

/**
 * Multi-step presentation consent screen with selective disclosure.
 *
 * Steps:
 * 1. Preview: verifier info and overview of what's requested
 * 2. Per-credential: select which claims to disclose (for each matched credential)
 * 3. Summary: confirm final selection before sharing
 *
 * A request that discloses no claims ([PresentationRequest.disclosesNoClaims], e.g. a `zkp_req` pseudonym or age proof) has only
 * step 1: nothing to select or confirm, so the user picks the credential and shares or declines.
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

    // preview + one "choose one" step per ambiguous credential_sets entry +
    // (unless disclosesNoClaims) one claim-selection step per active query
    // and a final summary. Degenerates to request.consentStepCount when
    // there's no ambiguity (exclusiveGroups empty => activeResults ==
    // consentMatchResults).
    val totalSteps = 1 + exclusiveGroups.size +
        if (request.disclosesNoClaims) 0 else activeResults.size + 1
    var currentStep by remember { mutableStateOf(0) }
    // Whether currentStep is one of the "choose one" steps, and whether
    // that step's group has been resolved - gates the Next/Share button so
    // the user can never advance (or share) past an ambiguous credential_sets
    // entry without picking an option. Since navigation is forward-only and
    // every choice step blocks on this, activeResults is stable - every
    // group resolved - by the time a claim-selection or summary step renders.
    val choiceStepIndex = currentStep - 1
    val onChoiceStep = choiceStepIndex in exclusiveGroups.indices
    val currentGroupChosen = !onChoiceStep ||
        chosenOptionIndex[exclusiveGroups[choiceStepIndex].credentialSetIndex] != null

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
                    currentStep == 0 -> PreviewStep(request, previewExhaustedQueryIds, presentationHistory, availableKeyIds)
                    onChoiceStep -> {
                        val group = exclusiveGroups[choiceStepIndex]
                        ChooseCredentialOptionStep(
                            group = group,
                            matchResultsById = request.matchResults.associateBy { it.queryId },
                            chosen = chosenOptionIndex[group.credentialSetIndex],
                            onChoose = { optionIndex -> chosenOptionIndex[group.credentialSetIndex] = optionIndex },
                            presentationHistory = presentationHistory,
                            availableKeyIds = availableKeyIds,
                        )
                    }
                    !request.disclosesNoClaims && currentStep <= exclusiveGroups.size + activeResults.size -> {
                        val matchResult = activeResults[currentStep - 1 - exclusiveGroups.size]
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
                        enabled = currentGroupChosen,
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
                        enabled = exhaustedQueryIds.isEmpty() && currentGroupChosen,
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

@Composable
private fun PreviewStep(
    request: PresentationRequest,
    exhaustedQueryIds: Set<String> = emptySet(),
    presentationHistory: List<PresentationRecord> = emptyList(),
    availableKeyIds: Set<String> = emptySet(),
) {
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

        // Overview of matched credentials - reuses the exact same
        // CredentialCard as the main credential list (including its batch
        // "remaining copies" ribbon) rather than a separate, simpler-looking
        // representation that risked reading as a different credential.
        request.matchResults.forEach { matchResult ->
            val isExhausted = matchResult.queryId in exhaustedQueryIds
            // One card representing the credential type this query matched,
            // not one per raw instance - a batch-issued credential can have
            // many interchangeable copies eligible for the same query (see
            // CredentialUtils.eligibleInstances), and the SDK - not the
            // user - picks which physical copy is actually used at share time.
            val grouped = CredentialUtils.groupForDisplay(matchResult.candidates, presentationHistory, availableKeyIds).firstOrNull()
            if (grouped != null) {
                CredentialCard(
                    credential = grouped.credential,
                    instances = grouped.instances,
                    modifier = Modifier.padding(vertical = 4.dp),
                )
                val claimCount = matchResult.requestedClaims.flatten().distinct().size
                Text(
                    text = if (request.disclosesNoClaims) "No data fields are shared (zero-knowledge proof)" else "$claimCount data fields requested",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
                )
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
        }
    }
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

// ── Step 2b: Choose one of several alternative credentials ──────────

/**
 * One `credential_sets` entry with more than one satisfiable option -
 * OID4VP 1.0 §6.2's "pick one of these alternatives" case (see
 * [PresentationRequest.exclusiveChoiceGroups]'s doc comment). Renders a
 * radio-button list, one row per option, matching [WscdChoiceDialog]'s
 * shape: this is a genuine "the user picks one" choice, never a
 * check-everything-you-want list like [ClaimSelectionStep] - picking any
 * other option here must visibly deselect whichever one was picked before.
 */
@Composable
private fun ChooseCredentialOptionStep(
    group: PresentationRequest.ExclusiveChoiceGroup,
    matchResultsById: Map<String, CredentialMatcher.MatchResult>,
    chosen: Int?,
    onChoose: (Int) -> Unit,
    presentationHistory: List<PresentationRecord> = emptyList(),
    availableKeyIds: Set<String> = emptySet(),
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
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
                val label = option.queryIds.joinToString(" + ") { queryId ->
                    val candidates = matchResultsById[queryId]?.candidates.orEmpty()
                    CredentialUtils.groupForDisplay(candidates, presentationHistory, availableKeyIds)
                        .firstOrNull()?.credential?.metadata?.name ?: queryId
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = option.optionIndex == chosen,
                            onClick = { onChoose(option.optionIndex) },
                            role = Role.RadioButton,
                        )
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = option.optionIndex == chosen, onClick = { onChoose(option.optionIndex) })
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(label, style = MaterialTheme.typography.bodyMedium)
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
