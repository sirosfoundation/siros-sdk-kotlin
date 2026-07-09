// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.sample

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
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.sirosfoundation.sdk.credentials.ClaimMeta
import org.sirosfoundation.sdk.credentials.CredentialMatcher
import org.sirosfoundation.sdk.credentials.StoredCredential
import org.sirosfoundation.sdk.wallet.PresentationRequest

/**
 * Multi-step presentation consent screen with selective disclosure.
 *
 * Steps:
 * 1. Preview: verifier info and overview of what's requested
 * 2. Per-credential: select which claims to disclose (for each matched credential)
 * 3. Summary: confirm final selection before sharing
 */
@Composable
fun PresentationConsentScreen(
    request: PresentationRequest,
    onAccept: (List<String>) -> Unit,
    onDecline: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val totalSteps = request.matchResults.size + 2 // preview + per-credential + summary
    var currentStep by remember { mutableStateOf(0) }

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

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        // Step indicator
        StepBar(currentStep = currentStep, totalSteps = totalSteps)

        Spacer(modifier = Modifier.height(16.dp))

        // Content area
        Box(modifier = Modifier.weight(1f)) {
            when {
                currentStep == 0 -> PreviewStep(request)
                currentStep <= request.matchResults.size -> {
                    val matchResult = request.matchResults[currentStep - 1]
                    ClaimSelectionStep(
                        matchResult = matchResult,
                        claimSelections = claimSelections,
                    )
                }
                else -> SummaryStep(request, claimSelections)
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
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text("Next")
                }
            } else {
                Button(
                    onClick = { onAccept(request.candidates.map { it.id }) },
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
private fun PreviewStep(request: PresentationRequest) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // Verifier identity
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
                    text = "Credential Request",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                val vName = request.verifierName
                if (vName != null) {
                    Text(
                        text = vName,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        val verifier = request.verifierName ?: "A verifier"
        Text(
            text = "$verifier is requesting the following credentials:",
            style = MaterialTheme.typography.bodyMedium,
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Overview of matched credentials
        request.matchResults.forEach { matchResult ->
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(12.dp),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    for (cred in matchResult.candidates) {
                        CredentialRow(cred)
                    }
                    val claimCount = matchResult.requestedClaims.flatten().distinct().size
                    Text(
                        text = "$claimCount data fields requested",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp),
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
) {
    val cred = matchResult.candidates.firstOrNull()
    val claimMetaMap = cred?.metadata?.claims
        ?.associateBy { it.path.joinToString(".") } ?: emptyMap()
    val claims = matchResult.requestedClaims.flatten().distinct()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // Credential header
        if (cred != null) {
            CredentialRow(cred)
            Spacer(modifier = Modifier.height(12.dp))
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

// ── Step 3: Summary ─────────────────────────────────────────────────

@Composable
private fun SummaryStep(
    request: PresentationRequest,
    claimSelections: Map<String, Boolean>,
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

        val verifier = request.verifierName ?: "the verifier"
        Text(
            text = "You will share the following with $verifier:",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(16.dp))

        request.matchResults.forEach { matchResult ->
            val cred = matchResult.candidates.firstOrNull() ?: return@forEach
            val claimMetaMap = cred.metadata?.claims
                ?.associateBy { it.path.joinToString(".") } ?: emptyMap()
            val disclosedClaims = matchResult.requestedClaims.flatten().distinct()
                .filter { claimSelections["${matchResult.queryId}:$it"] == true }

            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    CredentialRow(cred)
                    if (disclosedClaims.isNotEmpty()) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
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

// ── Shared Components ───────────────────────────────────────────────

@Composable
private fun CredentialRow(credential: StoredCredential) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val initial = credential.metadata?.name?.firstOrNull()?.uppercase() ?: "?"
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primary),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = initial,
                color = MaterialTheme.colorScheme.onPrimary,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
            )
        }
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Text(
                text = credential.metadata?.name ?: credential.format,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
            )
            val issuerName = credential.metadata?.issuer?.name
            if (issuerName != null) {
                Text(
                    text = issuerName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** Format a claim path like "given_name" or "address.street" for display. */
private fun formatClaimName(claim: String): String {
    return claim.split(".", "_")
        .joinToString(" ") { it.replaceFirstChar { c -> c.uppercase() } }
}
