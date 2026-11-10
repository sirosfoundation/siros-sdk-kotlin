package org.siros.sdk.sample

import androidx.annotation.StringRes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.graphics.Color
import org.siros.sdk.credentials.interop.CredentialStatus

/**
 * How a [CredentialStatus] is shown.
 *
 * Only the presentation lives here - which words and which colour. Whether a
 * credential *has* a status is the SDK's answer (see
 * `SirosWallet.refreshCredentialStatuses`), because establishing it means
 * reading a validity window and fetching the issuer's Token Status List.
 */
@StringRes
fun CredentialStatus.labelRes(): Int = when (this) {
    CredentialStatus.VALID -> R.string.credential_status_expired // unused; VALID is never rendered
    CredentialStatus.EXPIRED -> R.string.credential_status_expired
    CredentialStatus.NOT_YET_VALID -> R.string.credential_status_not_yet_valid
    CredentialStatus.REVOKED -> R.string.credential_status_revoked
    CredentialStatus.SUSPENDED -> R.string.credential_status_suspended
    CredentialStatus.UNKNOWN -> R.string.credential_status_unknown
}

/** The sentence shown on the detail screen, rather than the one-word ribbon. */
@StringRes
fun CredentialStatus.detailRes(): Int = when (this) {
    CredentialStatus.VALID -> R.string.credential_status_expired_detail // unused; see [labelRes]
    CredentialStatus.EXPIRED -> R.string.credential_status_expired_detail
    CredentialStatus.NOT_YET_VALID -> R.string.credential_status_not_yet_valid_detail
    CredentialStatus.REVOKED -> R.string.credential_status_revoked_detail
    CredentialStatus.SUSPENDED -> R.string.credential_status_suspended_detail
    CredentialStatus.UNKNOWN -> R.string.credential_status_unknown_detail
}

/**
 * Error colouring for the permanent outcomes, warning colouring for the ones
 * that may resolve on their own - a suspended credential can be reinstated by
 * its issuer, and one that is not yet valid simply becomes valid.
 */
@Composable
@ReadOnlyComposable
fun CredentialStatus.ribbonColor(): Color = when (this) {
    CredentialStatus.EXPIRED, CredentialStatus.REVOKED -> MaterialTheme.colorScheme.error
    CredentialStatus.NOT_YET_VALID, CredentialStatus.SUSPENDED, CredentialStatus.UNKNOWN ->
        MaterialTheme.colorScheme.tertiary
    CredentialStatus.VALID -> MaterialTheme.colorScheme.primary
}

/**
 * The content colour that goes on [ribbonColor].
 *
 * Material only guarantees contrast between a role and its own `on` colour, so
 * a label fixed to `onError` over a `tertiary` ribbon can come out unreadable
 * in some themes. Each status pairs with the role its background came from.
 */
@Composable
@ReadOnlyComposable
fun CredentialStatus.ribbonContentColor(): Color = when (this) {
    CredentialStatus.EXPIRED, CredentialStatus.REVOKED -> MaterialTheme.colorScheme.onError
    CredentialStatus.NOT_YET_VALID, CredentialStatus.SUSPENDED, CredentialStatus.UNKNOWN ->
        MaterialTheme.colorScheme.onTertiary
    CredentialStatus.VALID -> MaterialTheme.colorScheme.onPrimary
}

/**
 * Whether this credential belongs under "Needs attention": its status stops
 * it being used, or - when [countExhausted] - no copy of it is left to
 * present, the state its card shows as renew-only.
 *
 * The status is the SDK's ([statuses], see
 * `WalletViewModel.credentialStatuses`). Where the SDK has not evaluated the
 * credential yet, its own `exp` decides, exactly as on its card - so the
 * banner and the filter never disagree with what the card says.
 *
 * [countExhausted] is false until the signer's key inventory has been read:
 * before that every copy looks keyless, and a wallet full of healthy
 * credentials would briefly count as needing attention.
 *
 * [copiesReusable] is the wallet's consumption policy: under
 * `NEVER_CONSUME` a copy that has been presented can be presented again, so
 * only a copy without its key is spent. Under the consuming policies a
 * presented copy is spent (as `CredentialUtils.eligibleInstances` has it).
 */
fun org.siros.sdk.credentials.CredentialWithInstances.needsAttention(
    statuses: Map<Long, CredentialStatus>,
    countExhausted: Boolean = true,
    nowMillis: Long = System.currentTimeMillis(),
    copiesReusable: Boolean = false,
): Boolean {
    // expiresAt is a JWT `exp` claim - always epoch SECONDS, not millis.
    val status = statuses[credential.id]
        ?: CredentialStatus.EXPIRED.takeIf { credential.expiresAt?.let { exp -> exp * 1000L < nowMillis } == true }
    if (status != null && !status.isUsable) return true
    return countExhausted && instances.none { it.hasKey && (copiesReusable || it.sigCount == 0) }
}

/**
 * Whether [query] occurs in what the credential's card calls it: the title
 * and the type label under it, resolved the way the card resolves them (see
 * [cardLabels]). A blank query matches every credential.
 */
fun org.siros.sdk.credentials.StoredCredential.matchesSearch(query: String): Boolean {
    val q = query.trim()
    if (q.isEmpty()) return true
    val meta = metadata ?: org.siros.sdk.credentials.CredentialUtils.buildFallbackMetadata(this)
    val labels = cardLabels(meta?.name, format, meta?.vct ?: meta?.doctype)
    return labels.title.contains(q, ignoreCase = true) || labels.typeBadge?.contains(q, ignoreCase = true) == true
}
