package org.siros.sdk.sample

import androidx.annotation.StringRes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.graphics.Color
import org.siros.sdk.credentials.diip.CredentialStatus

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
}

/** The sentence shown on the detail screen, rather than the one-word ribbon. */
@StringRes
fun CredentialStatus.detailRes(): Int = when (this) {
    CredentialStatus.VALID -> R.string.credential_status_expired_detail // unused; see [labelRes]
    CredentialStatus.EXPIRED -> R.string.credential_status_expired_detail
    CredentialStatus.NOT_YET_VALID -> R.string.credential_status_not_yet_valid_detail
    CredentialStatus.REVOKED -> R.string.credential_status_revoked_detail
    CredentialStatus.SUSPENDED -> R.string.credential_status_suspended_detail
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
    CredentialStatus.NOT_YET_VALID, CredentialStatus.SUSPENDED -> MaterialTheme.colorScheme.tertiary
    CredentialStatus.VALID -> MaterialTheme.colorScheme.primary
}
