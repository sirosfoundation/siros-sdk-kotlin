// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.siros.sdk.auth.WalletInstance
import org.siros.sdk.auth.WalletInstanceStatus

/**
 * Settings → Devices: the wallet instances this user has in this tenant
 * (SID-AUTH-06, go-wallet-backend#319), and the two things a user can do
 * about them - suspend/reactivate/remove one, or deactivate the whole wallet.
 *
 * A thin consumer, deliberately: every rule about what a status change costs
 * (the token cut-off and the re-login that follows it, the erasure retry, what
 * becomes of the local account) lives in the SDK. This screen only renders
 * what `listWalletInstances()` returned and calls the two facade methods.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DevicesScreen(
    instances: List<WalletInstance>,
    loading: Boolean,
    errorMessage: String?,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.devices_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.nav_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            Text(
                stringResource(R.string.devices_description),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))

            if (errorMessage != null) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.errorContainer,
                ) {
                    Text(
                        errorMessage,
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
                Spacer(Modifier.height(16.dp))
            }

            when {
                loading && instances.isEmpty() -> Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) { CircularProgressIndicator(modifier = Modifier.size(28.dp)) }

                instances.isEmpty() -> Text(
                    stringResource(R.string.devices_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                else -> instances.forEach { instance ->
                    DeviceRow(instance)
                    Spacer(Modifier.height(12.dp))
                }
            }

            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = onRefresh,
                enabled = !loading,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(12.dp),
            ) { Text(stringResource(R.string.devices_refresh)) }

            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun DeviceRow(instance: WalletInstance) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    deviceLabel(instance),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                )
                StatusPill(instance.statusEnum)
            }
            if (instance.isThisDevice) {
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.devices_this_device),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Spacer(Modifier.height(8.dp))
            DeviceDetail(stringResource(R.string.devices_instance_id), instance.id)
            if (instance.wscdType.isNotBlank()) {
                DeviceDetail(stringResource(R.string.devices_wscd_type), instance.wscdType)
            }
            instance.lastAttestedAt?.takeIf { it.isNotBlank() }?.let {
                DeviceDetail(stringResource(R.string.devices_last_attested), it)
            }
            instance.statusReason?.takeIf { it.isNotBlank() }?.let {
                DeviceDetail(stringResource(R.string.devices_status_reason), it)
            }

        }
    }
}

@Composable
private fun StatusPill(status: WalletInstanceStatus?) {
    val (labelRes, color) = when (status) {
        WalletInstanceStatus.ACTIVE -> R.string.devices_status_active to MaterialTheme.colorScheme.primary
        WalletInstanceStatus.SUSPENDED -> R.string.devices_status_suspended to MaterialTheme.colorScheme.tertiary
        WalletInstanceStatus.REVOKED -> R.string.devices_status_revoked to MaterialTheme.colorScheme.error
        null -> R.string.devices_status_unknown to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Surface(shape = RoundedCornerShape(999.dp), color = color.copy(alpha = 0.12f)) {
        Text(
            stringResource(labelRes),
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelMedium,
            color = color,
        )
    }
}

@Composable
private fun DeviceDetail(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(
            label,
            modifier = Modifier.weight(0.4f),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(value, modifier = Modifier.weight(0.6f), style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * Something short enough to name a device in a confirmation dialog. The
 * backend has no display name for an instance - the id is a JWK thumbprint -
 * so this is the WSCD type when there is one, plus a truncated id.
 */
private fun deviceLabel(instance: WalletInstance): String {
    val head = instance.id.take(10)
    return if (instance.wscdType.isNotBlank()) "${instance.wscdType} · $head…" else "$head…"
}

/**
 * The screen for [org.siros.sdk.wallet.WalletState.LifecycleBlocked]: the
 * backend refuses this installation and no amount of retrying the same login
 * changes that until someone else acts. A suspended instance can be
 * reactivated from another device, so the offer is to try again later; a
 * revoked instance and a deactivated wallet are both terminal, and the only
 * way forward is a new enrollment.
 *
 * The three are told apart because they mean different things to the user: a
 * revoked instance leaves their other devices and credentials alone, while a
 * deactivated wallet has had its server-side data erased. Saying the second
 * when the first happened would tell the user their credentials are gone when
 * they are not.
 */
@Composable
fun WalletBlockedScreen(
    reason: org.siros.sdk.auth.WalletLifecycleRefusal,
    message: String?,
    onRetry: () -> Unit,
    onEnrollAgain: () -> Unit,
    /** A login is already in flight; the single action here must not start a second. */
    isLoading: Boolean = false,
) {
    val suspended = reason == org.siros.sdk.auth.WalletLifecycleRefusal.SUSPENDED
    val deactivated = reason == org.siros.sdk.auth.WalletLifecycleRefusal.DEACTIVATED
    val titleRes = when {
        suspended -> R.string.wallet_blocked_suspended_title
        deactivated -> R.string.wallet_blocked_deactivated_title
        else -> R.string.wallet_blocked_revoked_title
    }
    val messageRes = when {
        suspended -> R.string.wallet_blocked_suspended_message
        deactivated -> R.string.wallet_blocked_deactivated_message
        else -> R.string.wallet_blocked_revoked_message
    }
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(titleRes),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            // The backend's own text when it sent one - it is written for the
            // user and may say more than we can (who suspended it, and why).
            message ?: stringResource(messageRes),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(32.dp))
        Button(
            onClick = if (suspended) onRetry else onEnrollAgain,
            enabled = !isLoading,
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(
                stringResource(
                    if (suspended) R.string.wallet_blocked_retry else R.string.wallet_blocked_enroll_again
                )
            )
        }
    }
}
