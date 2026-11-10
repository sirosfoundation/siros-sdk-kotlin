// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.outlined.Contactless
import androidx.compose.material.icons.outlined.PhotoCamera
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/** Which of the two holder-initiated engagements [ProximityEngagementScreen] puts in front of the user. */
enum class ProximityStyle { Nfc, Qr }

const val SHARE_TAP_TAG = "share_tap"
const val SHARE_SHOW_QR_TAG = "share_show_qr"
const val SHARE_SCAN_QR_TAG = "share_scan_qr"

/**
 * Share In-Person: the three ways to hand a credential to a device in front
 * of the user. Tap and Show QR are the two faces of one ISO 18013-5 device
 * engagement (the SDK serves the NFC handover and the QR code at the same
 * time; the choice is which one the screen presents). Scan QR code reads the
 * other party's code with the wallet's one QR scanner.
 */
@Composable
fun ShareInPersonScreen(
    onTap: () -> Unit,
    onShowQr: () -> Unit,
    onScanQr: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = ScreenMargin, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        ScreenTitle(stringResource(R.string.share_title))
        Text(
            stringResource(R.string.share_intro),
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium,
        )
        Spacer(modifier = Modifier.height(4.dp))
        ActionCard(
            title = stringResource(R.string.share_tap_title),
            subtitle = stringResource(R.string.share_tap_subtitle),
            icon = Icons.Outlined.Contactless,
            onClick = onTap,
            tileLeading = true,
            modifier = Modifier.testTag(SHARE_TAP_TAG),
        )
        ActionCard(
            title = stringResource(R.string.share_show_qr_title),
            subtitle = stringResource(R.string.share_show_qr_subtitle),
            icon = Icons.Filled.QrCode2,
            onClick = onShowQr,
            tileLeading = true,
            modifier = Modifier.testTag(SHARE_SHOW_QR_TAG),
        )
        ActionCard(
            title = stringResource(R.string.add_credential_option_scan_qr_title),
            subtitle = stringResource(R.string.share_scan_qr_subtitle),
            icon = Icons.Outlined.PhotoCamera,
            onClick = onScanQr,
            tileLeading = true,
            modifier = Modifier.testTag(SHARE_SCAN_QR_TAG),
        )
    }
}
