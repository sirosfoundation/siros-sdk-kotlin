// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.mdoc.DeviceEngagement
import org.siros.sdk.keystore.mdoc.NfcHandoverSelect
import org.siros.sdk.sample.proximity.ActiveEngagement
import org.siros.sdk.sample.proximity.BlePeripheralServer

/**
 * ISO 18013-5 §8.2/§9.2 device engagement, shown as a QR code (§8.2.2.3),
 * NFC static handover (§9.2.1, via [ActiveEngagement]/`MdocHostApduService`),
 * AND a real "mdoc peripheral server mode" BLE GATT server ([BlePeripheralServer])
 * that a real mdoc reader can connect to, decrypt a request from, and
 * receive a signed `DeviceResponse` back from - this is a genuinely
 * completable proximity presentation, not just an engagement demo, PROVIDED
 * a stored credential's docType matches what the reader asks for.
 *
 * "mdoc central client mode" (this device scanning for and connecting to a
 * reader's own GATT server) is not implemented - see [BlePeripheralServer]'s
 * doc comment.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProximityEngagementScreen(
    getCredentials: suspend () -> List<StoredCredential>,
    signPresentation: suspend (credentialId: Long, disclosedClaims: List<String>?, sessionTranscriptBytes: ByteArray) -> ByteArray,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val engagement = remember {
        DeviceEngagement.create(supportsCentralClientMode = true, supportsPeripheralServerMode = true)
    }
    val qrBitmap = remember(engagement) { QrCodeGenerator.generate(engagement.mdocUri) }

    val blePermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        listOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
    } else {
        emptyList()
    }
    var hasBlePermissions by remember {
        mutableStateOf(
            blePermissions.all {
                ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
            },
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { results -> hasBlePermissions = results.values.all { it } }

    LaunchedEffect(Unit) {
        if (!hasBlePermissions && blePermissions.isNotEmpty()) {
            permissionLauncher.launch(blePermissions.toTypedArray())
        }
    }

    var statusLines by remember { mutableStateOf(listOf("Starting...")) }

    DisposableEffect(engagement) {
        ActiveEngagement.handoverSelectBytes = NfcHandoverSelect.build(engagement)
        onDispose { ActiveEngagement.handoverSelectBytes = null }
    }

    DisposableEffect(engagement, hasBlePermissions) {
        var server: BlePeripheralServer? = null
        if (hasBlePermissions) {
            server = BlePeripheralServer(
                context = context,
                engagement = engagement,
                getCredentials = getCredentials,
                signPresentation = signPresentation,
                onLog = { line -> statusLines = statusLines + line },
                onComplete = { success ->
                    statusLines = statusLines + if (success) "Presentation complete" else "Presentation did not complete"
                },
            )
            server.start()
        } else {
            statusLines = listOf("Bluetooth permissions not granted - BLE data retrieval disabled (QR/NFC engagement still active)")
        }
        onDispose { server?.stop() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Proximity Engagement") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                text = "Scan with an ISO 18013-5 mdoc reader",
                style = MaterialTheme.typography.titleMedium,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(16.dp))
            Image(
                bitmap = qrBitmap.asImageBitmap(),
                contentDescription = "Device engagement QR code",
                modifier = Modifier.fillMaxWidth().height(280.dp),
            )
            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "NFC is also active: tap this device against a reader's NFC antenna " +
                    "for static handover instead of scanning the QR code. BLE peripheral " +
                    "server mode is advertising - a real reader can connect and complete a " +
                    "presentation if a stored credential matches its requested docType.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(8.dp))
            for (line in statusLines.takeLast(6)) {
                Text(
                    text = line,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
