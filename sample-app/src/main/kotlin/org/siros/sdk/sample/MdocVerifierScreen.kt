// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import org.siros.sdk.verifier.mdoc.VerifiedMdocDocument

/** UI only: verification is available regardless of WalletState or account registration. */
data class VerifierUiState(
    val endpoint: String,
    val tenantId: String = "default",
    val scanning: Boolean = false,
    val busy: Boolean = false,
    val status: String? = null,
    val documents: List<VerifiedMdocDocument> = emptyList(),
    val error: String? = null,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MdocVerifierScreen(
    state: VerifierUiState,
    onEndpointChange: (String) -> Unit,
    onTenantChange: (String) -> Unit,
    onStartScan: () -> Unit,
    onStartNfc: () -> Unit,
    onBluetoothPermissionsDenied: () -> Unit,
    onQrScanned: (String) -> Unit,
    onCancelScan: () -> Unit,
    onClear: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val bluetoothPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
    } else {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { granted ->
        if (bluetoothPermissions.all { granted[it] == true }) onStartScan() else onBluetoothPermissionsDenied()
    }
    val startScanWithPermissions = {
        if (bluetoothPermissions.all {
                ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
            }
        ) {
            onStartScan()
        } else {
            permissionLauncher.launch(bluetoothPermissions)
        }
    }

    if (state.scanning) {
        QrScannerScreen(
            onQrScanned = onQrScanned,
            onBack = onCancelScan,
            title = "Verify nearby mdoc",
            pasteLabel = "Paste an mdoc engagement",
            pastePlaceholder = "mdoc:...",
            pasteButtonLabel = "Verify engagement",
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Verify nearby mdoc") },
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
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "No wallet account is required. The presentation is verified locally and every issuer is authorized by go-trust.",
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedTextField(
                value = state.endpoint,
                onValueChange = onEndpointChange,
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.busy,
                singleLine = true,
                label = { Text("go-trust evaluation URL") },
                placeholder = { Text("http://10.0.2.2:9095/v1/evaluate") },
            )
            OutlinedTextField(
                value = state.tenantId,
                onValueChange = onTenantChange,
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.busy,
                singleLine = true,
                label = { Text("Tenant ID") },
            )
            Text(
                "Request: mDL given name and family name; no retention.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = startScanWithPermissions,
                    enabled = !state.busy && state.endpoint.isNotBlank() && state.tenantId.isNotBlank(),
                ) {
                    Text("Scan wallet QR")
                }
                OutlinedButton(
                    onClick = onStartNfc,
                    enabled = !state.busy && state.endpoint.isNotBlank() && state.tenantId.isNotBlank(),
                ) {
                    Text("Tap wallet (NFC)")
                }
                if (state.documents.isNotEmpty() || state.error != null) {
                    OutlinedButton(onClick = onClear, enabled = !state.busy) {
                        Text("Clear")
                    }
                }
            }
            if (state.busy) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(1.dp))
                    Text(
                        state.status ?: "Verifying…",
                        modifier = Modifier.padding(start = 12.dp),
                    )
                }
            }
            state.error?.let { error ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        error,
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            if (state.error == null && state.documents.isNotEmpty()) {
                Text(
                    "Verified and authorized by go-trust",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.SemiBold,
                )
                state.documents.forEach { document ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(document.docType, fontWeight = FontWeight.SemiBold)
                            Text("Valid until: ${document.validUntil}", style = MaterialTheme.typography.bodySmall)
                            Spacer(modifier = Modifier.height(8.dp))
                            document.elements.forEach { element ->
                                Text(element.identifier, style = MaterialTheme.typography.labelLarge)
                                Text(formatElementValue(element.valueCbor))
                                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun formatElementValue(bytes: ByteArray): String = try {
    val value = CBORObject.DecodeFromBytes(bytes)
    if (value.type == CBORType.TextString) value.AsString() else value.ToJSONString()
} catch (_: Exception) {
    "Undisplayable CBOR value"
}
