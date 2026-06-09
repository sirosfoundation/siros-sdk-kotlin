// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.sample

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import timber.log.Timber
import java.util.concurrent.Executors

/**
 * QR code scanner screen for OID4VCI credential offer URIs
 * and OID4VP presentation request URIs.
 *
 * Detects URLs containing `credential_offer_uri`, `credential_offer`,
 * or `request_uri` parameters and calls the appropriate handler.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScannerScreen(
    onQrScanned: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.qr_scanner_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
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
                .padding(padding),
        ) {
            if (hasCameraPermission) {
                CameraPreviewWithScanner(
                    onQrScanned = onQrScanned,
                    modifier = Modifier.weight(1f),
                )
            } else {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Text(
                        text = stringResource(R.string.qr_scanner_permission_required),
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(
                        onClick = { launcher.launch(Manifest.permission.CAMERA) },
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Text(stringResource(R.string.qr_scanner_grant_permission))
                    }
                }
            }

            // Paste URI section (useful for testing / pre-authorized offers)
            HorizontalDivider()
            var pasteUri by remember { mutableStateOf("") }
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            ) {
                Text(
                    text = stringResource(R.string.qr_scanner_paste_label),
                    style = MaterialTheme.typography.labelLarge,
                )
                Spacer(modifier = Modifier.height(4.dp))
                OutlinedTextField(
                    value = pasteUri,
                    onValueChange = { pasteUri = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("openid-credential-offer://...") },
                    singleLine = true,
                )
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = { if (pasteUri.isNotBlank()) onQrScanned(pasteUri.trim()) },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = pasteUri.isNotBlank(),
                ) {
                    Text(stringResource(R.string.qr_scanner_paste_button))
                }
            }
        }
    }
}

@Composable
@androidx.annotation.OptIn(androidx.camera.core.ExperimentalGetImage::class)
private fun CameraPreviewWithScanner(
    onQrScanned: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var scanned by remember { mutableStateOf(false) }

    Box(modifier = modifier.fillMaxSize()) {
        AndroidView(
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)

                cameraProviderFuture.addListener({
                    val cameraProvider = cameraProviderFuture.get()

                    val preview = Preview.Builder().build().also {
                        it.surfaceProvider = previewView.surfaceProvider
                    }

                    val analyzer = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()

                    val scanner = BarcodeScanning.getClient()
                    val executor = Executors.newSingleThreadExecutor()

                    analyzer.setAnalyzer(executor) { imageProxy ->
                        val mediaImage = imageProxy.image
                        if (mediaImage != null && !scanned) {
                            val inputImage = InputImage.fromMediaImage(
                                mediaImage,
                                imageProxy.imageInfo.rotationDegrees,
                            )
                            scanner.process(inputImage)
                                .addOnSuccessListener { barcodes ->
                                    for (barcode in barcodes) {
                                        if (barcode.valueType == Barcode.TYPE_URL ||
                                            barcode.valueType == Barcode.TYPE_TEXT
                                        ) {
                                            val value = barcode.rawValue ?: continue
                                            if (isOID4URI(value)) {
                                                scanned = true
                                                Timber.d("QR scanned: $value")
                                                onQrScanned(value)
                                            }
                                        }
                                    }
                                }
                                .addOnCompleteListener {
                                    imageProxy.close()
                                }
                        } else {
                            imageProxy.close()
                        }
                    }

                    try {
                        cameraProvider.unbindAll()
                        cameraProvider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            analyzer,
                        )
                    } catch (e: Exception) {
                        Timber.e(e, "Camera bind failed")
                    }
                }, ContextCompat.getMainExecutor(ctx))

                previewView
            },
            modifier = Modifier.fillMaxSize(),
        )

        // Hint overlay
        Text(
            text = stringResource(R.string.qr_scanner_hint),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
            textAlign = TextAlign.Center,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(32.dp),
        )
    }
}

/**
 * Check if a scanned value looks like an OID4VCI or OID4VP URI.
 */
private fun isOID4URI(value: String): Boolean {
    return value.contains("credential_offer_uri=", ignoreCase = true) ||
        value.contains("credential_offer=", ignoreCase = true) ||
        value.contains("request_uri=", ignoreCase = true) ||
        value.startsWith("openid-credential-offer://", ignoreCase = true) ||
        value.startsWith("openid4vp://", ignoreCase = true) ||
        value.startsWith("haip://", ignoreCase = true)
}
