// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.runtime.Composable
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.mdoc.ReaderTrustResult
import org.siros.sdk.sample.WalletViewModel.ActivateMode

/**
 * The wallet's two engagement screens behind one entry point: scanning a QR
 * code ([ScanQrContent]) and presenting an ISO 18013-5 device engagement
 * ([ProximityEngagementScreen], as an NFC tap or a displayed QR code per
 * [proximityStyle]). Both are chrome-free; the caller frames them and owns
 * Back, which always means "leave Activate entirely".
 */
@Composable
fun ActivateScreen(
    mode: ActivateMode,
    proximityStyle: ProximityStyle,
    onQrScanned: (String) -> Unit,
    getCredentials: suspend () -> List<StoredCredential>,
    signPresentation: suspend (credentialId: Long, disclosedClaims: List<String>?, sessionTranscriptBytes: ByteArray) -> ByteArray,
    filterEligible: suspend (List<StoredCredential>) -> List<StoredCredential>,
    evaluateReaderTrust: suspend (x5chain: List<ByteArray>) -> ReaderTrustResult,
    onBack: () -> Unit,
) {
    when (mode) {
        ActivateMode.Qr -> ScanQrContent(onQrScanned = onQrScanned)
        ActivateMode.Proximity -> ProximityEngagementScreen(
            getCredentials = getCredentials,
            signPresentation = signPresentation,
            filterEligible = filterEligible,
            evaluateReaderTrust = evaluateReaderTrust,
            onBack = onBack,
            style = proximityStyle,
        )
    }
}
