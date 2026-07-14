// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.idv.facetec

import android.app.Activity
import org.json.JSONObject
import org.sirosfoundation.sdk.idv.BiometricCaptureDelegate
import org.sirosfoundation.sdk.idv.IDVException

/**
 * FaceTec biometric capture delegate.
 *
 * Implements [BiometricCaptureDelegate] by wrapping the FaceTec mobile SDK
 * to capture liveness (FaceScan) and document images. The actual HTTP
 * communication with the IDV backend is handled by [RemoteIDVClient].
 *
 * ## Setup
 *
 * ```kotlin
 * // In your app module (depends on FaceTec SDK):
 * val captureDelegate = FaceTecCaptureDelegate()
 * val client = RemoteIDVClient(RemoteIDVClient.Config(
 *     serverUrl = "https://idv.example.com",
 *     authToken = "Bearer <token>",
 * ))
 * val provider = RemoteIDVProvider(client, captureDelegate)
 * wallet.verifyIdentityAndIssue(provider, activity)
 * ```
 *
 * ## FaceTec SDK Integration
 *
 * The FaceTec SDK is distributed via a private Maven repository configured
 * in CI secrets (`FACETEC_MAVEN_URL`, `FACETEC_MAVEN_TOKEN`).
 * See the project's `settings.gradle.kts` for repository setup.
 *
 * Implement the capture methods using FaceTec's session API:
 *
 * 1. `captureLiveness`: Create a `FaceTecSession`, capture FaceScan,
 *    return `{ faceScan, auditTrailImage, lowQualityAuditTrailImage }`.
 *
 * 2. `captureDocument`: Create a `FaceTecIDScanSession`, capture
 *    document images, return `{ idScanFrontImage, livenessSessionId }`.
 */
class FaceTecCaptureDelegate : BiometricCaptureDelegate {

    override val name: String = "FaceTec"

    override suspend fun isAvailable(): Boolean {
        return try {
            Class.forName("com.facetec.sdk.FaceTecSDK")
            true
        } catch (_: ClassNotFoundException) {
            false
        }
    }

    override suspend fun captureLiveness(activity: Activity, sessionToken: String): JSONObject {
        // TODO: Implement with FaceTec SDK
        //
        // 1. Initialize FaceTec SDK if needed:
        //    FaceTecSDK.initializeInProductionMode(activity, ...)
        //
        // 2. Create and start a FaceTec session:
        //    val session = FaceTecSession(activity, sessionToken, faceTecCallback)
        //
        // 3. In the callback's processSessionWhileFaceTecSDKWaits():
        //    Extract faceScan, auditTrailImage, lowQualityAuditTrailImage
        //    from the FaceTecSessionResult
        //
        // 4. Return the payload:
        //    JSONObject().apply {
        //        put("faceScan", result.faceScan)
        //        put("auditTrailImage", result.auditTrailCompressedBase64[0])
        //        put("lowQualityAuditTrailImage", result.lowQualityAuditTrailCompressedBase64[0])
        //    }

        throw IDVException.Unavailable(
            "FaceTec SDK not integrated. Add com.facetec:facetec-sdk dependency " +
            "and implement captureLiveness() using FaceTecSession."
        )
    }

    override suspend fun captureDocument(
        activity: Activity,
        sessionToken: String,
        livenessSessionId: String,
    ): JSONObject {
        // TODO: Implement with FaceTec SDK
        //
        // 1. Create and start a FaceTec ID scan session:
        //    val session = FaceTecIDScanSession(activity, sessionToken, idScanCallback)
        //
        // 2. In the callback's processIDScanWhileFaceTecSDKWaits():
        //    Extract idScanFrontImage (and optionally back)
        //
        // 3. Return the payload:
        //    JSONObject().apply {
        //        put("idScanFrontImage", result.idScanFrontImage)
        //        put("livenessSessionId", livenessSessionId)
        //    }

        throw IDVException.Unavailable(
            "FaceTec SDK not integrated. Add com.facetec:facetec-sdk dependency " +
            "and implement captureDocument() using FaceTecIDScanSession."
        )
    }
}
