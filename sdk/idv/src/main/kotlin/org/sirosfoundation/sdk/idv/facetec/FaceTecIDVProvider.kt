// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.idv.facetec

import android.app.Activity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.sirosfoundation.sdk.idv.IDVException
import org.sirosfoundation.sdk.idv.IDVResult
import org.sirosfoundation.sdk.idv.IdentityVerificationProvider
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * FaceTec identity verification provider.
 *
 * Wraps the FaceTec mobile SDK and facetec-api server to perform
 * liveness detection + document verification, returning a
 * credential offer URI for OID4VCI issuance.
 *
 * ## Prerequisites
 *
 * 1. Add the FaceTec SDK dependency to your app's build.gradle.kts:
 *    ```kotlin
 *    implementation("com.facetec:facetec-sdk:9.8.+")
 *    ```
 *
 * 2. Initialize with your facetec-api server URL:
 *    ```kotlin
 *    val idvProvider = FaceTecIDVProvider(
 *        serverUrl = "https://idv.example.com",
 *        authToken = "Bearer <access-token>",
 *    )
 *    wallet.verifyIdentityAndIssue(idvProvider, activity)
 *    ```
 *
 * ## Flow
 *
 * 1. Get session token from facetec-api
 * 2. FaceTec SDK captures liveness (FaceScan)
 * 3. Send FaceScan to facetec-api → livenessSessionId
 * 4. FaceTec SDK captures document (ID scan)
 * 5. Send document + livenessSessionId → credentialOfferURI
 * 6. Return IDVResult for OID4VCI issuance
 */
class FaceTecIDVProvider(
    /** Base URL of the facetec-api server (e.g., "https://idv.example.com"). */
    private val serverUrl: String,
    /** Authorization header value (e.g., "Bearer <token>"). */
    private val authToken: String,
    /** Optional FaceTec device key SDK initialization (testing only). */
    private val deviceKey: String? = null,
) : IdentityVerificationProvider {

    override val name: String = "FaceTec"

    override suspend fun isAvailable(): Boolean {
        return try {
            Class.forName("com.facetec.sdk.FaceTecSDK")
            true
        } catch (_: ClassNotFoundException) {
            false
        }
    }

    override suspend fun startVerification(activity: Activity): IDVResult = withContext(Dispatchers.IO) {
        // Step 1: Get session token
        val sessionToken = getSessionToken()

        // Step 2-3: Liveness check
        // The FaceTec SDK UI is presented on the main thread via the activity.
        // This implementation delegates to FaceTecProcessor which handles the
        // FaceScan capture and server communication.
        val livenessSessionId = performLivenessCheck(activity, sessionToken)

        // Step 4-5: ID scan + credential issuance
        val result = performIDScan(activity, sessionToken, livenessSessionId)

        IDVResult(
            credentialOfferURI = result.credentialOfferURI,
            transactionId = result.transactionId,
        )
    }

    // MARK: - API calls

    private suspend fun getSessionToken(): String {
        val json = postJson("$serverUrl/v1/session-token", JSONObject())
        return json.getString("sessionToken")
    }

    private suspend fun performLivenessCheck(activity: Activity, sessionToken: String): String {
        // TODO: Integrate with FaceTec SDK
        // 1. Initialize FaceTec SDK: FaceTecSDK.initializeInProductionMode(...)
        // 2. Create FaceTecSessionActivity for liveness capture
        // 3. On success, get FaceScan data + audit trail images
        // 4. POST to /v1/liveness with the biometric data
        // 5. Return livenessSessionId

        // Placeholder: direct API call with mock data for testing
        throw IDVException.Unavailable("FaceTec SDK liveness capture not yet implemented. " +
            "Add com.facetec:facetec-sdk dependency and implement FaceScan capture.")
    }

    private suspend fun performIDScan(activity: Activity, sessionToken: String, livenessSessionId: String): IDScanResult {
        // TODO: Integrate with FaceTec SDK
        // 1. Create FaceTecIDScanActivity for document capture
        // 2. On success, get document images
        // 3. POST to /v1/id-scan with images + livenessSessionId
        // 4. Return credentialOfferURI + transactionId

        throw IDVException.Unavailable("FaceTec SDK ID scan not yet implemented. " +
            "Add com.facetec:facetec-sdk dependency and implement document capture.")
    }

    /**
     * Submit a liveness FaceScan to the facetec-api server.
     * Call this from the FaceTec SDK callback after a successful liveness session.
     *
     * @param faceScan Base64-encoded FaceScan data from FaceTec SDK.
     * @param auditTrailImage Base64-encoded audit trail image.
     * @param lowQualityAuditTrailImage Base64-encoded low quality audit trail.
     * @return livenessSessionId for use in the subsequent ID scan call.
     */
    suspend fun submitLiveness(
        faceScan: String,
        auditTrailImage: String,
        lowQualityAuditTrailImage: String,
    ): String = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("faceScan", faceScan)
            put("auditTrailImage", auditTrailImage)
            put("lowQualityAuditTrailImage", lowQualityAuditTrailImage)
        }

        val result = postJson("$serverUrl/v1/liveness", body, throwOn422 = { msg ->
            IDVException.LivenessFailed(msg)
        })
        result.getString("livenessSessionId")
    }

    /**
     * Submit an ID scan to the facetec-api server.
     * Call this from the FaceTec SDK callback after a successful ID scan session.
     *
     * @param idScanFrontImage Base64-encoded front of document.
     * @param idScanBackImage Base64-encoded back of document (optional).
     * @param livenessSessionId From the previous [submitLiveness] call.
     * @return IDScanResult with credentialOfferURI for OID4VCI issuance.
     */
    suspend fun submitIDScan(
        idScanFrontImage: String,
        idScanBackImage: String? = null,
        livenessSessionId: String,
    ): IDScanResult = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("idScanFrontImage", idScanFrontImage)
            if (idScanBackImage != null) put("idScanBackImage", idScanBackImage)
            put("livenessSessionId", livenessSessionId)
        }

        val result = postJson("$serverUrl/v1/id-scan", body, throwOn422 = { msg ->
            IDVException.VerificationFailed(msg)
        })
        IDScanResult(
            transactionId = result.getString("transactionId"),
            credentialOfferURI = result.getString("credentialOfferURI"),
        )
    }

    // MARK: - HTTP helper

    private fun postJson(
        url: String,
        body: JSONObject,
        throwOn422: ((String) -> IDVException)? = null,
    ): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Authorization", authToken)
            conn.connectTimeout = 30_000
            conn.readTimeout = 60_000
            conn.doOutput = true

            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body.toString()) }

            val code = conn.responseCode
            val responseBody = if (code in 200..299) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else {
                conn.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
            }

            if (code == 422 && throwOn422 != null) {
                throw throwOn422(responseBody)
            }
            if (code !in 200..299) {
                throw IDVException.NetworkError(Exception("HTTP $code: $responseBody"))
            }

            return JSONObject(responseBody)
        } finally {
            conn.disconnect()
        }
    }

    // MARK: - Data types

    data class IDScanResult(
        val transactionId: String,
        val credentialOfferURI: String,
    )
}
