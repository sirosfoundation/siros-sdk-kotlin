// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.siros.sdk.keystore.AttestationChain

/**
 * Evidence about the wallet instance key for `POST /wallet-provider/wia/generate` (go-wallet-backend pull 486): the challenge a key is
 * generated for, and the `key_attestation` member built from its chain.
 */
internal object InstanceKeyEvidence {
    private const val LABEL = "siros-instance-key-v1"
    const val TYPE_ANDROID_KEY = "android_key"

    // The backend's bounds (it refuses more): at most 8 certificates, 8 KiB each, 32 KiB in all; a leaf and at least one more.
    private const val MAX_CERTS = 8
    private const val MAX_CERT_BYTES = 8 * 1024
    private const val MAX_TOTAL_BYTES = 32 * 1024

    /**
     * The Android attestation challenge for the WIA challenge [wiaChallenge]: SHA-256("siros-instance-key-v1" || C), C being the
     * string exactly as the backend issued it (base64url, NOT decoded), as UTF-8. No separator.
     */
    fun challengeHash(wiaChallenge: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest((LABEL + wiaChallenge).toByteArray(Charsets.UTF_8))

    /** `{"type": "android_key", "x5c": [...]}` (STANDARD base64 DER, leaf first), or null when [chain] cannot be sent as such evidence. */
    fun androidKey(chain: AttestationChain?): JsonObject? {
        if (chain == null || chain.format != AttestationChain.FORMAT_ANDROID_KEY) return null
        val certs = chain.certificates
        if (certs.size < 2 || certs.size > MAX_CERTS) return null
        if (certs.any { it.isEmpty() || it.size > MAX_CERT_BYTES } || certs.sumOf { it.size } > MAX_TOTAL_BYTES) return null
        val b64 = Base64.getEncoder()
        return JsonObject(
            mapOf(
                "type" to JsonPrimitive(TYPE_ANDROID_KEY),
                "x5c" to JsonArray(certs.map { JsonPrimitive(b64.encodeToString(it)) }),
            ),
        )
    }
}
