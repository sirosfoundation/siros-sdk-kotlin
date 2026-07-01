// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.sirosfoundation.sdk.auth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.sirosfoundation.sdk.credentials.AuthException

/**
 * Token Access Control permission flags.
 *
 * | Flag | Purpose  |
 * |------|----------|
 * | `r`  | read     |
 * | `w`  | write    |
 * | `l`  | list     |
 * | `i`  | insert   |
 * | `d`  | delete   |
 * | `k`  | delegate |
 * | `a`  | admin    |
 */
enum class TacPermission(val flag: Char) {
    READ('r'),
    WRITE('w'),
    LIST('l'),
    INSERT('i'),
    DELETE('d'),
    DELEGATE('k'),
    ADMIN('a');

    companion object {
        /** Parse a TAC string like "rwl" into a set of permissions. */
        fun parse(tac: String): Set<TacPermission> =
            tac.mapNotNull { ch -> entries.find { it.flag == ch } }.toSet()
    }
}

/**
 * Authentication Context Class Reference.
 */
enum class Acr(val value: String) {
    PASSKEY("urn:siros:acr:passkey"),
    OIDC("urn:siros:acr:oidc");

    companion object {
        fun fromValue(value: String): Acr =
            entries.find { it.value == value }
                ?: throw AuthException("Unknown ACR value: $value")
    }
}

/**
 * JWT payload from the AS token endpoint.
 */
@Serializable
internal data class AccessTokenPayload(
    val sub: String,
    val aud: String,
    @SerialName("tenant_id") val tenantId: String,
    val tac: String,
    val acr: String,
    val exp: Long,
)

/**
 * Parsed access token with claims and utility methods.
 *
 * Mirrors the TypeScript `AccessToken` from wallet-frontend.
 */
class AccessToken(jwt: String) {
    /** Raw JWT string for use in Authorization headers. */
    val raw: String = jwt

    /** Subject — user ID this token represents. */
    val sub: String

    /** Audience — service this token is valid for. */
    val aud: String

    /** Tenant ID for multi-tenant isolation. */
    val tenantId: String

    /** Token Access Control permissions. */
    val tac: Set<TacPermission>

    /** Authentication context — how the user authenticated. */
    val acr: Acr

    /** Token expiration timestamp (epoch millis). */
    val expiresAtMillis: Long

    init {
        val payload = parseJwt(jwt)
        sub = payload.sub
        aud = payload.aud
        tenantId = payload.tenantId
        tac = TacPermission.parse(payload.tac)
        acr = Acr.fromValue(payload.acr)
        expiresAtMillis = payload.exp * 1000
    }

    /** True if the token is expired (with a 10-second safety margin). */
    fun isExpired(): Boolean =
        System.currentTimeMillis() >= expiresAtMillis - 10_000

    /** Returns the raw JWT for use in Authorization headers. */
    fun token(): String = raw

    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        private fun parseJwt(jwt: String): AccessTokenPayload {
            val parts = jwt.split('.')
            if (parts.size != 3) throw AuthException("Invalid JWT format")
            val payload = java.util.Base64.getUrlDecoder().decode(parts[1])
            return json.decodeFromString(AccessTokenPayload.serializer(), String(payload, Charsets.UTF_8))
        }
    }
}
