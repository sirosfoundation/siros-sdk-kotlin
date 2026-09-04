// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.auth

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.siros.sdk.credentials.AuthException
import timber.log.Timber

/**
 * Token kind definition — mirrors the MANIFEST in wallet-frontend's AuthTokens.ts.
 */
data class TokenKind(
    val name: String,
    val aud: String,
    val tac: String,
    val anonymous: Boolean = false,
)

/**
 * Token lifecycle manager for the new AS-based authentication.
 *
 * Manages a set of scoped access tokens (defined by [MANIFEST]),
 * handles caching, and tracks token rejections (401 responses)
 * to trigger forced logout when the session is invalid.
 *
 * Mirrors the TypeScript `AuthTokens` from wallet-frontend PR 177.
 *
 * Usage:
 * ```kotlin
 * val authTokens = AuthTokens(authServerClient, tenantId = "default")
 * val backendToken = authTokens.ensureBackendToken()
 * val anonToken = authTokens.ensureAnonymousToken()
 * ```
 */
class AuthTokens(
    private val authServerClient: AuthServerClient,
    private val tenantId: String = "default",
) {
    /**
     * Callback invoked when repeated token rejections indicate the session
     * is no longer valid. The host app should trigger a logout flow.
     */
    var onSessionRejected: (() -> Unit)? = null

    private val mutex = Mutex()
    private val tokens = java.util.concurrent.ConcurrentHashMap<String, AccessToken>()
    // ConcurrentHashMap/CopyOnWriteArrayList (rather than plain mutableMapOf/
    // mutableListOf) because registerTokenRejection is a plain (non-suspend)
    // function called directly from request-handling threads (e.g.
    // BackendApiClient.executeRaw on Dispatchers.IO, potentially from several
    // concurrent requests) - it can't take the coroutine `mutex` above without
    // becoming suspend itself, so its own map/list mutations need to be safe
    // under concurrent access independent of that mutex.
    private val rejections = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.CopyOnWriteArrayList<Long>>()

    /**
     * Ensure a valid token of the given kind is available.
     * Returns a cached token if still valid, otherwise requests a new one.
     */
    suspend fun ensureToken(name: String): AccessToken = mutex.withLock {
        val kind = MANIFEST[name]
            ?: throw AuthException("Unknown token kind: $name")

        tokens[name]?.let { cached ->
            if (!cached.isExpired()) return@withLock cached
            tokens.remove(name)
        }

        val token = try {
            if (kind.anonymous) {
                authServerClient.requestAnonymousToken(kind.aud, kind.tac)
            } else {
                authServerClient.requestAccessToken(kind.aud, kind.tac)
            }
        } catch (e: AuthException) {
            handleAsTokenFailure(e)
            throw e
        }
        tokens[name] = token
        token
    }

    /** Convenience: ensure a backend token (authenticated, full CRUD). */
    suspend fun ensureBackendToken(): AccessToken = ensureToken(TOKEN_BACKEND)

    /**
     * Convenience: ensure an anonymous token (issued without a `sub` claim;
     * still requires a real, already-authenticated session server-side).
     * Scoped to `tac ⊆ "rl"` (read/list only), enforced server-side - intended
     * for registry-style read calls, NOT for anything that needs to write
     * (e.g. the engine WebSocket session, which needs `insert` for OID4VCI
     * issuance - use [ensureBackendToken] there instead).
     */
    suspend fun ensureAnonymousToken(): AccessToken = ensureToken(TOKEN_ANONYMOUS)

    /**
     * Force-refresh a token by clearing the cache and re-requesting.
     */
    suspend fun forceRefreshToken(name: String): AccessToken = mutex.withLock {
        tokens.remove(name)
        val kind = MANIFEST[name]
            ?: throw AuthException("Unknown token kind: $name")

        val token = try {
            if (kind.anonymous) {
                authServerClient.requestAnonymousToken(kind.aud, kind.tac)
            } else {
                authServerClient.requestAccessToken(kind.aud, kind.tac)
            }
        } catch (e: AuthException) {
            handleAsTokenFailure(e)
            throw e
        }
        tokens[name] = token
        token
    }

    /**
     * A 401 straight from the AS's own `/auth/token` endpoint (i.e. minting a
     * *new* token failed, not just a previously-issued one being rejected
     * later by a backend API call) means the AS itself has already declared
     * the session dead - unlike [registerTokenRejection]'s REST-401 case,
     * there's no ambiguity to wait out via [REJECTION_THRESHOLD]/
     * [REJECTION_WINDOW_MS], so this fires [onSessionRejected] immediately.
     *
     * Without this, a call like "add credential" made with an AS session
     * that's expired (but whose locally-cached access token hadn't yet hit
     * its own claimed expiry, or had none cached at all) would throw a raw
     * [AuthException] straight out of [ensureToken]/[forceRefreshToken] with
     * no logout/re-login ever triggered — confirmed via a live "AS request
     * failed 401 - /auth/token" report with no reauth flow firing.
     */
    private fun handleAsTokenFailure(e: AuthException) {
        if (e.code == 401) {
            Timber.w("AS token request rejected (401) — session invalid")
            onSessionRejected?.invoke()
        }
    }

    /**
     * Register a token rejection (e.g. from a 401 response).
     * After [REJECTION_THRESHOLD] rejections within [REJECTION_WINDOW_MS],
     * invokes [onSessionRejected].
     */
    fun registerTokenRejection(name: String) {
        val now = System.currentTimeMillis()
        val list = rejections.computeIfAbsent(name) { java.util.concurrent.CopyOnWriteArrayList() }
        list.add(now)

        // Clear the rejected token from cache so it won't be re-served
        tokens.remove(name)

        // Prune old rejections outside the window
        list.removeAll { it < now - REJECTION_WINDOW_MS }

        if (list.size >= REJECTION_THRESHOLD) {
            Timber.w("Token '$name' rejected $REJECTION_THRESHOLD times in ${REJECTION_WINDOW_MS}ms — session invalid")
            onSessionRejected?.invoke()
        }
    }

    /** Clear all cached tokens. */
    suspend fun clear() = mutex.withLock {
        tokens.clear()
        rejections.clear()
    }

    companion object {
        const val TOKEN_BACKEND = "backend"
        const val TOKEN_ANONYMOUS = "anonymous"

        private const val REJECTION_THRESHOLD = 3
        private const val REJECTION_WINDOW_MS = 60_000L

        /** Token manifest — defines which tokens the SDK manages. */
        val MANIFEST = mapOf(
            TOKEN_BACKEND to TokenKind(
                name = TOKEN_BACKEND,
                aud = "wallet-backend",
                tac = "rwlid",
                anonymous = false,
            ),
            TOKEN_ANONYMOUS to TokenKind(
                name = TOKEN_ANONYMOUS,
                aud = "wallet-registry",
                tac = "rl",
                anonymous = true,
            ),
        )
    }
}
