package org.siros.sdk.auth

import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.AuthException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Covers [AuthTokens.registerTokenRejection]'s counting/threshold logic -
 * this was previously dead code (nothing in the codebase called it despite
 * [BackendApiClient] and [org.siros.sdk.transport.engine.WalletEngineSession]
 * both seeing real 401/403 auth failures and doing nothing about them). These
 * tests only cover the counter itself; the call-site wiring is covered by
 * BackendApiClientTest/WalletEngineSessionTest.
 */
class AuthTokensTest {

    private fun newAuthTokens(): AuthTokens =
        AuthTokens(authServerClient = mockk(relaxed = true), tenantId = "default")

    /** Reaches into the private `rejections` map to seed rejection timestamps
     *  directly, since the 60s rejection window isn't injectable and real-time
     *  sleeping in a unit test would be impractical. */
    @Suppress("UNCHECKED_CAST")
    private fun rejectionsMap(tokens: AuthTokens): ConcurrentHashMap<String, CopyOnWriteArrayList<Long>> {
        val field = AuthTokens::class.java.getDeclaredField("rejections")
        field.isAccessible = true
        return field.get(tokens) as ConcurrentHashMap<String, CopyOnWriteArrayList<Long>>
    }

    @Test
    fun `single rejection does not yet trigger session-rejected callback`() {
        val tokens = newAuthTokens()
        var rejected = false
        tokens.onSessionRejected = { rejected = true }

        tokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND)

        assertFalse(rejected)
    }

    @Test
    fun `three rejections within the window trigger session-rejected callback`() {
        val tokens = newAuthTokens()
        var rejected = false
        tokens.onSessionRejected = { rejected = true }

        tokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
        assertFalse(rejected)
        tokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
        assertFalse(rejected)
        tokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND)

        assertTrue(rejected)
    }

    @Test
    fun `rejections outside the window are pruned and do not accumulate`() {
        val tokens = newAuthTokens()
        var rejected = false
        tokens.onSessionRejected = { rejected = true }

        // Seed two rejections timestamped well outside the 60s window, as if
        // they happened long enough ago to no longer count.
        val staleTimestamp = System.currentTimeMillis() - 61_000L
        rejectionsMap(tokens)[AuthTokens.TOKEN_BACKEND] =
            CopyOnWriteArrayList(listOf(staleTimestamp, staleTimestamp))

        // A single fresh rejection should prune both stale entries and land
        // at count 1 (well below REJECTION_THRESHOLD=3), not 3 - so no logout.
        tokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND)

        assertFalse(rejected)
        assertEquals(1, rejectionsMap(tokens)[AuthTokens.TOKEN_BACKEND]?.size)
    }

    @Test
    fun `rejections for different token names are tracked independently`() {
        val tokens = newAuthTokens()
        var rejected = false
        tokens.onSessionRejected = { rejected = true }

        tokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND)
        tokens.registerTokenRejection(AuthTokens.TOKEN_ANONYMOUS)
        tokens.registerTokenRejection(AuthTokens.TOKEN_BACKEND)

        // Two rejections of "backend" and one of "anonymous" - neither name
        // has reached the threshold of 3 on its own.
        assertFalse(rejected)
    }

    /**
     * Covers the gap found live in task #245: a raw "AS request failed 401 -
     * /auth/token" surfaced with no re-auth flow firing when a user tapped
     * "add credential" with an expired AS session. Unlike
     * [AuthTokens.registerTokenRejection]'s 3-strikes REST-401 case, a 401
     * straight from the AS's own token endpoint is unambiguous and must fire
     * [AuthTokens.onSessionRejected] on the very first occurrence.
     */
    @Test
    fun `401 from the AS token endpoint triggers session-rejected immediately`() = runTest {
        val client = mockk<AuthServerClient>(relaxed = true)
        coEvery { client.requestAccessToken(any(), any()) } throws
            AuthException("AS request failed: 401 — /auth/token", code = 401)
        val tokens = AuthTokens(authServerClient = client, tenantId = "default")
        var rejected = false
        tokens.onSessionRejected = { rejected = true }

        try {
            tokens.ensureBackendToken()
        } catch (e: AuthException) {
            // Expected - the original failure still propagates to the caller.
        }

        assertTrue(rejected)
    }

    @Test
    fun `401 from the AS token endpoint during forceRefreshToken also triggers session-rejected`() = runTest {
        val client = mockk<AuthServerClient>(relaxed = true)
        coEvery { client.requestAccessToken(any(), any()) } throws
            AuthException("AS request failed: 401 — /auth/token", code = 401)
        val tokens = AuthTokens(authServerClient = client, tenantId = "default")
        var rejected = false
        tokens.onSessionRejected = { rejected = true }

        try {
            tokens.forceRefreshToken(AuthTokens.TOKEN_BACKEND)
        } catch (e: AuthException) {
            // Expected.
        }

        assertTrue(rejected)
    }

    @Test
    fun `non-401 AS token failure does not trigger session-rejected`() = runTest {
        val client = mockk<AuthServerClient>(relaxed = true)
        coEvery { client.requestAccessToken(any(), any()) } throws
            AuthException("AS request failed: 500 — /auth/token", code = 500)
        val tokens = AuthTokens(authServerClient = client, tenantId = "default")
        var rejected = false
        tokens.onSessionRejected = { rejected = true }

        try {
            tokens.ensureBackendToken()
        } catch (e: AuthException) {
            // Expected.
        }

        assertFalse(rejected)
    }

    /**
     * Pins the backend token's Token Access Control string against what the
     * wallet instance lifecycle endpoints require (SID-AUTH-06,
     * go-wallet-backend#319): `l` to list instances, `w` to suspend or
     * reactivate one, `d` to revoke one or to deactivate the wallet. The SDK
     * mints `rwlid` and so needs no new token kind - this test is what keeps
     * a future narrowing of the TAC from silently breaking the Devices screen.
     */
    @Test
    fun backend_token_tac_covers_the_wallet_instance_lifecycle_endpoints() {
        val tac = AuthTokens.MANIFEST.getValue(AuthTokens.TOKEN_BACKEND).tac
        assertTrue("list instances needs 'l' in $tac", tac.contains("l"))
        assertTrue("suspend/reactivate needs 'w' in $tac", tac.contains("w"))
        assertTrue("revoke and revoke-all need 'd' in $tac", tac.contains("d"))
    }

    /**
     * A token minted before a lifecycle cut-off must not end up cached for the
     * session that replaces it (SID-AUTH-06). Here the whole request runs
     * under [AuthTokens]' own mutex, which [AuthTokens.clear] also takes, so a
     * clear issued *while the request is in flight* blocks until the store has
     * happened and then wins - the cache ends up empty, and the next caller
     * mints afresh.
     *
     * This test is what keeps a future refactor that narrows the lock across
     * the network call from silently reintroducing the race the Swift port had
     * to close with a generation counter: with the lock released across the
     * await, the clear would land first and the stale token would be cached
     * after it.
     */
    @Test
    fun clear_issued_during_an_in_flight_request_leaves_no_token_cached() = runTest {
        val client = mockk<AuthServerClient>()
        val tokens = AuthTokens(authServerClient = client, tenantId = "default")
        val scope = this
        var minted = 0
        var clearing: Job? = null
        coEvery { client.requestAccessToken(any(), any()) } coAnswers {
            minted++
            // A concurrent re-login clearing the cache while this request is
            // in flight. It blocks on the same mutex until this one completes.
            if (clearing == null) clearing = scope.launch { tokens.clear() }
            yield()
            unexpiredToken()
        }

        tokens.ensureBackendToken()
        clearing!!.join()
        tokens.ensureBackendToken()

        assertEquals(
            "the token minted before the clear was not served to the session that replaced it",
            2,
            minted,
        )
    }

    /** header.{exp,aud,tenant_id,tac}.sig - enough for AccessToken to parse. */
    private fun unexpiredToken(): AccessToken {
        val exp = System.currentTimeMillis() / 1000 + 3600
        val payload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            """{"exp":$exp,"aud":"wallet-backend","tenant_id":"default","tac":"rwlid"}"""
                .toByteArray(Charsets.UTF_8)
        )
        return AccessToken("eyJhbGciOiJub25lIn0.$payload.sig")
    }
}
