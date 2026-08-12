package org.siros.sdk.auth

import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
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
}
