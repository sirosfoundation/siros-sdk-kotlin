// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore

import org.junit.Assert.assertEquals
import org.junit.Test

class PlayIntegrityProviderTest {

    /**
     * Independently computed (Python `hashlib.sha256` + `base64.urlsafe_b64encode`,
     * not derived from this code) against go-wallet-backend's expected nonce
     * contract: base64url-no-pad(SHA-256(challenge)).
     */
    @Test
    fun nonceForChallenge_matchesHandVerifiedTestVector() {
        val nonce = PlayIntegrityProvider.nonceForChallenge("test-challenge-123")

        assertEquals("68glHNvF_WSxEI_qy7eHuUfScButHoTiv6S-te5-EnY", nonce)
    }

    @Test
    fun nonceForChallenge_isDeterministic() {
        val first = PlayIntegrityProvider.nonceForChallenge("some-challenge")
        val second = PlayIntegrityProvider.nonceForChallenge("some-challenge")

        assertEquals(first, second)
    }

    @Test
    fun nonceForChallenge_producesNoPaddingAndNoPlusOrSlash() {
        // "challenge-0" is specifically chosen: its raw SHA-256 digest's
        // standard base64 encoding contains BOTH '+' and '/' (and needs
        // '=' padding) - "BBFcs+FRXe8fJtuGr/i/YrM+VoFbOLQqJax5gkt7TOE=" -
        // so this genuinely exercises the base64url-no-pad requirement
        // rather than trivially passing for a string whose digest happens
        // not to need those characters either way.
        val nonce = PlayIntegrityProvider.nonceForChallenge("challenge-0")

        assertEquals("BBFcs-FRXe8fJtuGr_i_YrM-VoFbOLQqJax5gkt7TOE", nonce)
        assertEquals(false, nonce.contains("+"))
        assertEquals(false, nonce.contains("/"))
        assertEquals(false, nonce.contains("="))
    }

    @Test
    fun nonceForChallenge_differsForDifferentChallenges() {
        val a = PlayIntegrityProvider.nonceForChallenge("challenge-a")
        val b = PlayIntegrityProvider.nonceForChallenge("challenge-b")

        assert(a != b)
    }
}
