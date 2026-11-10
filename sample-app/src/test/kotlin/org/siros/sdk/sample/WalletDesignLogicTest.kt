// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.CredentialInstance
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.CredentialWithInstances
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.interop.CredentialStatus
import java.util.Locale
import java.util.TimeZone

/**
 * The decisions behind the redesigned screens that are not layout: which
 * credentials count as needing attention (Home's banner and the Manage
 * credentials filter), what the two search fields match, and which day
 * heading a history record falls under.
 */
class WalletDesignLogicTest {

    private fun entry(id: Long, name: String? = null, vararg instances: CredentialInstance) = CredentialWithInstances(
        credential = StoredCredential(
            id = id,
            format = "dc+sd-jwt",
            raw = "",
            metadata = name?.let { CredentialMetadata(name = it) },
            batchId = id,
            instanceId = 0,
        ),
        instances = instances.toList(),
    )

    private val unused = CredentialInstance(instanceId = 0, sigCount = 0)
    private val used = CredentialInstance(instanceId = 1, sigCount = 1)
    private val keyless = CredentialInstance(instanceId = 2, sigCount = 0, hasKey = false)

    @Test
    fun aUsableCredentialNeedsNoAttention() {
        assertFalse(entry(1, "PID", unused).needsAttention(emptyMap()))
        assertFalse(entry(1, "PID", unused).needsAttention(mapOf(1L to CredentialStatus.VALID)))
    }

    @Test
    fun aStatusThatStopsUseNeedsAttention() {
        for (status in listOf(CredentialStatus.EXPIRED, CredentialStatus.REVOKED, CredentialStatus.SUSPENDED)) {
            assertTrue("$status", entry(1, "PID", unused).needsAttention(mapOf(1L to status)))
        }
        // Another credential's status says nothing about this one.
        assertFalse(entry(1, "PID", unused).needsAttention(mapOf(2L to CredentialStatus.EXPIRED)))
    }

    @Test
    fun aCredentialWithNoCopyLeftNeedsAttention() {
        assertTrue(entry(1, "PID", used).needsAttention(emptyMap()))
        assertTrue(entry(1, "PID", used, keyless).needsAttention(emptyMap()))
        assertFalse(entry(1, "PID", used, unused).needsAttention(emptyMap()))
    }

    @Test
    fun exhaustionIsNotCountedBeforeTheKeyInventoryIsKnown() {
        // Every copy looks keyless until the signer's keys have been read.
        assertFalse(entry(1, "PID", keyless).needsAttention(emptyMap(), countExhausted = false))
        // A status from the SDK counts regardless.
        assertTrue(entry(1, "PID", keyless).needsAttention(mapOf(1L to CredentialStatus.EXPIRED), countExhausted = false))
    }

    @Test
    fun aCredentialPastItsOwnExpiryNeedsAttentionBeforeTheSdkHasEvaluatedIt() {
        val now = 2_000_000_000_000L
        fun expiring(expSeconds: Long?) = CredentialWithInstances(
            StoredCredential(id = 1, format = "dc+sd-jwt", raw = "", expiresAt = expSeconds, batchId = 1, instanceId = 0),
            listOf(unused),
        )
        assertTrue(expiring(now / 1000 - 1).needsAttention(emptyMap(), nowMillis = now))
        assertFalse(expiring(now / 1000 + 60).needsAttention(emptyMap(), nowMillis = now))
        assertFalse(expiring(null).needsAttention(emptyMap(), nowMillis = now))
        // Once the SDK has an answer, that answer stands.
        assertFalse(expiring(now / 1000 - 1).needsAttention(mapOf(1L to CredentialStatus.VALID), nowMillis = now))
    }

    @Test
    fun credentialSearchMatchesWhatTheCardShows() {
        // No display metadata: the card resolves a title of its own, and that title is what a user types.
        val bare = StoredCredential(
            id = 3, format = "dc+sd-jwt", raw = "", credentialConfigurationId = "diploma", batchId = 3, instanceId = 0,
        )
        val meta = org.siros.sdk.credentials.CredentialUtils.buildFallbackMetadata(bare)
        val labels = cardLabels(meta?.name, bare.format, meta?.vct ?: meta?.doctype)
        assertTrue(bare.matchesSearch(labels.title))
        labels.typeBadge?.let { assertTrue(bare.matchesSearch(it)) }
        assertFalse(bare.matchesSearch("passport"))
    }

    @Test
    fun credentialSearchMatchesTheListedName() {
        val pid = entry(1, "Person Identification Data").credential
        assertTrue(pid.matchesSearch(""))
        assertTrue(pid.matchesSearch("   "))
        assertTrue(pid.matchesSearch("identif"))
        assertTrue(pid.matchesSearch(" PERSON "))
        assertFalse(pid.matchesSearch("diploma"))
        // Without display metadata a credential is listed under its format.
        assertTrue(entry(2).credential.matchesSearch("sd-jwt"))
    }

    private fun record(verifier: String?, names: List<String> = emptyList(), claims: List<String> = emptyList()) =
        PresentationRecord(
            id = 1,
            flowId = "f",
            verifierName = verifier,
            credentialIds = listOf(1),
            credentialNames = names,
            requestedClaims = claims,
            timestamp = 0,
        )

    @Test
    fun historySearchCoversVerifierCredentialsAndClaims() {
        val r = record("Example Bank", listOf("Photo ID"), listOf("family_name"))
        assertTrue(matchesHistoryQuery(r, ""))
        assertTrue(matchesHistoryQuery(r, "bank"))
        assertTrue(matchesHistoryQuery(r, "photo"))
        assertTrue(matchesHistoryQuery(r, "family"))
        assertFalse(matchesHistoryQuery(r, "library"))
        assertFalse(matchesHistoryQuery(record(null), "bank"))
    }

    @Test
    fun historyDayHeadingsFollowTheLocalCalendarDay() {
        val zone = TimeZone.getTimeZone("Europe/Stockholm")
        val day = 86_400_000L
        // 2026-06-04 12:00 UTC = 14:00 in Stockholm.
        val now = 1_780_574_400_000L
        fun label(t: Long) = historyDayLabel(t, now, "Today", "Yesterday", zone, Locale.ENGLISH)
        assertEquals("Today", label(now))
        // 00:30 local the same day is 22:30 UTC the day before: still today.
        assertEquals("Today", label(now - 13 * 3_600_000L - 30 * 60_000L))
        // 23:30 local the day before.
        assertEquals("Yesterday", label(now - 14 * 3_600_000L - 30 * 60_000L))
        assertEquals("Yesterday", label(now - day))
        assertEquals("1 June 2026", label(now - 3 * day))
    }
}
