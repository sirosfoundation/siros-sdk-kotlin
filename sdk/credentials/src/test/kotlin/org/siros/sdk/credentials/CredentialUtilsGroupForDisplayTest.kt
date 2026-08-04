// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialUtilsGroupForDisplayTest {

    private fun credential(id: Long, batchId: Long = id, instanceId: Int = 0, issuedAt: Long? = null) =
        StoredCredential(
            id = id,
            format = "vc+sd-jwt",
            raw = "raw-$id",
            batchId = batchId,
            instanceId = instanceId,
            issuedAt = issuedAt,
        )

    private fun presentation(vararg credentialIds: Long) = PresentationRecord(
        id = credentialIds.sum() + 1000L,
        flowId = "flow",
        credentialIds = credentialIds.toList(),
        timestamp = 0L,
    )

    @Test
    fun standaloneCredentialBecomesItsOwnOneInstanceFamily() {
        // A batch of one - every issuance response is its own batch, matching
        // wallet-frontend exactly (no separate "no batch" concept, see
        // StoredCredential.batchId's KDoc).
        val cred = credential(id = 1L)

        val result = CredentialUtils.groupForDisplay(listOf(cred), emptyList())

        assertEquals(1, result.size)
        assertEquals(cred, result.first().credential)
        assertEquals(listOf(CredentialInstance(0, 0)), result.first().instances)
    }

    @Test
    fun batchOnlyShowsTheInstanceZeroCredentialAsTheVisibleEntry() {
        val batchId = 100L
        val credentials = listOf(
            credential(id = 1L, batchId = batchId, instanceId = 0),
            credential(id = 2L, batchId = batchId, instanceId = 1),
            credential(id = 3L, batchId = batchId, instanceId = 2),
        )

        val result = CredentialUtils.groupForDisplay(credentials, emptyList())

        assertEquals(1, result.size)
        assertEquals(1L, result.first().credential.id)
        assertEquals(3, result.first().instances.size)
    }

    @Test
    fun sigCountReflectsHowManyPresentationsUsedEachInstance() {
        val batchId = 200L
        val credentials = listOf(
            credential(id = 10L, batchId = batchId, instanceId = 0),
            credential(id = 11L, batchId = batchId, instanceId = 1),
            credential(id = 12L, batchId = batchId, instanceId = 2),
        )
        // instance 1 used once, instance 2 used twice, instance 0 never used
        val history = listOf(presentation(11L), presentation(12L), presentation(12L))

        val result = CredentialUtils.groupForDisplay(credentials, history)

        val instances = result.first().instances.associateBy { it.instanceId }
        assertEquals(0, instances.getValue(0).sigCount)
        assertEquals(1, instances.getValue(1).sigCount)
        assertEquals(2, instances.getValue(2).sigCount)
    }

    @Test
    fun batchMissingItsInstanceZeroCredentialIsDroppedEntirely() {
        // Simulates instance 0 having been deleted independently of its siblings -
        // there is no sane "visible" card left to represent the family.
        val batchId = 300L
        val credentials = listOf(
            credential(id = 21L, batchId = batchId, instanceId = 1),
            credential(id = 22L, batchId = batchId, instanceId = 2),
        )

        val result = CredentialUtils.groupForDisplay(credentials, emptyList())

        assertTrue(result.isEmpty())
    }

    @Test
    fun mixOfStandaloneAndBatchedCredentialsSortedByIssuedAtDescending() {
        val batchId = 400L
        val older = credential(id = 30L, issuedAt = 100L)
        val newerBatchVisible = credential(id = 31L, batchId = batchId, instanceId = 0, issuedAt = 200L)
        val newerBatchSibling = credential(id = 32L, batchId = batchId, instanceId = 1, issuedAt = 200L)

        val result = CredentialUtils.groupForDisplay(listOf(older, newerBatchVisible, newerBatchSibling), emptyList())

        assertEquals(2, result.size)
        assertEquals(31L, result.first().credential.id)
        assertEquals(30L, result[1].credential.id)
    }
}
