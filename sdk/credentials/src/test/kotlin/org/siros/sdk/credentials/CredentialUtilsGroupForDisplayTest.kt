// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialUtilsGroupForDisplayTest {

    private fun credential(
        id: Long,
        batchId: Long = id,
        instanceId: Int = 0,
        issuedAt: Long? = null,
        kid: String? = null,
    ) = StoredCredential(
        id = id,
        format = "vc+sd-jwt",
        raw = "raw-$id",
        batchId = batchId,
        instanceId = instanceId,
        issuedAt = issuedAt,
        kid = kid,
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

        val result = CredentialUtils.groupForDisplay(listOf(cred), emptyList(), setOf("irrelevant-kid"))

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

        val result = CredentialUtils.groupForDisplay(credentials, emptyList(), setOf("irrelevant-kid"))

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

        val result = CredentialUtils.groupForDisplay(credentials, history, setOf("irrelevant-kid"))

        val instances = result.first().instances.associateBy { it.instanceId }
        assertEquals(0, instances.getValue(0).sigCount)
        assertEquals(1, instances.getValue(1).sigCount)
        assertEquals(2, instances.getValue(2).sigCount)
    }

    @Test
    fun hasKeyReflectsWhetherEachInstancesBoundKeyIsAvailable() {
        // An instance whose kid isn't in availableKeyIds - the "shadow"
        // state trigger the UI derives via sigCount == 0 && hasKey (see
        // CredentialInstance.hasKey's doc comment) - a lost key must read
        // the same as an already-consumed one, not as still-usable.
        val batchId = 250L
        val credentials = listOf(
            credential(id = 13L, batchId = batchId, instanceId = 0, kid = "kid-13"),
            credential(id = 14L, batchId = batchId, instanceId = 1, kid = "kid-14"),
        )

        val result = CredentialUtils.groupForDisplay(credentials, emptyList(), setOf("kid-13"))

        val instances = result.first().instances.associateBy { it.instanceId }
        assertEquals(true, instances.getValue(0).hasKey)
        assertEquals(false, instances.getValue(1).hasKey)
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

        val result = CredentialUtils.groupForDisplay(credentials, emptyList(), setOf("irrelevant-kid"))

        assertTrue(result.isEmpty())
    }

    @Test
    fun mixOfStandaloneAndBatchedCredentialsSortedByIssuedAtDescending() {
        val batchId = 400L
        val older = credential(id = 30L, issuedAt = 100L)
        val newerBatchVisible = credential(id = 31L, batchId = batchId, instanceId = 0, issuedAt = 200L)
        val newerBatchSibling = credential(id = 32L, batchId = batchId, instanceId = 1, issuedAt = 200L)

        val result = CredentialUtils.groupForDisplay(listOf(older, newerBatchVisible, newerBatchSibling), emptyList(), setOf("irrelevant-kid"))

        assertEquals(2, result.size)
        assertEquals(31L, result.first().credential.id)
        assertEquals(30L, result[1].credential.id)
    }

    @Test
    fun groupIntoFamilies_representativeIsTheInstanceZeroMember() {
        val batchId = 500L
        val credentials = listOf(
            credential(id = 41L, batchId = batchId, instanceId = 0),
            credential(id = 42L, batchId = batchId, instanceId = 1),
            credential(id = 43L, batchId = batchId, instanceId = 2),
        )

        val result = CredentialUtils.groupIntoFamilies(credentials)

        assertEquals(1, result.size)
        assertEquals(41L, result.first().representative.id)
        assertEquals(3, result.first().instances.size)
    }

    @Test
    fun groupIntoFamilies_skipsABatchMissingItsInstanceZeroMember() {
        // Matches groupForDisplay's convention exactly (see
        // batchMissingItsInstanceZeroCredentialIsDroppedEntirely above) -
        // the two grouping functions must never disagree about which
        // batches are representable, so this must skip rather than fall
        // back to an arbitrary member.
        val batchId = 600L
        val credentials = listOf(
            credential(id = 51L, batchId = batchId, instanceId = 1),
            credential(id = 52L, batchId = batchId, instanceId = 2),
        )

        val result = CredentialUtils.groupIntoFamilies(credentials)

        assertTrue(result.isEmpty())
    }

    @Test
    fun groupIntoFamilies_standaloneCredentialBecomesItsOwnOneInstanceFamily() {
        val cred = credential(id = 61L)

        val result = CredentialUtils.groupIntoFamilies(listOf(cred))

        assertEquals(1, result.size)
        assertEquals(cred, result.first().representative)
        assertEquals(listOf(cred), result.first().instances)
    }
}
