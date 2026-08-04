// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Test

class CredentialUtilsEligibleInstancesTest {

    private fun credential(id: Long, batchId: Long = 1L, instanceId: Int = 0, format: String = "vc+sd-jwt") =
        StoredCredential(
            id = id,
            format = format,
            raw = "raw-$id",
            batchId = batchId,
            instanceId = instanceId,
        )

    private fun presentation(vararg credentialIds: Long) = PresentationRecord(
        id = credentialIds.sum() + 1000L,
        flowId = "flow",
        credentialIds = credentialIds.toList(),
        timestamp = 0L,
    )

    @Test
    fun neverConsume_returnsEveryInstanceRegardlessOfHistory() {
        val instances = listOf(credential(id = 1L, instanceId = 0), credential(id = 2L, instanceId = 1))
        val history = listOf(presentation(1L), presentation(2L))

        val result = CredentialUtils.eligibleInstances(instances, CredentialConsumptionPolicy.NEVER_CONSUME, history)

        assertEquals(instances, result)
    }

    @Test
    fun consumeAll_excludesInstancesAlreadyPresented() {
        val used = credential(id = 1L, instanceId = 0)
        val unused = credential(id = 2L, instanceId = 1)
        val history = listOf(presentation(1L))

        val result = CredentialUtils.eligibleInstances(listOf(used, unused), CredentialConsumptionPolicy.CONSUME_ALL, history)

        assertEquals(listOf(unused), result)
    }

    @Test
    fun consumeAll_withNoHistory_everyInstanceIsEligible() {
        val instances = listOf(credential(id = 1L, instanceId = 0), credential(id = 2L, instanceId = 1))

        val result = CredentialUtils.eligibleInstances(instances, CredentialConsumptionPolicy.CONSUME_ALL, emptyList())

        assertEquals(instances, result)
    }

    @Test
    fun consumeAll_allInstancesUsed_returnsEmptyList() {
        val a = credential(id = 1L, instanceId = 0)
        val b = credential(id = 2L, instanceId = 1)
        val history = listOf(presentation(1L), presentation(2L))

        val result = CredentialUtils.eligibleInstances(listOf(a, b), CredentialConsumptionPolicy.CONSUME_ALL, history)

        assertEquals(emptyList<StoredCredential>(), result)
    }

    @Test
    fun consumeNonZkp_behavesIdenticallyToConsumeAll_sinceNoZkpFormatExistsYet() {
        // Every format this SDK supports today discloses via salted-hash
        // digests, not a real ZKP proof - see CredentialUtils.isZkpFormat's
        // doc comment. This test pins that current equivalence so a future
        // change introducing a real ZKP format is forced to reconsider it.
        val used = credential(id = 1L, instanceId = 0, format = "mso_mdoc")
        val unused = credential(id = 2L, instanceId = 1, format = "mso_mdoc")
        val history = listOf(presentation(1L))

        val result = CredentialUtils.eligibleInstances(listOf(used, unused), CredentialConsumptionPolicy.CONSUME_NON_ZKP, history)

        assertEquals(listOf(unused), result)
    }

    @Test
    fun sigCountOfTwoOrMore_stillCountsAsUsed_notJustExactlyOne() {
        val overused = credential(id = 1L, instanceId = 0)
        val history = listOf(presentation(1L), presentation(1L), presentation(1L))

        val result = CredentialUtils.eligibleInstances(listOf(overused), CredentialConsumptionPolicy.CONSUME_ALL, history)

        assertEquals(emptyList<StoredCredential>(), result)
    }
}
