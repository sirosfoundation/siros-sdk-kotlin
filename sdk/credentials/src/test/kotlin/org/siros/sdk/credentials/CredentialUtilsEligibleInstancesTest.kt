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

    @Test
    fun consumeNonZkp_withResolverReturningTrue_keepsUsedInstanceEligible() {
        // A real ZK presentation (per the caller's own resolver - see
        // eligibleInstances' isZkPresentation doc comment) is never
        // consumed under CONSUME_NON_ZKP, even if it was already presented.
        val used = credential(id = 1L, instanceId = 0, format = "mso_mdoc")
        val history = listOf(presentation(1L))

        val result = CredentialUtils.eligibleInstances(
            listOf(used),
            CredentialConsumptionPolicy.CONSUME_NON_ZKP,
            history,
            isZkPresentation = { true },
        )

        assertEquals(listOf(used), result)
    }

    @Test
    fun consumeNonZkp_withResolverReturningFalse_excludesUsedInstance() {
        // A raw disclosure (per the caller's resolver) is consumed under
        // CONSUME_NON_ZKP just like under CONSUME_ALL.
        val used = credential(id = 1L, instanceId = 0, format = "mso_mdoc")
        val unused = credential(id = 2L, instanceId = 1, format = "mso_mdoc")
        val history = listOf(presentation(1L))

        val result = CredentialUtils.eligibleInstances(
            listOf(used, unused),
            CredentialConsumptionPolicy.CONSUME_NON_ZKP,
            history,
            isZkPresentation = { false },
        )

        assertEquals(listOf(unused), result)
    }

    @Test
    fun consumeNonZkp_withResolver_isEvaluatedPerInstance() {
        // The resolver is evaluated per-instance, not once for the whole
        // batch - a zk instance and a raw instance already presented in the
        // same batch must be judged independently of each other.
        val zkUsed = credential(id = 1L, instanceId = 0, format = "mso_mdoc")
        val rawUsed = credential(id = 2L, instanceId = 1, format = "mso_mdoc")
        val history = listOf(presentation(1L), presentation(2L))

        val result = CredentialUtils.eligibleInstances(
            listOf(zkUsed, rawUsed),
            CredentialConsumptionPolicy.CONSUME_NON_ZKP,
            history,
            isZkPresentation = { it.id == zkUsed.id },
        )

        assertEquals(listOf(zkUsed), result)
    }
}
