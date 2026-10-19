package org.siros.sdk.sample

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.siros.sdk.credentials.ConsentEntry
import org.siros.sdk.credentials.ConsentItem
import org.siros.sdk.credentials.ConsentVerifier
import org.siros.sdk.credentials.CredentialRef
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.credentials.PseudonymScope

@OptIn(ExperimentalCoroutinesApi::class)
class PresentationConsentGateTest {
    private fun request() = PresentationConsentRequest(
        ConsentVerifier("Shop", verifierId = "shop.example"),
        listOf(ConsentEntry(CredentialRef("Nym", null), listOf(ConsentItem.Pseudonym("known-offender-matching-ssc", PseudonymScope.PER_VERIFIER, true, false, "shop.example", null)))),
        requestSigned = true,
        locale = "en",
    )

    @Test
    fun `the gate shows the SDK's request and returns the user's answer`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
        assertNull(gate.pending.value)
        val result = async { gate.handler.confirm(request()) }
        advanceUntilIdle()
        assertEquals("Shop", gate.pending.value?.verifier?.label)
        gate.answer(true)
        assertEquals(true, result.await())
        assertNull(gate.pending.value)
    }

    @Test
    fun `a decline is passed on, and an answer with nothing waiting is ignored`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
        gate.answer(true)
        val result = async { gate.handler.confirm(request()) }
        advanceUntilIdle()
        gate.answer(false)
        assertEquals(false, result.await())
    }

    @Test
    fun `when the SDK stops waiting the dialog goes away`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
        val result = async { gate.handler.confirm(request()) }
        advanceUntilIdle()
        assertNotNull(gate.pending.value)
        result.cancel()
        advanceUntilIdle()
        assertNull(gate.pending.value)
    }
}
