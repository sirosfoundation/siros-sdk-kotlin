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
        val shown = request()
        val result = async { gate.handler.confirm(shown) }
        advanceUntilIdle()
        assertEquals("Shop", gate.pending.value?.verifier?.label)
        gate.answer(shown, true)
        assertEquals(true, result.await())
        assertNull(gate.pending.value)
    }

    @Test
    fun `a decline is passed on, and an answer with nothing waiting is ignored`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
        gate.answer(request(), true)
        val shown = request()
        val result = async { gate.handler.confirm(shown) }
        advanceUntilIdle()
        gate.answer(shown, false)
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

    @Test
    fun `an overlapping request waits its turn, and a stale dialog cannot approve it`() = runTest(StandardTestDispatcher()) {
        val gate = PresentationConsentGate()
        val a = request()
        val b = request()
        val first = async { gate.handler.confirm(a) }
        val second = async { gate.handler.confirm(b) }
        advanceUntilIdle()
        // Only A is on screen; B has not replaced it.
        assertEquals(true, gate.pending.value === a)
        // An answer naming B (not on screen) is ignored.
        gate.answer(b, true)
        advanceUntilIdle()
        assertEquals(true, gate.pending.value === a)
        gate.answer(a, false)
        assertEquals(false, first.await())
        advanceUntilIdle()
        // Now B is on screen, and A's late callback cannot approve it.
        assertEquals(true, gate.pending.value === b)
        gate.answer(a, true)
        advanceUntilIdle()
        assertEquals(true, gate.pending.value === b)
        gate.answer(b, true)
        assertEquals(true, second.await())
    }
}
