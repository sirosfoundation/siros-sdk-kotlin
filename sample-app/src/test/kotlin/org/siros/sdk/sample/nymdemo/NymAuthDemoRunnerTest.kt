// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.nymdemo

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NymAuthDemoRunnerTest {
    private val runner = NymAuthDemoRunner(ByteArray(32) { it.toByte() })
    private val base = NymAuthDemoRunner.Params(
        birthDate = "1990-05-17",
        ge = "1900-01-01",
        le = "2008-10-14",
        verifierId = "verifier.example.org",
    )

    @Test
    fun `a satisfiable request is presented and the pseudonym matches an independent recompute`() = runTest {
        val outcome = runner.run(base)
        val presented = outcome as NymAuthDemoRunner.Outcome.Presented
        assertTrue(presented.pseudonymMatches)
        assertEquals("true", presented.ageResult)
        assertEquals(setOf("nym", "age"), presented.decodedHandles.toSet())
    }

    @Test
    fun `the pseudonym differs per verifier id`() = runTest {
        val a = runner.run(base) as NymAuthDemoRunner.Outcome.Presented
        val b = runner.run(base.copy(verifierId = "other.example.org")) as NymAuthDemoRunner.Outcome.Presented
        assertTrue(a.pseudonymHex != b.pseudonymHex)
    }

    @Test
    fun `the pseudonym is stable across presentations`() = runTest {
        val a = runner.run(base) as NymAuthDemoRunner.Outcome.Presented
        val b = runner.run(base) as NymAuthDemoRunner.Outcome.Presented
        assertEquals(a.pseudonymHex, b.pseudonymHex)
    }

    @Test
    fun `a foreign psc is refused`() = runTest {
        assertEquals(NymAuthDemoRunner.Outcome.Refused, runner.run(base.copy(foreignPsc = true)))
    }

    @Test
    fun `a false age predicate is refused`() = runTest {
        assertEquals(NymAuthDemoRunner.Outcome.Refused, runner.run(base.copy(birthDate = "2015-01-01")))
    }

    @Test
    fun `an unsatisfiable age span is refused`() = runTest {
        assertEquals(NymAuthDemoRunner.Outcome.Refused, runner.run(base.copy(ge = "2000-01-01", le = "2000-06-01")))
    }
}
