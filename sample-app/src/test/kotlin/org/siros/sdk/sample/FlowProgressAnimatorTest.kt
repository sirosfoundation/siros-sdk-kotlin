package org.siros.sdk.sample

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the root cause of the "progress bar freezes during compute" bug:
 * [FlowProgressAnimator.displayProgress] must keep visibly advancing while
 * waiting on a long-running step (e.g. native ZK proof generation) with no
 * intermediate real progress signal, without ever lying about completion by
 * crossing into the next step's territory, and without ever regressing.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class FlowProgressAnimatorTest {
    private val dispatcher = StandardTestDispatcher()

    @Test
    fun onRealProgress_snaps_display_value_up_immediately() = runTest(dispatcher) {
        val animator = FlowProgressAnimator()
        animator.onRealProgress(0.5f)
        assertEquals(0.5f, animator.displayProgress.value)
    }

    @Test
    fun onRealProgress_ignores_null_and_non_advancing_values() = runTest(dispatcher) {
        val animator = FlowProgressAnimator()
        animator.onRealProgress(0.5f)
        animator.onRealProgress(null)
        animator.onRealProgress(0.3f) // a step "retried" out of order must not move the bar backward
        assertEquals(0.5f, animator.displayProgress.value)
    }

    @Test
    fun run_creeps_display_value_forward_during_a_stalled_step_but_caps_below_next_step() = runTest(dispatcher) {
        val creepCap = 0.08f
        val animator = FlowProgressAnimator(tickIntervalMs = 150L, creepCap = creepCap, creepFactor = 0.12f)
        val job = launch { animator.run() }

        animator.onRealProgress(0.5f)
        assertEquals(0.5f, animator.displayProgress.value)

        // Simulate a long-running step (e.g. ZK proof compute) with zero
        // intermediate real progress events: the ticker alone should keep
        // nudging the displayed value forward well past the freeze point...
        advanceTimeBy(5_000L)
        val creeped = animator.displayProgress.value
        assertTrue("expected the display value to creep forward while stalled, was $creeped", creeped > 0.5f)

        // ...but never far enough to look like the next step already
        // started - it must stay strictly under the real-value-plus-cap
        // ceiling even after a long stall.
        assertTrue("expected creep to stay capped below ${0.5f + creepCap}, was $creeped", creeped < 0.5f + creepCap)

        job.cancel()
    }

    @Test
    fun run_never_lets_display_value_regress_across_repeated_ticks() = runTest(dispatcher) {
        val animator = FlowProgressAnimator()
        val job = launch { animator.run() }

        animator.onRealProgress(0.2f)
        var previous = animator.displayProgress.value
        repeat(20) {
            advanceTimeBy(150L)
            val current = animator.displayProgress.value
            assertTrue("progress must never regress: $previous -> $current", current >= previous)
            previous = current
        }

        job.cancel()
    }

    @Test
    fun onRealProgress_arriving_mid_creep_raises_the_ceiling_and_keeps_advancing() = runTest(dispatcher) {
        val animator = FlowProgressAnimator(tickIntervalMs = 150L, creepCap = 0.08f, creepFactor = 0.12f)
        val job = launch { animator.run() }

        animator.onRealProgress(0.2f)
        advanceTimeBy(2_000L) // let it creep toward the 0.2f + 0.08f ceiling
        val creeped = animator.displayProgress.value
        assertTrue(creeped > 0.2f)

        // A genuine new step event arrives further ahead than the creep
        // reached - display value must snap to it immediately, not wait for
        // the next tick to catch up.
        animator.onRealProgress(0.6f)
        assertEquals(0.6f, animator.displayProgress.value)

        job.cancel()
    }
}
