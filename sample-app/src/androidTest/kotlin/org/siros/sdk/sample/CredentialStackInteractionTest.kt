// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.siros.sdk.credentials.CredentialInstance
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.CredentialWithInstances
import org.siros.sdk.credentials.StoredCredential

/**
 * Drives [CredentialStack] with real touch input on-device - taps and drags,
 * not a simulated callback invocation - because the whole point of this
 * component is that tap, long-press and drag resolve correctly against each
 * other, and that is exactly the kind of thing a plain unit test calling the
 * composable's lambdas directly cannot catch. Two real bugs in this
 * interaction were found only this way, neither visible from reading the
 * code in isolation:
 *
 * - The very first version layered a `Modifier.draggable` under
 *   [CredentialCard]'s own `combinedClickable` on a separate node. It
 *   compiled cleanly and looked correct in review, and silently dropped
 *   every tap - two independent gesture detectors on nodes at different
 *   depths both reach for the same down event, and whichever claims it
 *   first starves the other.
 * - The first version of the hand-written replacement,
 *   [detectCredentialStackGestures], checked the long-press timeout only
 *   when a pointer event arrived - and a finger held perfectly still can
 *   mean the OS never delivers one between the down and the eventual up, so
 *   every still, held press read as a plain tap regardless of how long it
 *   was held. Racing the wait itself against the deadline, rather than
 *   reacting to events after the fact, is what actually fixed it.
 *
 * Renders [CredentialStack] directly, with no wallet session or SDK backing
 * it - it is a pure composable over a plain credential list, so nothing here
 * needs a login.
 */
@RunWith(AndroidJUnit4::class)
class CredentialStackInteractionTest {

    @get:Rule
    val composeRule = createComposeRule()

    private fun credential(batchId: Long, name: String) = CredentialWithInstances(
        credential = StoredCredential(
            id = batchId,
            format = "dc+sd-jwt",
            raw = "",
            metadata = CredentialMetadata(name = name, backgroundColor = "#224488", textColor = "#FFFFFF"),
            batchId = batchId,
            instanceId = 0,
        ),
        instances = listOf(CredentialInstance(instanceId = 0, sigCount = 0)),
    )

    /** batchId 1, 2, 3 in that order; 3 starts frontmost (last in the deck). */
    private val entries = listOf(
        credential(1L, "Alpha"),
        credential(2L, "Bravo"),
        credential(3L, "Charlie"),
    )

    private class RecordedClicks {
        val opened = mutableListOf<Long>()
        val longPressed = mutableListOf<Long>()
    }

    private fun setContent(recorded: RecordedClicks) {
        composeRule.setContent {
            CredentialStack(
                entries = entries,
                onCredentialClick = { recorded.opened += it.batchId },
                onCredentialLongClick = { recorded.longPressed += it.batchId },
                onRenewCredential = {},
                onDeleteCredential = {},
            )
        }
    }

    @Test
    fun tapping_the_frontmost_card_opens_it_directly() {
        val recorded = RecordedClicks()
        setContent(recorded)

        composeRule.onNodeWithTag(credentialStackCardTestTag(3L)).performClick()

        assertEquals(listOf(3L), recorded.opened)
    }

    @Test
    fun tapping_a_buried_card_brings_it_forward_instead_of_opening_it() {
        val recorded = RecordedClicks()
        setContent(recorded)

        // 1 starts at the back of the deck, not the front.
        composeRule.onNodeWithTag(credentialStackCardTestTag(1L)).performClick()
        composeRule.waitForIdle()

        assertEquals("a tap on a buried card must not open it", emptyList<Long>(), recorded.opened)

        // Tapping the SAME card again now opens it - proof the first tap
        // actually moved it to the front rather than doing nothing.
        composeRule.onNodeWithTag(credentialStackCardTestTag(1L)).performClick()

        assertEquals(listOf(1L), recorded.opened)
    }

    @Test
    fun a_long_drag_pulls_a_buried_card_to_the_front() {
        val recorded = RecordedClicks()
        setContent(recorded)

        val node = composeRule.onNodeWithTag(credentialStackCardTestTag(2L))
        node.performTouchInput {
            // Comfortably past CREDENTIAL_PULL_THRESHOLD_FRACTION (0.18): a
            // quarter of the card's own height, so this is unambiguous
            // regardless of exactly how touch slop and the threshold trade
            // off on the test device.
            val distance = Offset(0f, visibleSize.height * 0.30f)
            swipeDown(startY = center.y, endY = center.y + distance.y, durationMillis = 200)
        }
        composeRule.waitForIdle()

        // The pull committed: 2 is now frontmost, so a plain tap opens it
        // without a second tap being needed.
        node.performClick()
        assertEquals(listOf(2L), recorded.opened)
    }

    @Test
    fun a_short_drag_springs_back_without_reordering_the_deck() {
        val recorded = RecordedClicks()
        setContent(recorded)

        val node = composeRule.onNodeWithTag(credentialStackCardTestTag(1L))
        node.performTouchInput {
            // Past touch slop (so it registers as a drag, not a tap) but
            // well under CREDENTIAL_PULL_THRESHOLD_FRACTION (0.18) - a
            // twentieth of the card's height.
            val distance = visibleSize.height * 0.05f
            swipeDown(startY = center.y, endY = center.y + distance, durationMillis = 200)
        }
        composeRule.waitForIdle()

        // The drag did not reach the threshold, so the deck's front is
        // unchanged: 3 still opens on the first tap...
        composeRule.onNodeWithTag(credentialStackCardTestTag(3L)).performClick()
        assertEquals(listOf(3L), recorded.opened)

        // ...and 1, which is what was actually dragged, is still buried:
        // one tap on it only brings it forward, exactly as if the drag had
        // never happened.
        composeRule.onNodeWithTag(credentialStackCardTestTag(1L)).performClick()
        assertEquals("the short drag must not have brought 1 to the front", listOf(3L), recorded.opened)
    }

    @Test
    fun a_long_press_reports_long_click_without_opening_or_reordering() {
        val recorded = RecordedClicks()
        setContent(recorded)

        val node = composeRule.onNodeWithTag(credentialStackCardTestTag(1L))
        node.performTouchInput { down(center) }
        // detectCredentialStackGestures races the platform's real long-press
        // timeout against the next pointer event, specifically so a finger
        // held still - no intervening event at all - still resolves to a
        // long-press rather than reading as a tap the moment it lifts (see
        // that function's doc comment: an earlier version measured elapsed
        // time only when an event arrived, which a perfectly still hold
        // never delivered). That race runs on the real coroutine dispatcher,
        // not the test's injected-event clock, so it needs an actual wall
        // pause between down and up to have elapsed - advanceEventTime()
        // would not do it here.
        Thread.sleep(700)
        node.performTouchInput { up() }
        composeRule.waitForIdle()

        assertEquals(listOf(1L), recorded.longPressed)
        assertEquals(emptyList<Long>(), recorded.opened)

        // The deck's front is unaffected by a long-press: 3 still opens
        // directly.
        composeRule.onNodeWithTag(credentialStackCardTestTag(3L)).performClick()
        assertEquals(listOf(3L), recorded.opened)
    }
}
