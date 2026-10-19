// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.siros.sdk.credentials.PresentationConsentRequest
import org.siros.sdk.wallet.PresentationConsentHandler

/**
 * A request on screen. A plain class (identity equality) on purpose: [PresentationConsentRequest] is a data class,
 * so two requests with equal content would be conflated by a `StateFlow` and the second one never shown.
 */
class PendingPresentationConsent(val request: PresentationConsentRequest)

/**
 * Hands a `circuit_zk` presentation consent from the SDK to the UI and the answer back: [handler] suspends
 * the SDK until the user answers via [answer], while [pending] is what the UI renders. Cancelling the SDK's
 * wait (its own time limit) clears [pending], so a stale dialog never outlives the request. Requests are
 * served one at a time, and an answer names the request it is for ([answer]): a callback of a replaced or
 * expired dialog can never approve another presentation. The request is never logged.
 */
class PresentationConsentGate {
    private val _pending = MutableStateFlow<PendingPresentationConsent?>(null)

    /** The request waiting for the user, or `null`. */
    val pending: StateFlow<PendingPresentationConsent?> = _pending

    @Volatile
    private var waiting: CompletableDeferred<Boolean>? = null

    private val serial = Mutex()

    @Volatile
    private var current: PendingPresentationConsent? = null

    /** Register this with `SirosWallet.presentationConsentHandler`. */
    val handler = PresentationConsentHandler { request ->
        // One request on screen at a time; a second waits here (and is subject to the SDK's own time limit).
        serial.withLock {
            val answer = CompletableDeferred<Boolean>()
            waiting = answer
            val shown = PendingPresentationConsent(request)
            current = shown
            _pending.value = shown
            try {
                answer.await()
            } finally {
                if (waiting === answer) {
                    waiting = null
                    current = null
                    _pending.value = null
                }
            }
        }
    }

    /** The user's answer to [shown]; ignored unless [shown] is the one on screen now. */
    fun answer(shown: PendingPresentationConsent, agreed: Boolean) {
        if (current === shown) waiting?.complete(agreed)
    }
}
