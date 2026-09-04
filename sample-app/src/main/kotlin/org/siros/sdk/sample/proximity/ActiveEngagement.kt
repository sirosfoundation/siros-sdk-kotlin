// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.proximity

/**
 * Holds the NFC Handover Select bytes for the currently-displayed device
 * engagement, if any - read by [MdocHostApduService], which the Android
 * platform instantiates and drives independently of app UI lifecycle (HCE
 * services can't be constructor-injected with per-session state).
 *
 * Set when `ProximityEngagementScreen` is shown, cleared when it's
 * dismissed - a reader tapping the device outside an active engagement
 * session gets [MdocHostApduService]'s "file not found" response rather
 * than a stale engagement.
 */
object ActiveEngagement {
    @Volatile
    var handoverSelectBytes: ByteArray? = null

    /**
     * Invoked by [MdocHostApduService] once a reader has read all the way to
     * the end of the NDEF file - i.e. actually received the full Handover
     * Select message (including the `DeviceEngagement` CBOR), not merely
     * tapped the tag partway through a SELECT/READ BINARY sequence.
     *
     * `ProximityEngagementScreen` uses this to defer starting
     * `BleCentralClient`/`BlePeripheralServer` until the physical NFC tap
     * has genuinely completed, rather than the instant the screen composes.
     * Confirmed live against two independent mdoc readers: both correctly
     * received the NFC static handover, but our own `BleCentralClient` scan
     * (a fixed window starting at screen-mount time) had already expired by
     * the time each reader - having just finished reading the handover and
     * now waiting for a central-client connection from us - was actually
     * ready, since a real-world NFC tap (walk up, position, hold steady)
     * can easily eat most or all of a 20-second budget before the reader
     * ever sees the engagement it's meant to race against.
     */
    @Volatile
    var onHandoverServed: (() -> Unit)? = null
}
