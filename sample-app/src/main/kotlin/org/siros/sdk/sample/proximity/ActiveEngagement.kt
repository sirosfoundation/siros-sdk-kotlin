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
}
