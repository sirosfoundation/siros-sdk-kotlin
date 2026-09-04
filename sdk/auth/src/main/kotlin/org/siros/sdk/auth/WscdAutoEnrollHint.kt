// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

/**
 * Optional capability an [AuthProvider] can implement: a heuristic signal
 * that the credential just used to log in MIGHT ALSO be usable as a WSCD
 * signing device - e.g. a roaming FIDO2 security key (used for passkey
 * login) that happens to also support the previewSign CTAP2 extension
 * (used for credential signing).
 *
 * This is deliberately a HINT, not a real capability check. Standard
 * WebAuthn - what login goes through - has no way to query CTAP2-level
 * extension support like previewSign; that's a proprietary extension
 * entirely invisible to the WebAuthn/CredentialManager layer. Confirming
 * it requires an actual raw CTAP2 session with the physical device, which
 * is exactly what the auto-enroll attempt this hint triggers performs. A
 * true [suggestsWscdCapableDevice] therefore means "worth offering the
 * user an auto-enroll prompt", not "confirmed supported" - the enrollment
 * attempt itself is the real test, and can still fail (gracefully) if the
 * physical key doesn't actually support the plugin's signing extension.
 *
 * Any future login mechanism that might front a WSCD-capable device (e.g.
 * some other authenticator-based login scheme down the line) can implement
 * this the same way [CredentialManagerAuthProvider] does for FIDO2 - the
 * host app's post-login check (see [org.siros.sdk.wallet.SirosWallet.wscdAutoEnrollHint])
 * doesn't need to know which concrete auth mechanism it's talking to.
 */
interface WscdAutoEnrollHint {
    /** WSCD plugin ID this hint is for (e.g. `"fido2"`), so multiple hints/plugins can coexist. */
    val hintedWscdPluginId: String

    /** True if the most recent login looks like it might also support that plugin's signing. */
    fun suggestsWscdCapableDevice(): Boolean
}
