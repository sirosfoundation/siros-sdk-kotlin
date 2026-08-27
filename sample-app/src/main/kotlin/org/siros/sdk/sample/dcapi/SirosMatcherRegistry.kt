// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.dcapi

import android.content.Context
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.siros.sdk.credentials.StoredCredential

/**
 * Registers this wallet's credentials with a matcher we supply ourselves,
 * instead of the one AndroidX ships.
 *
 * The matcher is the WebAssembly module Play Services runs inside the
 * credential picker to decide which credentials to offer. AndroidX's
 * [androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry]
 * supplies Google's build of it, which understands `mso_mdoc` and `dc+sd-jwt`
 * and nothing else - so a verifier asking for `mso_mdoc_zk` gets no entry from
 * us at all, and the ZK presentation path is unreachable from a browser.
 *
 * Swapping it is public API rather than a workaround:
 * [androidx.credentials.registry.provider.RegisterCredentialsRequest] takes the
 * matcher as a plain `ByteArray`, so this is an ordinary subclass with our own
 * two byte arrays.
 *
 * ## Phase 1 scope
 *
 * The bundled matcher emits one fixed entry for any protocol it recognises. It
 * does not match yet - that arrives with the DCQL engine. What it does do is
 * read every input the real matcher will depend on and report what came back,
 * so a run on a device says which leg of the plumbing worked rather than only
 * that something did.
 *
 * Enabled by `-PcustomDcMatcher=true`; off by default, so ordinary builds keep
 * the stock behaviour. See `siros-dc-matcher/docs/plan.md`.
 */
class SirosMatcherRegistry(
    credentials: ByteArray,
    matcher: ByteArray,
) : DigitalCredentialRegistry(
    id = DCAPIProviderRegistration.REGISTRY_ID,
    credentials = credentials,
    matcher = matcher,
) {
    companion object {
        /** Asset path of the matcher built from `sirosfoundation/siros-dc-matcher`. */
        private const val MATCHER_ASSET = "matcher.wasm"

        fun create(context: Context, credentials: List<StoredCredential>) =
            SirosMatcherRegistry(
                credentials = credentialBlob(credentials),
                matcher = context.assets.open(MATCHER_ASSET).use { it.readBytes() },
            )

        /**
         * The credential snapshot handed to the matcher.
         *
         * Phase 1 deliberately keeps this trivial: the matcher only reports its
         * size, which is enough to prove the blob survives registration and
         * reaches the sandbox - the leg that silently breaks first. The real
         * versioned CBOR schema, with claim values the matcher can evaluate
         * DCQL against, is Phase 2.
         */
        internal fun credentialBlob(credentials: List<StoredCredential>): ByteArray {
            val entries = JSONArray()
            credentials.forEach { cred ->
                entries.put(
                    JSONObject().apply {
                        // Deliberately a string, though StoredCredential.id is
                        // a Long. Its "genuine JSON number on the wire"
                        // requirement is about the privatedata container
                        // shared with wallet-frontend (privatedata-spec §6),
                        // which this is not - this blob is read only by our
                        // own matcher. The id also has to be a string at the
                        // platform boundary, since the registry API types
                        // entry ids as String, so keeping it a string here
                        // means one representation the whole way through
                        // rather than converting twice.
                        put("id", cred.id.toString())
                        put("format", cred.format)
                    },
                )
            }
            return JSONObject().apply {
                put("version", 0)
                put("credentials", entries)
            }.toString().toByteArray(Charsets.UTF_8)
        }
    }
}
