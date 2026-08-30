// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.provider.ClearCredentialRegistryRequest
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialRegistry
import java.io.ByteArrayOutputStream
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.StoredCredential
import timber.log.Timber
import uniffi.siros_dc_matcher_ffi.FfiCapability
import uniffi.siros_dc_matcher_ffi.FfiClaim
import uniffi.siros_dc_matcher_ffi.FfiCredential
import uniffi.siros_dc_matcher_ffi.SirosBlobBuilder

/**
 * Registers this wallet's credentials with the OS credential picker, using a
 * matcher the SDK supplies rather than the one AndroidX ships.
 *
 * The matcher is the WebAssembly module the platform runs inside the picker to
 * decide which credentials to offer. AndroidX's `OpenId4VpRegistry` supplies
 * Google's build, which understands `mso_mdoc` and `dc+sd-jwt` and nothing
 * else - so a verifier asking for `mso_mdoc_zk` gets no entry at all and the
 * ZK presentation path is unreachable from a browser.
 *
 * Swapping it is public API rather than a workaround: [DigitalCredentialRegistry]
 * takes the matcher as a plain `ByteArray`.
 *
 * ## Why this lives in the SDK
 *
 * Registration, blob building and matching are wallet logic that every
 * consumer needs. They lived in the sample app while the swap was being
 * proven; keeping them there would have made every wallet reimplement the one
 * part where a mistake is invisible - a blob the matcher cannot read looks
 * exactly like having no matching credential.
 *
 * ## One artifact, one version
 *
 * The encoder and `matcher.wasm` both come from the `siros-dc-matcher` AAR.
 * Pairing an encoder with a matcher that predates it produces a wallet that
 * matches nothing and reports nothing, so they are deliberately not separable.
 */
object SirosCredentialRegistry {

    /** Matches the `intentAction` the wallet's DC API activity declares. */
    const val REGISTRY_ID = "org.siros.sdk.wallet.dcapi.registry"

    /** Asset path of the matcher, shipped inside the `siros-dc-matcher` AAR. */
    private const val MATCHER_ASSET = "matcher.wasm"

    /** Icon edge length, in pixels, for the placeholder card image. */
    private const val ICON_SIZE = 64

    /**
     * Replace the registered snapshot with [credentials].
     *
     * Registration is a whole-snapshot replace rather than an incremental
     * update, so call this whenever the credential set materially changes.
     * An empty set clears the registry: a wallet with nothing to offer should
     * not appear in the picker at all.
     */
    suspend fun refresh(
        context: Context,
        credentials: List<StoredCredential>,
        zkSystems: List<ZkSystem> = emptyList(),
        useStockMatcher: Boolean = false,
    ) {
        if (credentials.isEmpty()) {
            clear(context)
            return
        }
        try {
            if (useStockMatcher) {
                registerWithStockMatcher(context, credentials)
                return
            }
            val blob = buildBlob(credentials, zkSystems)
            val matcher = context.assets.open(MATCHER_ASSET).use { it.readBytes() }
            RegistryManager.create(context).registerCredentials(
                SirosRegistry(credentials = blob, matcher = matcher),
            )
            Timber.d("DC API registry updated: ${credentials.size} credentials, ${blob.size}-byte blob")
        } catch (e: Exception) {
            // Registration failing must never break the rest of the app - on a
            // device without DC API support it simply means these credentials
            // are not offered through the browser.
            Timber.w(e, "Failed to register DC API credentials")
        }
    }

    /**
     * Register through AndroidX's matcher instead of ours.
     *
     * Kept reachable deliberately. The platform accepting a wallet-supplied
     * matcher is confirmed on hardware, but it is not ours to guarantee, and
     * the cost of keeping a way back is one function. It understands
     * `mso_mdoc` and `dc+sd-jwt` only - a `mso_mdoc_zk` request produces no
     * entry on this path, which is the whole reason the other one exists.
     */
    private suspend fun registerWithStockMatcher(
        context: Context,
        credentials: List<StoredCredential>,
    ) {
        val entries = StockEntryBuilder.buildEntries(credentials)
        if (entries.isEmpty()) {
            clear(context)
            return
        }
        RegistryManager.create(context).registerCredentials(
            OpenId4VpRegistry(
                credentialEntries = entries,
                id = REGISTRY_ID,
                supportedProtocols = listOf(
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_SIGNED,
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_MULTISIGNED,
                    OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_UNSIGNED,
                ),
            ),
        )
        Timber.d("DC API registry updated via the stock matcher (${entries.size} entries)")
    }

    /** Remove this wallet's entries from the picker. */
    suspend fun clear(context: Context) {
        try {
            RegistryManager.create(context)
                .clearCredentialRegistry(ClearCredentialRegistryRequest(true))
        } catch (e: Exception) {
            Timber.w(e, "Failed to clear DC API credential registry")
        }
    }

    /**
     * A zero-knowledge proof system this wallet can actually produce.
     *
     * [params] is not decoration. A ZK circuit is built for a fixed attribute
     * count, so a request naming the right [system] with a different
     * `num_attributes` is a proof this wallet cannot produce - and omitting the
     * parameter turns that into a failure after the user has consented, rather
     * than an entry that was never offered.
     */
    data class ZkSystem(val system: String, val params: Map<String, String>)

    /**
     * Encode the blob to register.
     *
     * Built by the Rust encoder rather than assembled here: the matcher reads
     * this with the decoder from the same artifact, and a second hand-written
     * encoder is exactly the kind of thing that drifts silently.
     */
    internal fun buildBlob(
        credentials: List<StoredCredential>,
        zkSystems: List<ZkSystem>,
    ): ByteArray {
        val builder = SirosBlobBuilder()
        zkSystems.forEach { builder.addZkSystem(FfiCapability(it.system, it.params)) }

        credentials.forEach { cred ->
            val iconId = cred.id.toString()
            builder.addIcon(iconId, placeholderIcon(cred))
            builder.addCredential(
                FfiCredential(
                    id = cred.id.toString(),
                    format = cred.format,
                    // The real docType, parsed from the credential's own MSO -
                    // not issuer metadata, which is only populated when the
                    // issuer happens to expose a SIROS-internal schema
                    // endpoint. A standards-conformant third-party issuer has
                    // no reason to, and relying on it leaves every such
                    // credential unmatchable while looking perfectly valid.
                    doctype = CredentialUtils.parseMdocDocument(cred)?.docType
                        ?: cred.metadata?.doctype,
                    vct = cred.metadata?.vct,
                    title = cred.metadata?.name ?: cred.format,
                    subtitle = cred.metadata?.issuer?.name ?: "",
                    iconId = iconId,
                    claims = CredentialUtils.extractClaims(cred).map { claim ->
                        FfiClaim(
                            // A list, not a dotted string. ISO mdoc namespaces
                            // contain dots themselves (org.iso.18013.5.1), so
                            // flattening and re-splitting mis-parses every one
                            // of them - splitting on the LAST dot is what makes
                            // "org.iso.18013.5.1.family_name" come back as the
                            // namespace and element it actually is.
                            path = splitClaimKey(cred.format, claim.key),
                            value = claim.value,
                            display = claim.label,
                            displayValue = claim.value,
                        )
                    },
                ),
            )
        }
        return builder.build()
    }

    /**
     * Split a display-claim key into the path components DCQL matches against.
     *
     * mdoc element identifiers never contain dots while namespaces routinely
     * do, so the split is on the last one. JSON-based credentials keep the key
     * whole - their claim keys are not dotted paths.
     */
    internal fun splitClaimKey(format: String, key: String): List<String> =
        if (format.equals("mso_mdoc", ignoreCase = true) && key.contains('.')) {
            listOf(key.substringBeforeLast('.'), key.substringAfterLast('.'))
        } else {
            listOf(key)
        }

    /**
     * A flat card-coloured placeholder.
     *
     * The real issuer logo is a remote URL, and fetching it needs async I/O
     * this synchronous encode cannot do. Fetching and caching it is a
     * reasonable follow-up; showing nothing is worse than showing the card's
     * own colour.
     */
    private fun placeholderIcon(cred: StoredCredential): ByteArray {
        val color = try {
            Color.parseColor(cred.metadata?.backgroundColor ?: "#1A365D")
        } catch (_: Exception) {
            Color.parseColor("#1A365D")
        }
        val bitmap = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888)
        Canvas(bitmap).drawColor(color)
        return ByteArrayOutputStream().use { out ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            out.toByteArray()
        }
    }

    /** The registration request itself. */
    private class SirosRegistry(credentials: ByteArray, matcher: ByteArray) :
        DigitalCredentialRegistry(
            id = REGISTRY_ID,
            credentials = credentials,
            matcher = matcher,
        )
}
