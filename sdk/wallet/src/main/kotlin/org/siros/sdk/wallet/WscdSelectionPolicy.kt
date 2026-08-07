// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.siros.sdk.keystore.WscdPluginCapabilities
import timber.log.Timber

/** The host app's answer to a [RequestWscdChoice] prompt. */
sealed interface WscdChoiceResult {
    data class Chosen(val pluginId: String) : WscdChoiceResult
    data object Cancelled : WscdChoiceResult
}

/**
 * Asks the host app to pick which registered WSCD plugin to use for an
 * upcoming credential-issuance key batch, when [WscdSelectionPolicy] can't
 * resolve it unambiguously on its own (see that class's doc comment for the
 * full resolution order this is one step of).
 *
 * Mirrors [org.siros.sdk.keystore.mdoc.RequestProximityConsent]'s shape
 * exactly: a suspending bridge to the host app's own UI, implemented by the
 * host app and supplied via [WalletConfig.requestWscdChoice].
 *
 * Only a plugin ID is returned, not a `KeystoreManager` instance - the SDK
 * already holds the concrete instance via [WalletConfig.availableKeystores],
 * since that map is how the host app registers what's available in the
 * first place.
 *
 * @param issuer the credential issuer identifier.
 * @param credentialType the credential type identifier (`vct` or mdoc
 *   `doctype`) about to be issued.
 * @param eligiblePluginIds every plugin ID whose static nominal tier (see
 *   [WscdPluginCapabilities]) meets the credential type's required tier
 *   (never empty or a singleton - [WscdSelectionPolicy] only invokes this
 *   when there's a genuine choice to make).
 */
typealias RequestWscdChoice = suspend (
    issuer: String,
    credentialType: String,
    eligiblePluginIds: List<String>,
) -> WscdChoiceResult

/**
 * Thrown by [WscdSelectionPolicy.resolve] when zero of the host app's
 * [WalletConfig.availableKeystores] entries have a static nominal tier
 * ([WscdPluginCapabilities]) meeting a credential type's declared
 * `requiredTier` - a distinct signal from "no requirement" (which resolves
 * to `null`, a no-op) so a caller can surface a clear "no available
 * authenticator meets this credential's requirement" error instead of
 * silently proceeding with an insufficient plugin.
 */
class NoEligibleWscdPluginException(
    val issuer: String,
    val credentialType: String,
    val requiredTier: String,
) : Exception(
    "No available WSCD plugin meets required key-storage tier '$requiredTier' for issuer=$issuer credentialType=$credentialType"
)

/**
 * Trust-on-first-use persistence for [WscdSelectionPolicy]'s per-
 * (issuer, credentialType) plugin choice, so the host app/user is asked at
 * most once unless the persisted choice stops being sufficient for a
 * (possibly later, stricter) required tier. Abstracted behind an interface
 * so tests can supply an in-memory fake instead of an Android
 * `EncryptedSharedPreferences`-backed [SessionStore].
 */
interface WscdTofuStore {
    /** The persisted plugin ID for `"$issuer|$credentialType"`, or `null` if none yet. */
    fun get(issuer: String, credentialType: String): String?

    /** Persist `pluginId` as the TOFU choice for `"$issuer|$credentialType"`. */
    fun put(issuer: String, credentialType: String, pluginId: String)

    /**
     * Every persisted mapping, keyed by `"$issuer|$credentialType"` -> plugin
     * ID - for host-app settings UI that wants to show/clear the TOFU state
     * (see [WscdSelectionPolicy.tofuMapping]). Defaults to empty so existing
     * [WscdTofuStore] implementations (e.g. test fakes) don't have to
     * implement it just to keep compiling.
     */
    fun getAll(): Map<String, String> = emptyMap()

    /**
     * Remove the persisted mapping for `"$issuer|$credentialType"`, if any -
     * a "forget this choice" host-app affordance (see
     * [WscdSelectionPolicy.clearTofuMapping]). No-op by default.
     */
    fun remove(issuer: String, credentialType: String) {}

    /**
     * Remove every persisted mapping (see [WscdSelectionPolicy.clearAllTofuMappings]).
     * No-op by default.
     */
    fun clearAll() {}
}

/**
 * [WscdTofuStore] backed by [SessionStore.wscdTofuMappingJson] - the whole
 * mapping is kept as a single serialized `Map<String, String>` JSON blob
 * (matching [SessionStore.privateDataJwe]'s "one opaque string" precedent)
 * rather than one `SessionStore` property per (issuer, credentialType) pair,
 * since that set is open-ended and account-scoped storage already handles
 * multi-account isolation for us.
 */
internal class SessionStoreWscdTofuStore(private val sessionStore: SessionStore) : WscdTofuStore {
    private val json = Json { ignoreUnknownKeys = true }
    private val mapSerializer = MapSerializer(String.serializer(), String.serializer())

    private fun key(issuer: String, credentialType: String) = "$issuer|$credentialType"

    private fun readAll(): Map<String, String> {
        val raw = sessionStore.wscdTofuMappingJson ?: return emptyMap()
        return try {
            json.decodeFromString(mapSerializer, raw)
        } catch (e: Exception) {
            Timber.w(e, "Failed to decode WSCD TOFU mapping, treating as empty")
            emptyMap()
        }
    }

    override fun get(issuer: String, credentialType: String): String? = readAll()[key(issuer, credentialType)]

    override fun put(issuer: String, credentialType: String, pluginId: String) {
        val updated = readAll() + (key(issuer, credentialType) to pluginId)
        sessionStore.wscdTofuMappingJson = json.encodeToString(mapSerializer, updated)
    }

    override fun getAll(): Map<String, String> = readAll()

    override fun remove(issuer: String, credentialType: String) {
        val updated = readAll() - key(issuer, credentialType)
        sessionStore.wscdTofuMappingJson = if (updated.isEmpty()) null else json.encodeToString(mapSerializer, updated)
    }

    override fun clearAll() {
        sessionStore.wscdTofuMappingJson = null
    }
}

/**
 * Resolves which WSCD plugin should back key generation for one
 * credential-issuance key batch, given the credential type's declared
 * key-storage assurance requirement (`Vctm.requiredKeyStorage` /
 * `MddlSchema.requiredKeyStorage`, wire field `attestation_los`) and the set
 * of plugins the host app has actually registered
 * (`WalletConfig.availableKeystores`).
 *
 * **Phase 1 scope**: no changes to `siros-wscd-manager` (Rust/UniFFI) - no
 * live plugin enumeration, no live per-plugin capability query. Resolution
 * uses only [WscdPluginCapabilities]'s static table and picks among
 * `KeystoreManager` instances the host app has already constructed and
 * handed to the SDK via `availableKeystores` - never by asking the SDK to
 * build or mutate a plugin instance itself (only the host app can wire up
 * the platform transports real plugins like fido2/r2ps need).
 *
 * Resolution order for [resolve]:
 * 1. `requiredTier == null` (credential type declared no requirement) ->
 *    `null` (no-op: caller keeps using its existing default keystore).
 * 2. A [WscdTofuStore]-persisted choice for (issuer, credentialType) that's
 *    still available and still meets `requiredTier` -> reuse it.
 * 3. [defaultMapping]'s entry for (issuer, credentialType), if available and
 *    sufficient -> persist as the new TOFU entry, return it.
 * 4. Exactly one plugin among `availablePluginIds` meets `requiredTier` ->
 *    persist as TOFU, return it. Otherwise, if [currentDefaultPluginId] (the
 *    plugin already active before this resolution) itself meets
 *    `requiredTier`, prefer it - avoids an unnecessary plugin switch when
 *    the current default is already good enough, even though other eligible
 *    plugins exist.
 * 5. More than one eligible plugin and the current default isn't one of
 *    them (or is unknown) -> ask the host app via [requestChoice]. A
 *    `Chosen` result is persisted as TOFU and returned; `Cancelled` (or no
 *    [requestChoice] callback configured at all) returns `null` - matching
 *    this SDK's "best effort, never block issuance outright without a clear
 *    reason" convention (see `SirosWallet.requestBackendKeyAttestation`'s
 *    catch blocks) - the caller's existing fallback path takes over.
 * 6. Zero eligible plugins -> [NoEligibleWscdPluginException], a distinct
 *    signal from every other branch above so the caller does NOT silently
 *    proceed with an insufficient plugin.
 */
class WscdSelectionPolicy(
    private val tofuStore: WscdTofuStore,
    private val defaultMapping: Map<String, String>? = null,
    private val requestChoice: RequestWscdChoice? = null,
) {
    /**
     * Every persisted TOFU mapping, keyed by `"issuer|credentialType"` ->
     * plugin ID - for a host-app settings screen to display (and, via
     * [clearTofuMapping]/[clearAllTofuMappings], let the user forget).
     */
    fun tofuMapping(): Map<String, String> = tofuStore.getAll()

    /**
     * Forget one persisted TOFU choice, so the next [resolve] call for that
     * (issuer, credentialType) pair re-evaluates from scratch (falling back
     * to [defaultMapping], auto-pick, or [requestChoice] again).
     */
    fun clearTofuMapping(issuer: String, credentialType: String) = tofuStore.remove(issuer, credentialType)

    /** Forget every persisted TOFU choice. */
    fun clearAllTofuMappings() = tofuStore.clearAll()

    suspend fun resolve(
        issuer: String,
        credentialType: String,
        requiredTier: String?,
        availablePluginIds: Set<String>,
        currentDefaultPluginId: String? = null,
    ): String? {
        if (requiredTier == null) return null

        fun isEligible(pluginId: String): Boolean {
            val tier = WscdPluginCapabilities.tierOf(pluginId) ?: return false
            return WscdPluginCapabilities.meets(tier, requiredTier)
        }

        tofuStore.get(issuer, credentialType)?.let { persisted ->
            if (persisted in availablePluginIds && isEligible(persisted)) return persisted
        }

        val mappingKey = "$issuer|$credentialType"
        defaultMapping?.get(mappingKey)?.let { mapped ->
            if (mapped in availablePluginIds && isEligible(mapped)) {
                tofuStore.put(issuer, credentialType, mapped)
                return mapped
            }
        }

        val eligibleIds = availablePluginIds.filter { isEligible(it) }
        return when {
            eligibleIds.isEmpty() ->
                throw NoEligibleWscdPluginException(issuer, credentialType, requiredTier)

            eligibleIds.size == 1 ->
                eligibleIds.first().also { tofuStore.put(issuer, credentialType, it) }

            currentDefaultPluginId != null && isEligible(currentDefaultPluginId) ->
                currentDefaultPluginId.also { tofuStore.put(issuer, credentialType, it) }

            else -> when (val choice = requestChoice?.invoke(issuer, credentialType, eligibleIds) ?: WscdChoiceResult.Cancelled) {
                is WscdChoiceResult.Chosen -> {
                    if (choice.pluginId !in eligibleIds) {
                        // Host app returned something outside the list it was
                        // offered - treat like Cancelled rather than trusting
                        // an answer that wasn't actually one of the options.
                        Timber.w(
                            "RequestWscdChoice returned '${choice.pluginId}' which wasn't in the offered " +
                                "eligible list $eligibleIds for issuer=$issuer credentialType=$credentialType; ignoring"
                        )
                        null
                    } else {
                        choice.pluginId.also { tofuStore.put(issuer, credentialType, it) }
                    }
                }
                WscdChoiceResult.Cancelled -> null
            }
        }
    }
}
