package org.siros.sdk.sample

import android.content.Context
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/**
 * One known wallet backend: everything a login needs to reach it.
 *
 * The wallet's connection settings ([WalletViewModel]'s `siros_test_overrides`
 * prefs) describe the ONE backend the app currently talks to; this type is
 * the registry of every backend the user has told the app about, so they can
 * keep several around (dev / GDC / a vendor sandbox) and switch between them
 * without retyping the URL set each time.
 *
 * **Android-only by design**: a backend switch is only as good as the
 * redirect URI it uses for the OAuth login, and iOS registers custom URL
 * schemes statically in the Info.plist (universal links in the
 * Associated-Domains entitlement) - a backend added at runtime there could
 * never complete its own login round-trip, so the Swift sample app keeps a
 * single backend and does not grow a registry like this one.
 */
@Serializable
data class BackendProfile(
    /** Stable identity of the profile (a UUID); rename edits [name], never this. */
    val id: String,
    /** The human label shown in the picker and the settings list. */
    val name: String,
    /** The wallet backend URL (`WalletConfig.backendUrl`). */
    val backendUrl: String,
    /** The tenant on that backend (`WalletConfig.tenantId`). */
    val tenantId: String = "default",
    /** Explicit engine URL override, blank = derive from [backendUrl]. */
    val engineUrl: String = "",
    /** ZK circuit mirror URLs, empty = the SDK default list. */
    val zkCircuitUrls: List<String> = emptyList(),
)

/**
 * Load/save of the registry over the same `siros_test_overrides` prefs the
 * individual connection settings use. The registry is the user's record; the
 * individual keys remain the materialized "current" state every existing
 * reader (`_backendUrl` and friends) already consumes - a switch writes a
 * profile INTO those keys rather than replacing them.
 */
object BackendProfiles {
    private const val PREFS = "siros_test_overrides"
    private const val KEY_KNOWN = "known_backends"
    private const val KEY_CURRENT = "current_backend_id"

    private val json = Json { ignoreUnknownKeys = true }

    fun load(context: Context): List<BackendProfile> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_KNOWN, null)
            ?.let { raw -> runCatching { json.decodeFromString(ListSerializer(BackendProfile.serializer()), raw) }.getOrNull() }
            .orEmpty()

    fun save(context: Context, profiles: List<BackendProfile>) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_KNOWN, json.encodeToString(ListSerializer(BackendProfile.serializer()), profiles))
            .apply()
    }

    fun currentId(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_CURRENT, null)

    fun saveCurrentId(context: Context, id: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_CURRENT, id).apply()
    }

    /**
     * The first-run migration: a user who has already configured a backend
     * (the pre-login sheet) has never heard of profiles, so their current
     * individual settings become the seed "Default" profile instead of an
     * empty picker over a still-working app.
     */
    fun seed(context: Context, backendUrl: String, tenantId: String, engineUrl: String, zkCircuitUrls: List<String>): List<BackendProfile> {
        val existing = load(context)
        if (existing.isNotEmpty()) return existing
        val seeded = listOf(
            BackendProfile(
                id = java.util.UUID.randomUUID().toString(),
                name = "Default",
                backendUrl = backendUrl,
                tenantId = tenantId,
                engineUrl = engineUrl,
                zkCircuitUrls = zkCircuitUrls,
            )
        )
        save(context, seeded)
        saveCurrentId(context, seeded[0].id)
        return seeded
    }
}