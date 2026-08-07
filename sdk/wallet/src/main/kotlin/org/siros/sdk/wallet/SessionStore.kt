// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import timber.log.Timber

/**
 * Account-keyed encrypted session storage.
 *
 * All session data (tokens, key material, private data JWE) is stored
 * under a prefix derived from the active account ID (`tenantId:userId`).
 * This allows multiple accounts to coexist in the same SharedPreferences
 * file without interfering with each other.
 *
 * The active account is tracked via [activeAccountId]. When set, all
 * property reads/writes are scoped to that account. When null, reads
 * return null and writes are no-ops.
 *
 * Calling [clearAccount] removes only the active account's data.
 * Calling [clearAll] removes everything (factory reset).
 */
internal class SessionStore(context: Context) {

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        "siros_wallet_session",
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context.applicationContext,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    /**
     * The currently active account ID (`tenantId:userId`).
     * All property reads/writes are scoped to this account.
     */
    var activeAccountId: String? = null

    // ── Scoped key helper ───────────────────────────────────────────

    private fun getString(name: String): String? {
        val id = activeAccountId ?: return null
        return prefs.getString("${id}/${name}", null)
    }

    private fun putString(name: String, value: String?) {
        val id = activeAccountId ?: return
        val k = "${id}/${name}"
        if (value != null) prefs.edit().putString(k, value).apply()
        else prefs.edit().remove(k).apply()
    }

    // ── Session ─────────────────────────────────────────────────────

    var appToken: String?
        get() = getString("app_token")
        set(value) = putString("app_token", value)

    var refreshToken: String?
        get() = getString("refresh_token")
        set(value) = putString("refresh_token", value)

    var userId: String?
        get() = getString("user_id")
        set(value) = putString("user_id", value)

    var displayName: String?
        get() = getString("display_name")
        set(value) = putString("display_name", value)

    var tenantId: String?
        get() = getString("tenant_id")
        set(value) = putString("tenant_id", value)

    // ── Key material ────────────────────────────────────────────────

    var mainKey: String?
        get() = getString("main_key")
        set(value) = putString("main_key", value)

    var hkdfSalt: String?
        get() = getString("hkdf_salt")
        set(value) = putString("hkdf_salt", value)

    var hkdfInfo: String?
        get() = getString("hkdf_info")
        set(value) = putString("hkdf_info", value)

    var prfSalt: String?
        get() = getString("prf_salt")
        set(value) = putString("prf_salt", value)

    var credentialId: String?
        get() = getString("credential_id")
        set(value) = putString("credential_id", value)

    /**
     * The keystore key ID used as this wallet installation's persistent
     * OAuth Client Attestation instance key (draft-ietf-oauth-attestation-based-client-auth-04
     * §3.1) - generated once, reused for the account's lifetime. The
     * backend's Wallet Instance Attestation tracks/revokes instances by this
     * key's JWK thumbprint, so a different key each time would silently
     * register a new "instance" on every flow.
     */
    var instanceKeyId: String?
        get() = getString("instance_key_id")
        set(value) = putString("instance_key_id", value)

    // ── Private data ────────────────────────────────────────────────

    var privateDataJwe: String?
        get() = getString("private_data_jwe")
        set(value) = putString("private_data_jwe", value)

    var privateDataETag: String?
        get() = getString("private_data_etag")
        set(value) = putString("private_data_etag", value)

    /**
     * TOFU (trust-on-first-use) mapping of `"issuer|credentialType"` ->
     * chosen WSCD plugin ID, serialized as a single JSON string blob (see
     * [SessionStoreWscdTofuStore]) - matches [privateDataJwe]'s "one opaque
     * string" precedent rather than one property per (issuer, credentialType)
     * pair, since that set is open-ended.
     */
    var wscdTofuMappingJson: String?
        get() = getString("wscd_tofu_mapping")
        set(value) = putString("wscd_tofu_mapping", value)

    /**
     * Explicit per-`"issuer|credentialType"` user overrides for which WSCD
     * plugin to use - distinct from [wscdTofuMappingJson]: TOFU is an
     * auto-remembered outcome of an ambiguous resolution, this is a
     * deliberate "always use this plugin here" preference the user set
     * directly (e.g. from a settings screen). Same "one opaque JSON blob"
     * shape as [wscdTofuMappingJson] (see [SessionStoreWscdUserOverrideStore]).
     */
    var wscdUserOverrideMappingJson: String?
        get() = getString("wscd_user_override_mapping")
        set(value) = putString("wscd_user_override_mapping", value)

    /**
     * A single user-chosen WSCD plugin ID to prefer for EVERY issuer/
     * credential type, unless a more specific [wscdUserOverrideMappingJson]
     * entry applies instead - e.g. "always use my YubiKey, no matter what
     * any individual issuer/credential type actually requires."
     */
    var wscdGlobalOverridePluginId: String?
        get() = getString("wscd_global_override_plugin_id")
        set(value) = putString("wscd_global_override_plugin_id", value)

    // ── Lifecycle ───────────────────────────────────────────────────

    /** True if the active account has session data. */
    val hasSession: Boolean
        get() = userId != null

    /** Clear the active account's session data only. */
    fun clearAccount() {
        val id = activeAccountId ?: return
        val prefix = "$id/"
        val editor = prefs.edit()
        prefs.all.keys.filter { it.startsWith(prefix) }.forEach { editor.remove(it) }
        editor.apply()
        Timber.d("Session store cleared for account: $id")
    }

    /** Clear all accounts' session data (factory reset). */
    fun clearAll() {
        prefs.edit().clear().apply()
        activeAccountId = null
        Timber.d("Session store cleared (all accounts)")
    }

    /** Legacy alias for [clearAccount] — clears the active account only. */
    fun clear() = clearAccount()
}
