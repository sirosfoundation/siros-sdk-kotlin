// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import timber.log.Timber

/**
 * Encrypted session storage backed by [EncryptedSharedPreferences].
 *
 * Stores the session token, PRF key derivation parameters, and the
 * raw main-key bytes so the wallet can be re-opened without requiring
 * a new WebAuthn assertion on every app launch.
 *
 * All values are encrypted at rest using an AES-256 key protected by
 * the Android Keystore. Calling [clear] wipes everything.
 */
internal class SessionStore(context: Context) {

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        "siros_wallet_session",
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context.applicationContext,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    // ── Session ─────────────────────────────────────────────────────

    var appToken: String?
        get() = prefs.getString(KEY_APP_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_APP_TOKEN, value).apply()

    var refreshToken: String?
        get() = prefs.getString(KEY_REFRESH_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_REFRESH_TOKEN, value).apply()

    var userId: String?
        get() = prefs.getString(KEY_USER_ID, null)
        set(value) = prefs.edit().putString(KEY_USER_ID, value).apply()

    var displayName: String?
        get() = prefs.getString(KEY_DISPLAY_NAME, null)
        set(value) = prefs.edit().putString(KEY_DISPLAY_NAME, value).apply()

    var tenantId: String?
        get() = prefs.getString(KEY_TENANT_ID, null)
        set(value) = prefs.edit().putString(KEY_TENANT_ID, value).apply()

    // ── Key material ────────────────────────────────────────────────

    /** Raw main-key bytes (AES-256, 32 bytes), base64-encoded. */
    var mainKey: String?
        get() = prefs.getString(KEY_MAIN_KEY, null)
        set(value) = prefs.edit().putString(KEY_MAIN_KEY, value).apply()

    /** HKDF salt used during key derivation, base64-encoded. */
    var hkdfSalt: String?
        get() = prefs.getString(KEY_HKDF_SALT, null)
        set(value) = prefs.edit().putString(KEY_HKDF_SALT, value).apply()

    /** HKDF info string used during key derivation, base64-encoded. */
    var hkdfInfo: String?
        get() = prefs.getString(KEY_HKDF_INFO, null)
        set(value) = prefs.edit().putString(KEY_HKDF_INFO, value).apply()

    /** PRF salt for the registered credential, base64-encoded. */
    var prfSalt: String?
        get() = prefs.getString(KEY_PRF_SALT, null)
        set(value) = prefs.edit().putString(KEY_PRF_SALT, value).apply()

    /** Credential ID of the registered passkey, base64url-encoded. */
    var credentialId: String?
        get() = prefs.getString(KEY_CREDENTIAL_ID, null)
        set(value) = prefs.edit().putString(KEY_CREDENTIAL_ID, value).apply()

    // ── Private data ────────────────────────────────────────────────

    /** The encrypted JWE container, stored as-is from the backend. */
    var privateDataJwe: String?
        get() = prefs.getString(KEY_PRIVATE_DATA_JWE, null)
        set(value) = prefs.edit().putString(KEY_PRIVATE_DATA_JWE, value).apply()

    /** ETag for optimistic concurrency on privateData updates. */
    var privateDataETag: String?
        get() = prefs.getString(KEY_PRIVATE_DATA_ETAG, null)
        set(value) = prefs.edit().putString(KEY_PRIVATE_DATA_ETAG, value).apply()

    // ── Lifecycle ───────────────────────────────────────────────────

    val hasSession: Boolean
        get() = appToken != null && userId != null

    fun clear() {
        prefs.edit().clear().apply()
        Timber.d("Session store cleared")
    }

    companion object {
        private const val KEY_APP_TOKEN = "app_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_DISPLAY_NAME = "display_name"
        private const val KEY_TENANT_ID = "tenant_id"
        private const val KEY_MAIN_KEY = "main_key"
        private const val KEY_HKDF_SALT = "hkdf_salt"
        private const val KEY_HKDF_INFO = "hkdf_info"
        private const val KEY_PRF_SALT = "prf_salt"
        private const val KEY_CREDENTIAL_ID = "credential_id"
        private const val KEY_PRIVATE_DATA_JWE = "private_data_jwe"
        private const val KEY_PRIVATE_DATA_ETAG = "private_data_etag"
    }
}
