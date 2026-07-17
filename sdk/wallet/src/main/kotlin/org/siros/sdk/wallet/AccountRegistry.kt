// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import timber.log.Timber

/**
 * Persistent registry of known accounts that survives logout.
 *
 * Mirrors the frontend's `localStorage.cachedUsers` — stores an array
 * of [CachedAccount] entries so the login screen can show "Welcome back"
 * with a list of known accounts and their passkeys.
 *
 * The registry is encrypted at rest using `EncryptedSharedPreferences`.
 * It is separate from [SessionStore] which holds the active session.
 */
class AccountRegistry(context: Context) {

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = false }

    private val prefs: SharedPreferences = try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (e: Exception) {
        // Fallback to plain SharedPreferences on API < 23 or test environments
        Timber.w(e, "EncryptedSharedPreferences unavailable, using plain prefs")
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /** All known accounts across all tenants and backends. */
    fun listAccounts(): List<CachedAccount> {
        val raw = prefs.getString(KEY_ACCOUNTS, null) ?: return emptyList()
        return try {
            json.decodeFromString<List<CachedAccount>>(raw)
        } catch (e: Exception) {
            Timber.e(e, "Failed to decode account registry")
            emptyList()
        }
    }

    /** Accounts for a specific tenant. */
    fun listAccounts(tenantId: String): List<CachedAccount> =
        listAccounts().filter { it.tenantId == tenantId }

    /** Accounts that have at least one passkey with PRF support. */
    fun listLoginableAccounts(): List<CachedAccount> =
        listAccounts().filter { it.hasPrfKeys }

    /** Accounts for a specific tenant that can log in (have PRF keys). */
    fun listLoginableAccounts(tenantId: String): List<CachedAccount> =
        listAccounts(tenantId).filter { it.hasPrfKeys }

    /** Find an account by its unique ID (`tenantId:userId`). */
    fun findAccount(accountId: String): CachedAccount? =
        listAccounts().find { it.accountId == accountId }

    /** Add or update an account in the registry. */
    fun upsertAccount(account: CachedAccount) {
        val accounts = listAccounts().toMutableList()
        val index = accounts.indexOfFirst { it.accountId == account.accountId }
        if (index >= 0) {
            accounts[index] = account
        } else {
            accounts.add(account)
        }
        save(accounts)
    }

    /** Remove an account from the registry. */
    fun removeAccount(accountId: String) {
        val accounts = listAccounts().filter { it.accountId != accountId }
        save(accounts)
    }

    /** Remove all cached accounts (factory reset). */
    fun clear() {
        prefs.edit().remove(KEY_ACCOUNTS).apply()
    }

    /** The ID of the currently active account, or null. */
    var activeAccountId: String?
        get() = prefs.getString(KEY_ACTIVE, null)
        set(value) {
            if (value != null) prefs.edit().putString(KEY_ACTIVE, value).apply()
            else prefs.edit().remove(KEY_ACTIVE).apply()
        }

    /** Distinct tenants across all registered accounts. */
    fun knownTenants(): List<TenantInfo> {
        val accounts = listAccounts()
        return accounts.groupBy { it.tenantId }.map { (tenantId, accts) ->
            TenantInfo(
                id = tenantId,
                accountCount = accts.size,
                backendUrl = accts.first().backendUrl,
            )
        }
    }

    private fun save(accounts: List<CachedAccount>) {
        val raw = json.encodeToString(accounts)
        prefs.edit().putString(KEY_ACCOUNTS, raw).apply()
    }

    companion object {
        private const val PREFS_NAME = "siros_account_registry"
        private const val KEY_ACCOUNTS = "accounts"
        private const val KEY_ACTIVE = "active_account_id"
    }
}

/**
 * Summary info about a known tenant.
 */
data class TenantInfo(
    val id: String,
    val accountCount: Int,
    val backendUrl: String,
)
