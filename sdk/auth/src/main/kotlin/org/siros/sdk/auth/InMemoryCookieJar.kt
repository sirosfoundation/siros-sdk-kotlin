// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.auth

import android.content.Context
import android.content.SharedPreferences
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * Simple in-memory cookie jar for OkHttp.
 *
 * Suitable for tests or short-lived operations. For production use where the app
 * may be offloaded during long flows (e.g., credential issuance), prefer
 * [PersistentCookieJar] which survives process death.
 */
class InMemoryCookieJar : CookieJar {
    private val store = mutableMapOf<String, MutableList<Cookie>>()
    private val lock = Any()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        synchronized(lock) {
            val key = url.host
            val existing = store.getOrPut(key) { mutableListOf() }
            for (cookie in cookies) {
                existing.removeAll { it.name == cookie.name && it.path == cookie.path }
                existing.add(cookie)
            }
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        synchronized(lock) {
            val key = url.host
            val cookies = store[key] ?: return emptyList()
            val now = System.currentTimeMillis()
            cookies.removeAll { it.expiresAt <= now }
            return cookies.filter { it.matches(url) }
        }
    }

    /** Clear all stored cookies. */
    fun clear() {
        synchronized(lock) {
            store.clear()
        }
    }
}

/**
 * Persistent cookie jar backed by [SharedPreferences].
 *
 * Session cookies survive app process death so that authentication state is not
 * lost if the OS offloads the app during an extended issuance or presentation flow.
 *
 * Cookies are serialized as OkHttp `Set-Cookie` header strings and keyed by host.
 *
 * @param context Android context for SharedPreferences access.
 */
class PersistentCookieJar(context: Context) : CookieJar {
    private val prefs: SharedPreferences = context.getSharedPreferences(
        PREFS_NAME, Context.MODE_PRIVATE
    )
    // In-memory mirror for fast reads
    private val store = mutableMapOf<String, MutableList<Cookie>>()
    private val lock = Any()

    init {
        // Load persisted cookies into memory
        for ((key, value) in prefs.all) {
            if (value !is Set<*>) continue
            val url = "https://$key".toHttpUrlOrNull() ?: continue
            val cookies = value.mapNotNull { raw ->
                (raw as? String)?.let { Cookie.parse(url, it) }
            }.toMutableList()
            if (cookies.isNotEmpty()) {
                store[key] = cookies
            }
        }
    }

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        synchronized(lock) {
            val key = url.host
            val existing = store.getOrPut(key) { mutableListOf() }
            for (cookie in cookies) {
                existing.removeAll { it.name == cookie.name && it.path == cookie.path }
                existing.add(cookie)
            }
            persist(key, existing)
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        synchronized(lock) {
            val key = url.host
            val cookies = store[key] ?: return emptyList()
            val now = System.currentTimeMillis()
            val expired = cookies.filter { it.expiresAt <= now }
            if (expired.isNotEmpty()) {
                cookies.removeAll(expired.toSet())
                persist(key, cookies)
            }
            return cookies.filter { it.matches(url) }
        }
    }

    /** Clear all stored cookies (e.g., on logout). */
    fun clear() {
        synchronized(lock) {
            store.clear()
            prefs.edit().clear().apply()
        }
    }

    private fun persist(host: String, cookies: List<Cookie>) {
        val serialized = cookies.map { it.toSetCookieHeader() }.toSet()
        prefs.edit().putStringSet(host, serialized).apply()
    }

    companion object {
        private const val PREFS_NAME = "siros_auth_cookies"
    }
}

/**
 * Serialize a Cookie to a Set-Cookie header string that can be re-parsed by OkHttp.
 */
private fun Cookie.toSetCookieHeader(): String {
    val sb = StringBuilder()
    sb.append("$name=$value")
    if (expiresAt != Long.MAX_VALUE) {
        sb.append("; Expires=${java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", java.util.Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("GMT")
        }.format(java.util.Date(expiresAt))}")
    }
    if (domain.isNotEmpty()) {
        sb.append("; Domain=$domain")
    }
    sb.append("; Path=$path")
    if (secure) sb.append("; Secure")
    if (httpOnly) sb.append("; HttpOnly")
    return sb.toString()
}
