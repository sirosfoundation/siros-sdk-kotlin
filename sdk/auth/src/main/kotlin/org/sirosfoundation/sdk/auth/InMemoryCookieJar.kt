// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.sirosfoundation.sdk.auth

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl

/**
 * Simple in-memory cookie jar for OkHttp.
 *
 * The Authorization Server uses session cookies for authentication after
 * a successful passkey login/register. This cookie jar stores them in memory
 * so that subsequent requests (token endpoint, logout) include the session cookie.
 */
class InMemoryCookieJar : CookieJar {
    private val store = mutableMapOf<String, MutableList<Cookie>>()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        val key = url.host
        val existing = store.getOrPut(key) { mutableListOf() }
        for (cookie in cookies) {
            existing.removeAll { it.name == cookie.name && it.path == cookie.path }
            existing.add(cookie)
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val key = url.host
        val cookies = store[key] ?: return emptyList()
        val now = System.currentTimeMillis() / 1000
        cookies.removeAll { it.expiresAt / 1000 <= now }
        return cookies.filter { it.matches(url) }
    }

    /** Clear all stored cookies. */
    fun clear() {
        store.clear()
    }
}
