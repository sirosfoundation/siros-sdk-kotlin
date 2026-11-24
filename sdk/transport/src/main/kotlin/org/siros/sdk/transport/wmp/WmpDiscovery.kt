package org.siros.sdk.transport.wmp

/**
 * Where the well-known configuration of a domain-based WMP identifier is
 * found (WMP Core 7.5.1): a host and, for a tenant of a host that serves
 * several providers, the tenant's path.
 *
 * @property host the host, with its port when the identifier names one
 * @property tenantPath empty for the whole host; otherwise starts with `/`
 *   and has no trailing `/`
 */
data class WmpDiscoveryBase(val host: String, val tenantPath: String) {

    /**
     * The URL of the configuration: the well-known segment inserted between
     * the host and the tenant path, as RFC 8414 Section 3.1 does.
     */
    val wellKnownUrl: String
        get() = "https://$host/.well-known/wmp-configuration$tenantPath"

    /** The base as the `https` URL a configuration carries in `discovery_base`. */
    val url: String
        get() = "https://$host$tenantPath"

    /**
     * Whether a configuration that carries [discoveryBase] describes this
     * base. A configuration for a tenant path must name the base; one for a
     * whole host may leave it out (`null`).
     */
    fun isDescribedBy(discoveryBase: String?): Boolean {
        if (discoveryBase.isNullOrEmpty()) return tenantPath.isEmpty()
        // The declared base is compared as written: a trailing `/` is not
        // the base, only an identifier's path is trimmed.
        if (discoveryBase.endsWith('/')) return false
        // The scheme compares case-insensitively, like the host.
        val scheme = "https:"
        val normalized =
            if (discoveryBase.startsWith(scheme, ignoreCase = true)) {
                scheme + discoveryBase.substring(scheme.length)
            } else {
                discoveryBase
            }
        val got = ofUrl(normalized) ?: return false
        return got.host.equals(host, ignoreCase = true) && got.tenantPath == tenantPath
    }

    companion object {
        private val HOST = Regex(
            "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*(:\\d{1,5})?$",
            RegexOption.IGNORE_CASE,
        )
        private val IPV6_HOST = Regex("^\\[[0-9a-f:.]+](:\\d{1,5})?$", RegexOption.IGNORE_CASE)

        /**
         * The discovery base of an identifier, or `null` when it has none.
         *
         * ```
         * x509:san:dns:example.com                -> example.com
         * https://example.com/tenant1             -> example.com, /tenant1
         * x509:san:uri:https://example.com/tenant -> example.com, /tenant
         * did:web:example.com                     -> example.com
         * ```
         *
         * A `did:web` identifier with a path has none: the did:web method
         * resolves it through its DID Document, whose `WMPMessaging` service
         * names the endpoint (WMP Core 7.5.4). An identifier with a query, a
         * fragment, userinfo or a `.` or `..` path segment has none either.
         */
        fun of(identifier: String): WmpDiscoveryBase? = when {
            identifier.startsWith("x509:san:dns:") ->
                ofHost(identifier.removePrefix("x509:san:dns:"))
            identifier.startsWith("x509:san:uri:") ->
                ofUrl(identifier.removePrefix("x509:san:uri:"))
            identifier.startsWith("https://") -> ofUrl(identifier)
            identifier.startsWith("did:web:") -> {
                val parts = identifier.removePrefix("did:web:").split(":")
                if (parts.size == 1) percentDecode(parts[0])?.let(::ofHost) else null
            }
            else -> null
        }

        private fun ofHost(host: String): WmpDiscoveryBase? =
            if (host.length <= 259 && (HOST.matches(host) || IPV6_HOST.matches(host))) {
                WmpDiscoveryBase(host, "")
            } else {
                null
            }

        /**
         * The base of an `https` URL, read from the string as written: a URL
         * parser would resolve dot segments, and the identifier is what the
         * tenant path is compared with.
         */
        private fun ofUrl(raw: String): WmpDiscoveryBase? {
            if (!raw.startsWith("https://")) return null
            if (raw.any { it == '?' || it == '#' || it == '\\' || it.isWhitespace() }) return null
            val rest = raw.removePrefix("https://")
            val slash = rest.indexOf('/')
            val base = ofHost(if (slash < 0) rest else rest.substring(0, slash)) ?: return null
            val tenantPath = if (slash < 0) "" else rest.substring(slash).trimEnd('/')
            for (segment in tenantPath.split('/')) {
                val decoded = percentDecode(segment) ?: return null
                if (decoded == "." || decoded == "..") return null
            }
            return WmpDiscoveryBase(base.host, tenantPath)
        }

        /** Percent-decodes a path segment; `null` when an escape is malformed. */
        private fun percentDecode(s: String): String? {
            if ('%' !in s) return s
            val out = java.io.ByteArrayOutputStream()
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c == '%') {
                    if (i + 2 >= s.length) return null
                    val hi = Character.digit(s[i + 1], 16)
                    val lo = Character.digit(s[i + 2], 16)
                    if (hi < 0 || lo < 0) return null
                    out.write(hi * 16 + lo)
                    i += 3
                } else {
                    out.write(c.toString().toByteArray(Charsets.UTF_8))
                    i++
                }
            }
            return out.toString(Charsets.UTF_8.name())
        }
    }
}
