package org.siros.sdk.transport.wmp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The discovery base and well-known URL rules of WMP Core 7.5.1. */
class WmpDiscoveryBaseTest {

    private val wk = "/.well-known/wmp-configuration"

    @Test
    fun the_well_known_url_inserts_the_segment_before_the_tenant_path() {
        // The rows of the well-known URL table of the specification.
        val rows = listOf(
            "x509:san:dns:example.com" to "https://example.com$wk",
            "https://example.com" to "https://example.com$wk",
            "https://example.com/" to "https://example.com$wk",
            "https://example.com/tenant1" to "https://example.com$wk/tenant1",
            "https://example.com:8443/tenants/acme/" to "https://example.com:8443$wk/tenants/acme",
            "x509:san:uri:https://example.com/tenant1" to "https://example.com$wk/tenant1",
            "did:web:example.com" to "https://example.com$wk",
            "did:web:example.com%3A8443" to "https://example.com:8443$wk",
        )
        for ((identifier, url) in rows) {
            val base = WmpDiscoveryBase.of(identifier)
            assertNotNull(identifier, base)
            assertEquals(identifier, url, base!!.wellKnownUrl)
        }
    }

    @Test
    fun identifiers_without_a_discovery_base() {
        val none = listOf(
            "did:web:example.com:tenant1",
            "did:key:z6Mkf5rGMoatrSj1f3JWKc",
            "https://example.com/tenant1?x=1",
            "https://example.com/tenant1?",
            "https://example.com/tenant1#frag",
            "https://user@example.com/tenant1",
            "https://example.com/a/../b",
            "https://example.com/a/./b",
            "https://example.com/a/%2e%2e/b",
            "https://example.com/a/%zz/b",
            "https://example.com\\@evil.example/",
            "x509:san:uri:https://example.com/t?x=1",
            "x509:san:uri:http://example.com/t",
            "x509:san:dns:example.com/path",
            "http://example.com/tenant1",
            "opaque",
        )
        for (identifier in none) {
            assertNull(identifier, WmpDiscoveryBase.of(identifier))
        }
    }

    @Test
    fun a_tenant_document_must_name_the_tenant() {
        val tenant = WmpDiscoveryBase.of("https://example.com/tenants/acme")!!
        assertTrue(tenant.isDescribedBy("https://example.com/tenants/acme"))
        assertTrue(tenant.isDescribedBy("HTTPS://EXAMPLE.com/tenants/acme"))
        assertFalse("trailing slash", tenant.isDescribedBy("https://example.com/tenants/acme/"))
        assertFalse("absent", tenant.isDescribedBy(null))
        assertFalse("empty", tenant.isDescribedBy(""))
        assertFalse("the host's", tenant.isDescribedBy("https://example.com"))
        assertFalse("another tenant's", tenant.isDescribedBy("https://example.com/tenants/other"))
        assertFalse("another host's", tenant.isDescribedBy("https://evil.example/tenants/acme"))
        assertFalse("another port's", tenant.isDescribedBy("https://example.com:8443/tenants/acme"))
        assertFalse("path case", tenant.isDescribedBy("https://example.com/tenants/ACME"))
    }

    @Test
    fun a_host_document_may_leave_the_base_out_but_not_name_another() {
        val host = WmpDiscoveryBase.of("x509:san:dns:example.com")!!
        assertTrue(host.isDescribedBy(null))
        assertTrue(host.isDescribedBy("https://example.com"))
        assertFalse("trailing slash", host.isDescribedBy("https://example.com/"))
        assertFalse(host.isDescribedBy("https://example.com/tenant1"))
        assertFalse(host.isDescribedBy("https://evil.example"))
    }
}
