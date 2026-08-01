// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * `coilLogoModel` works around Coil's default components not decoding a
 * `data:` URI *string* on their own (they only handle raw byte arrays, via
 * the built-in `ByteArrayMapper` -> `ByteBufferFetcher`) - issuer-published
 * logos are frequently embedded this way (e.g.
 * geneva2026.mdoc.online's `credential_metadata.display[].logo.uri`), which
 * silently failed to render before this fix.
 */
class CredentialCardTest {

    @Test
    fun `decodes a base64 data URI into raw bytes`() {
        val payload = "hello logo bytes".toByteArray(Charsets.UTF_8)
        val encoded = java.util.Base64.getEncoder().encodeToString(payload)
        val uri = "data:image/png;base64,$encoded"

        val model = coilLogoModel(uri)

        assertArrayEquals(payload, model as ByteArray)
    }

    @Test
    fun `leaves an http url unchanged`() {
        val uri = "https://issuer.example.com/logo.png"
        assertEquals(uri, coilLogoModel(uri))
    }

    @Test
    fun `leaves a non-base64 data URI unchanged`() {
        // e.g. a URL-encoded (not base64) data URI - not what we're built to unwrap.
        val uri = "data:image/svg+xml,%3Csvg%2F%3E"
        assertEquals(uri, coilLogoModel(uri))
    }

    @Test
    fun `falls back to the original string when the payload is not valid base64`() {
        val uri = "data:image/png;base64,not-valid-base64!!!"
        assertEquals(uri, coilLogoModel(uri))
    }
}
