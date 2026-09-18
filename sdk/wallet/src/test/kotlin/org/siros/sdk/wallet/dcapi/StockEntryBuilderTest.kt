// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import org.junit.Assert.assertEquals
import org.junit.Test

class StockEntryBuilderTest {

    @Test
    fun `splits a dotted ISO namespace and a plain element identifier`() {
        val (namespace, identifier) = StockEntryBuilder.splitMdocClaimKey(
            "org.iso.18013.5.1.family_name"
        )
        assertEquals("org.iso.18013.5.1", namespace)
        assertEquals("family_name", identifier)
    }

    @Test
    fun `splits a single-segment namespace correctly`() {
        val (namespace, identifier) = StockEntryBuilder.splitMdocClaimKey(
            "eu.europa.ec.eudi.pid.1.given_name"
        )
        assertEquals("eu.europa.ec.eudi.pid.1", namespace)
        assertEquals("given_name", identifier)
    }

    @Test
    fun `key with no dot puts everything in both halves`() {
        // Degenerate input (shouldn't happen in practice - DisplayClaim.key for
        // mdoc always has at least one dot) - substringBeforeLast/AfterLast both
        // fall back to the whole string when no delimiter is present.
        val (namespace, identifier) = StockEntryBuilder.splitMdocClaimKey("no_dot_here")
        assertEquals("no_dot_here", namespace)
        assertEquals("no_dot_here", identifier)
    }
}
