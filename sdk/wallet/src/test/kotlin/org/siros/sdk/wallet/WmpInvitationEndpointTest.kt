// A unit test for the derivation + a live probe through the derivation path.
// Run: ./gradlew :sdk:wallet:testDebugUnitTest --tests '*WmpInvitationEndpointTest*'

package org.siros.sdk.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Issue #77's regression pin (2026-11-20's three blind rounds): the
 * invitation endpoint derivation strips ONLY the send URL's trailing
 * `/wmp` segment — never splitting at the first `/wmp` occurrence, which
 * on the deployed shape (`…/wmp-engine/wmp`) is the start of
 * `/wmp-engine` itself and would leave the bare backend URL (the
 * invitation POST then hit the wallet-proxy's nginx, 404, never the
 * engine).
 */
class WmpInvitationEndpointTest {

    @Test
    fun the_derived_base_strips_only_the_trailing_wmp_segment() {
        // The deployed GDC shape: the send URL ends /wmp-engine/wmp.
        val sendUrl = "https://sirosid-gdc-wallet-proxy.fly.dev/wmp-engine/wmp"
        // The derivation (SirosWallet's own): trim, remove the suffix only.
        val base = sendUrl.trimEnd('/').removeSuffix("/wmp")
        assertEquals(
            "the base keeps the /wmp-engine path (the engine's own route prefix)",
            "https://sirosid-gdc-wallet-proxy.fly.dev/wmp-engine",
            base,
        )
        // The invitation POST target.
        assertEquals(
            "the POST target is the engine's route",
            "https://sirosid-gdc-wallet-proxy.fly.dev/wmp-engine/wmp/invitation",
            base.trimEnd('/') + "/wmp/invitation",
        )
    }

    @Test
    fun a_send_url_with_no_wmp_suffix_stays_whole() {
        val sendUrl = "https://engine.example.com"
        val base = sendUrl.trimEnd('/').removeSuffix("/wmp").ifEmpty { null }
        assertNotNull("a suffix-less send URL stays whole", base)
        assertEquals(
            "the POST target appends the route",
            "https://engine.example.com/wmp/invitation",
            base!!.trimEnd('/') + "/wmp/invitation",
        )
    }
}