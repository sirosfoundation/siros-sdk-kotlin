// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.dcapi

import androidx.credentials.registry.provider.ClearCredentialRegistryRequest
import androidx.credentials.registry.provider.RegistryManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Does the platform actually accept a matcher we supply ourselves?
 *
 * This is the riskiest single assumption in the whole custom-matcher plan.
 * Everything else - the DCQL engine, the configurable profile, the ZK format -
 * is wasted work if Play Services silently refuses a wallet-supplied matcher.
 *
 * It runs on a device rather than in Robolectric because there is no way to
 * fake the answer: the thing under test is Play Services' own acceptance of
 * our bytes. It needs no wallet login and no credentials, which is what makes
 * it automatable when the full picker flow is not.
 *
 * What this does NOT prove: that the module runs and emits an entry. That
 * needs a verifier making a real request, and a user to look at the picker.
 */
@RunWith(AndroidJUnit4::class)
class SirosMatcherRegistryInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /** The matcher asset ships in the APK and is readable at runtime. */
    @Test
    fun matcher_asset_is_bundled_and_is_a_wasm_module() {
        val wasm = context.assets.open("matcher.wasm").use { it.readBytes() }

        // WebAssembly magic: \0asm followed by version 1. A truncated or
        // text-mangled asset would still "load" as bytes and then fail deep
        // inside Play Services with nothing useful in the log.
        assertTrue("matcher.wasm is too small to be a module", wasm.size > 1024)
        assertEquals(0x00.toByte(), wasm[0])
        assertEquals('a'.code.toByte(), wasm[1])
        assertEquals('s'.code.toByte(), wasm[2])
        assertEquals('m'.code.toByte(), wasm[3])
        assertEquals(0x01.toByte(), wasm[4])
    }

    /** The Phase 1 blob is well-formed JSON the matcher can report on. */
    @Test
    fun credential_blob_is_well_formed() {
        val blob = SirosMatcherRegistry.credentialBlob(emptyList())
        val parsed = JSONObject(String(blob, Charsets.UTF_8))
        assertEquals(0, parsed.getInt("version"))
        assertEquals(0, parsed.getJSONArray("credentials").length())
    }

    /**
     * The real question: Play Services accepts a registration carrying our own
     * matcher bytes.
     *
     * A rejection surfaces as an exception from
     * [RegistryManager.registerCredentials], so completing without throwing is
     * the assertion. Registering an empty credential set is deliberate - this
     * is about whether the matcher is accepted, not about what it would match.
     */
    @Test
    fun play_services_accepts_our_matcher() = runTest {
        val registry = SirosMatcherRegistry.create(context, emptyList())

        assertTrue("matcher bytes did not reach the registry", registry.matcher.size > 1024)

        try {
            // Throws on rejection; there is no success value to inspect.
            RegistryManager.create(context).registerCredentials(registry)
        } finally {
            // The registry is device-global and outlives the test process, so
            // leaving one behind would change what a later run - or another
            // suite, or the app itself - starts from.
            RegistryManager.create(context)
                .clearCredentialRegistry(ClearCredentialRegistryRequest(true))
        }
    }
}
