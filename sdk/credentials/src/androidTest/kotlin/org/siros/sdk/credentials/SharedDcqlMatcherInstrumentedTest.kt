// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The shared DCQL engine, running on a device.
 *
 * On a device because the engine is native: a JVM test cannot load the library
 * at all, so it would exercise only the `null` path this class returns when the
 * engine is unavailable - which is precisely the path that must not be mistaken
 * for a real answer.
 */
@RunWith(AndroidJUnit4::class)
class SharedDcqlMatcherInstrumentedTest {

    private fun query(json: String): JsonObject =
        Json.parseToJsonElement(json) as JsonObject

    private fun mdoc(id: Long): StoredCredential = StoredCredential(
        id = id,
        format = "mso_mdoc",
        raw = "",
        metadata = null,
        batchId = 1L,
        instanceId = 0,
    )

    /** The engine loads and answers, rather than reporting itself unavailable. */
    @Test
    fun the_engine_runs_on_a_real_device() {
        val ids = SharedDcqlMatcher.matchedCredentialIds(
            query("""{"credentials":[{"id":"q","format":"mso_mdoc","meta":{}}]}"""),
            emptyList(),
        )
        assertNotNull("null means the native library did not load, not that nothing matched", ids)
        assertTrue(ids!!.isEmpty())
    }

    /**
     * ISO namespaces keep their dots; only the element identifier splits off.
     *
     * Splitting on the first dot yields namespace `org`, which matches nothing
     * while looking entirely reasonable.
     */
    @Test
    fun mdoc_claim_keys_split_on_the_last_dot() {
        assertEquals(
            listOf("org.iso.18013.5.1", "family_name"),
            SharedDcqlMatcher.splitClaimKey("mso_mdoc", "org.iso.18013.5.1.family_name"),
        )
        assertEquals(
            listOf("given_name"),
            SharedDcqlMatcher.splitClaimKey("dc+sd-jwt", "given_name"),
        )
    }

    /**
     * A credential with no claims cannot satisfy a query that asks for one.
     *
     * This is the §6.4.1 rule the built-in matcher does not apply, and the
     * difference the two will report against each other until the switch is
     * made deliberately.
     */
    @Test
    fun a_requested_claim_the_credential_lacks_prevents_a_match() {
        val ids = SharedDcqlMatcher.matchedCredentialIds(
            query(
                """{"credentials":[{"id":"q","format":"mso_mdoc","meta":{},
                     "claims":[{"path":["org.iso.18013.5.1","age_over_18"]}]}]}"""
            ),
            listOf(mdoc(1L)),
        )
        assertEquals(emptyList<Long>(), ids)
    }

    /** A malformed query is "no answer", never a crash across the boundary. */
    @Test
    fun a_malformed_query_reports_no_answer_rather_than_crashing() {
        assertEquals(null, SharedDcqlMatcher.matchedCredentialIds(query("""{"credentials":42}"""), emptyList()))
    }
}
