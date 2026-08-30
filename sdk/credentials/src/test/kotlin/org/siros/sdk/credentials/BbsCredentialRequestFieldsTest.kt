package org.siros.sdk.credentials

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.zk_cred_bbs.BbsSuiteId

/**
 * The encoding contract at the boundary between
 * [ZkIssuancePreparation.credentialRequestFields] and the transport.
 *
 * The map's values are pre-encoded JSON *strings*, deliberately: they are
 * covered by the commitment proof, and re-encoding a value a signature
 * covers is how the two ends stop agreeing about what was signed. The wallet
 * therefore parses them rather than building them again — which only works if
 * every value really is well-formed JSON, including for claim names the
 * wallet did not choose.
 *
 * These construct the preparation directly rather than through `prepare()`,
 * so they run on the JVM without the native library: the encoding under test
 * is pure Kotlin either way.
 */
class BbsCredentialRequestFieldsTest {

    private val json = Json

    private fun preparation(pointers: List<String>) = BbsIssuancePreparation(
        suiteId = BbsSuiteId.SCHNORR,
        commitmentWithProof = ByteArray(48) { it.toByte() },
        holderPointers = pointers,
        committedMessages = pointers.map { it.toByteArray() },
        secretProverBlind = ByteArray(32) { 7 },
        keybindPublicKeys = emptyList(),
    )

    @Test
    fun everyFieldIsWellFormedJson() {
        val fields = preparation(listOf("/device_pin_hash", "/recovery_secret")).credentialRequestFields

        assertEquals(
            setOf(BbsIssuanceParticipant.COMMITMENT_FIELD, BbsIssuanceParticipant.POINTERS_FIELD),
            fields.keys,
        )
        fields.forEach { (member, encoded) ->
            // Throws if it is not parseable, which is the assertion.
            json.parseToJsonElement(encoded)
            assertTrue("$member must not be empty", encoded.isNotEmpty())
        }
    }

    @Test
    fun theCommitmentIsBase64UrlWithoutPadding() {
        val commitment = json
            .parseToJsonElement(
                preparation(listOf("/a")).credentialRequestFields
                    .getValue(BbsIssuanceParticipant.COMMITMENT_FIELD),
            )
            .jsonPrimitive.content

        assertTrue("must be base64url, not base64: $commitment", commitment.none { it == '+' || it == '/' })
        assertTrue("must be unpadded: $commitment", !commitment.endsWith("="))
    }

    @Test
    fun pointersSurviveInOrder() {
        val pointers = listOf("/z_last", "/a_first", "/m_middle")
        val decoded = json
            .parseToJsonElement(
                preparation(pointers).credentialRequestFields
                    .getValue(BbsIssuanceParticipant.POINTERS_FIELD),
            )
            .jsonArray

        assertEquals(pointers, decoded.map { it.jsonPrimitive.content })
    }

    /**
     * A claim name the wallet did not choose must not be able to break the
     * encoding.
     *
     * The pointers come from the holder's own claims object, which a host app
     * may build from data it did not author. A name carrying a quote or a
     * control character would, without escaping, produce a member the
     * transport cannot parse — or, worse, one it parses into something other
     * than what the commitment covers.
     */
    @Test
    fun aHostileClaimNameIsEscapedRatherThanBreakingTheEncoding() {
        val nasty = listOf("""/he said "hi"""", """/back\slash""", "/new\nline", "/tab\there")

        val decoded = json
            .parseToJsonElement(
                preparation(nasty).credentialRequestFields
                    .getValue(BbsIssuanceParticipant.POINTERS_FIELD),
            )

        assertTrue(decoded is JsonArray)
        assertEquals(nasty, (decoded as JsonArray).map { it.jsonPrimitive.content })
    }
}
