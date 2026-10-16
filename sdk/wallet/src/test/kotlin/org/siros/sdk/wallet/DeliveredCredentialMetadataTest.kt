package org.siros.sdk.wallet

import com.upokecenter.cbor.CBORObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.transport.CredentialResponseMetadataEntry
import org.siros.sdk.transport.engine.CredentialResult
import org.siros.sdk.wallet.NymTestCredentials as N

class DeliveredCredentialMetadataTest {

    private val type = WalletConfig.DEFAULT_SECRET_SEED_METADATA_TYPE

    private fun seedEntry(value: JsonElement = JsonPrimitive(N.seedHex), t: String = type) =
        CredentialResponseMetadataEntry(t, value)

    private fun result(
        entries: List<CredentialResponseMetadataEntry>?,
        encrypted: Boolean = true,
    ) = CredentialResult(
        format = "dc+sd-jwt",
        credential = "x",
        credentialMetadata = entries,
        credentialMetadataEncryptedResponse = encrypted,
    )

    private fun check(
        entries: List<CredentialResponseMetadataEntry>?,
        credential: String = N.sdJwt(),
        format: String = "dc+sd-jwt",
        encrypted: Boolean = true,
        seedType: String = type,
        canStore: Boolean = true,
    ) = DeliveredCredentialMetadata.check(format, credential, result(entries, encrypted), seedType, canStore)

    private fun assertRefused(reason: DeliveredMetadataRefusal, v: DeliveredMetadataVerdict) {
        assertTrue("expected $reason but was $v", v is DeliveredMetadataVerdict.Refuse)
        assertEquals(reason, (v as DeliveredMetadataVerdict.Refuse).reason)
    }

    @Test
    fun noMetadataIsNone() {
        assertSame(DeliveredMetadataVerdict.None, check(null))
        assertSame(DeliveredMetadataVerdict.None, check(emptyList()))
    }

    @Test
    fun matchingSeedIsAcceptedForSdJwtAndMdoc() {
        val other = CredentialResponseMetadataEntry("other", buildJsonObject { put("k", JsonNull) })
        for ((format, cred) in listOf("dc+sd-jwt" to N.sdJwt(), "mso_mdoc" to N.mdoc())) {
            val v = check(listOf(seedEntry(), other), cred, format)
            assertTrue(format, v is DeliveredMetadataVerdict.Accept)
            val entries = (v as DeliveredMetadataVerdict.Accept).entries
            // Every entry, in order, exactly as received.
            assertEquals(2, entries.size)
            assertEquals(JsonPrimitive(type), (entries[0] as kotlinx.serialization.json.JsonObject)["type"])
            assertEquals(JsonPrimitive(N.seedHex), (entries[0] as kotlinx.serialization.json.JsonObject)["value"])
            assertEquals(buildJsonObject { put("k", JsonNull) }, (entries[1] as kotlinx.serialization.json.JsonObject)["value"])
        }
    }

    @Test
    fun metadataWithoutTheSeedTypeIsStoredEvenOverPlainJson() {
        val v = check(listOf(CredentialResponseMetadataEntry("other", JsonPrimitive("x"))), encrypted = false)
        assertTrue(v is DeliveredMetadataVerdict.Accept)
    }

    @Test
    fun aSeedOutsideAnEncryptedResponseIsRefused() {
        assertRefused(DeliveredMetadataRefusal.NOT_ENCRYPTED, check(listOf(seedEntry()), encrypted = false))
    }

    @Test
    fun malformedSeedValuesAreRefused() {
        val bad = listOf<JsonElement>(
            JsonPrimitive(N.seedHex.dropLast(2)),
            JsonPrimitive(N.seedHex + "00"),
            JsonPrimitive(N.seedHex.uppercase()),
            JsonPrimitive("0x" + N.seedHex.drop(2)),
            JsonPrimitive(" " + N.seedHex.drop(1)),
            JsonPrimitive("zz" + N.seedHex.drop(2)),
            JsonPrimitive(5),
            JsonNull,
            JsonArray(listOf(JsonPrimitive(N.seedHex))),
        )
        for (value in bad) assertRefused(DeliveredMetadataRefusal.MALFORMED, check(listOf(seedEntry(value))))
        assertRefused(DeliveredMetadataRefusal.MALFORMED, check(listOf(CredentialResponseMetadataEntry("", JsonPrimitive("x")))))
    }

    @Test
    fun aDuplicateSeedEntryIsRefused() {
        assertRefused(DeliveredMetadataRefusal.DUPLICATE, check(listOf(seedEntry(), seedEntry())))
    }

    @Test
    fun anSdJwtWithoutAUsableSscIsRefused() {
        val bad = listOf(
            N.sdJwt(sscValues = emptyList()),
            N.sdJwt(sscValues = listOf(N.hex(N.goodSsc), N.hex(N.goodSsc))),
            N.sdJwt(sscInClear = N.hex(N.goodSsc), sscValues = emptyList()),
            N.sdJwt(sscInClear = N.hex(N.goodSsc)),
            N.sdJwt(referenceInSd = false),
            N.sdJwt(sscValues = listOf(N.hex(N.goodSsc).dropLast(2))),
            N.sdJwt(sscValues = listOf(N.hex(N.goodSsc) + "00")),
            N.sdJwt(sscValues = listOf(N.hex(N.goodSsc).uppercase())),
            "not-a-jwt",
        )
        for (cred in bad) assertRefused(DeliveredMetadataRefusal.NO_COMMITMENT, check(listOf(seedEntry()), cred))
    }

    @Test
    fun anMdocWithoutAUsableSscIsRefused() {
        val bad = listOf(
            N.mdoc(sscValues = emptyList()),
            N.mdoc(sscValues = listOf(N.bstr(N.goodSsc), N.bstr(N.goodSsc))),
            N.mdoc(sscValues = listOf(N.bstr(N.goodSsc.copyOf(31)))),
            N.mdoc(sscValues = listOf(N.text(N.hex(N.goodSsc)))),
            N.mdoc(namespace = "org.example.other"),
            "!!not-base64!!",
        )
        for (cred in bad) assertRefused(DeliveredMetadataRefusal.NO_COMMITMENT, check(listOf(seedEntry()), cred, "mso_mdoc"))
    }

    @Test
    fun aSeedThatDoesNotOpenTheSscIsRefused() {
        assertRefused(DeliveredMetadataRefusal.MISMATCH, check(listOf(seedEntry()), N.sdJwt(sscValues = listOf(N.hex(N.wrongSsc)))))
        assertRefused(
            DeliveredMetadataRefusal.MISMATCH,
            check(listOf(seedEntry()), N.mdoc(sscValues = listOf(N.bstr(N.wrongSsc))), "mso_mdoc"),
        )
    }

    @Test
    fun aFormatWithoutACommitmentIsRefused() {
        assertRefused(DeliveredMetadataRefusal.NO_COMMITMENT, check(listOf(seedEntry()), "the.jwp.here", "jwp"))
    }

    @Test
    fun aKeystoreThatCannotHoldTheSecretRefuses() {
        assertRefused(DeliveredMetadataRefusal.NO_STORAGE, check(listOf(seedEntry()), canStore = false))
    }

    @Test
    fun onlyTheConfiguredTypeIsInterpreted() {
        // The default type is just another entry once a different type is configured.
        val v = check(listOf(seedEntry(JsonPrimitive("not hex"))), encrypted = false, seedType = "example.other_seed")
        assertTrue(v is DeliveredMetadataVerdict.Accept)
        // And the configured one is checked.
        assertRefused(
            DeliveredMetadataRefusal.NOT_ENCRYPTED,
            check(listOf(seedEntry(t = "example.other_seed")), encrypted = false, seedType = "example.other_seed"),
        )
        assertTrue(check(listOf(seedEntry(t = "example.other_seed")), seedType = "example.other_seed") is DeliveredMetadataVerdict.Accept)
    }

    @Test
    fun theSeedTypeMustNotBeBlank() {
        try {
            WalletConfig(backendUrl = "https://wallet.example.com", secretSeedMetadataType = " ")
            org.junit.Assert.fail("accepted a blank type")
        } catch (_: IllegalArgumentException) {
        }
    }
}
