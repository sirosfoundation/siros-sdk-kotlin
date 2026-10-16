// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Test

class CredentialSecretSeedSourceTest {
    private val type = "org.siros.NS.secret_seed"
    private val hex = NymTestCredentials.seedHex

    private fun entry(t: String, v: kotlinx.serialization.json.JsonElement) =
        buildJsonObject { put("type", JsonPrimitive(t)); put("value", v) }

    private fun source(md: JsonArray?) = KeystoreSecretSeedSource(type) { md }

    @Test
    fun noneHoldsNothing() = runTest {
        assertNull(CredentialSecretSeedSource.NONE.secretSeed(1L))
        assertNull(CredentialSecretSeedSource.NONE.secretSeed(Long.MAX_VALUE))
    }

    @Test
    fun readsTheDeliveredSeedAsAFreshCopyEachTime() = runTest {
        val s = source(buildJsonArray { add(entry("other", JsonPrimitive("x"))); add(entry(type, JsonPrimitive(hex))) })
        val a = s.secretSeed(1L)!!
        val b = s.secretSeed(1L)!!
        assertArrayEquals(NymTestCredentials.seed, a)
        assertNotSame(a, b)
        a.fill(0)
        assertArrayEquals("zeroing one copy must not affect the next", NymTestCredentials.seed, s.secretSeed(1L))
    }

    @Test
    fun failsClosed() = runTest {
        assertNull(source(null).secretSeed(1L))
        assertNull(source(JsonArray(emptyList())).secretSeed(1L))
        assertNull(source(buildJsonArray { add(entry("other", JsonPrimitive(hex))) }).secretSeed(1L))
        assertNull(source(buildJsonArray { add(entry(type, JsonPrimitive(hex))); add(entry(type, JsonPrimitive(hex))) }).secretSeed(1L))
        for (bad in listOf(hex.dropLast(2), hex.uppercase(), hex + "00", "0x$hex", "")) {
            assertNull(bad, source(buildJsonArray { add(entry(type, JsonPrimitive(bad))) }).secretSeed(1L))
        }
        assertNull(source(buildJsonArray { add(entry(type, JsonPrimitive(5))) }).secretSeed(1L))
        assertNull(source(buildJsonArray { add(JsonPrimitive("junk")) }).secretSeed(1L))
    }
}
