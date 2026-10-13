package org.siros.sdk.keystore

import io.mockk.mockk
import java.io.File
import javax.crypto.SecretKey
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.credentials.KeystoreException

/**
 * [PrivateSeed] against `spec/private-seed-vectors.json` (fixed roots; expected values from
 * `tools/gen_private_seed_vectors.py`, see `spec/private-seed-vectors.md`), plus the keystore's own contract.
 */
class PrivateSeedTest {
    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private fun JsonObject.str(key: String) = this[key]!!.jsonPrimitive.content

    /** A fixed root, using the keystore's own HKDF. */
    private class FixedRoot(private val root: ByteArray) : RootSecret {
        override fun deriveSecret(info: ByteArray, length: Int) = EncryptedContainer.hkdfSha256(root, ByteArray(0), info, length)
    }

    private val vectors: List<JsonObject> by lazy {
        // Gradle runs unit tests with the module directory as the working directory.
        val f = File("../../spec/private-seed-vectors.json")
        require(f.isFile) { "vector file not found at ${f.absolutePath}" }
        Json.parseToJsonElement(f.readText()).jsonObject["vectors"]!!.jsonArray.map { it.jsonObject }
    }

    @Test
    fun `every vector gives its seed and psc`() {
        assertTrue(vectors.size >= 7)
        for (v in vectors) {
            val seeds = PrivateSeed(FixedRoot(hex(v.str("root_hex"))))
            val type = v.str("credential_type")
            assertEquals(v.str("name"), v.str("seed_hex"), seeds.derive(type).toHex())
            assertEquals(v.str("name"), v.str("psc_hex"), seeds.psc(type).toHex())
            assertTrue(seeds.matchesCommitment(type, hex(v.str("psc_hex"))))
        }
    }

    @Test
    fun `seed is 16 bytes, stable per type and distinct across types`() {
        val seeds = PrivateSeed(FixedRoot(ByteArray(32) { it.toByte() }))
        val a = seeds.derive("type-a")
        assertEquals(16, a.size)
        assertArrayEquals(a, seeds.derive("type-a"))
        assertNotEquals(a.toHex(), seeds.derive("type-b").toHex())
        assertEquals(32, seeds.psc("type-a").size)
    }

    @Test
    fun `matchesCommitment fails closed`() {
        val seeds = PrivateSeed(FixedRoot(ByteArray(32) { it.toByte() }))
        val psc = seeds.psc("t")
        assertTrue(seeds.matchesCommitment("t", psc))
        assertFalse(seeds.matchesCommitment("other", psc))
        assertFalse(seeds.matchesCommitment("t", psc.copyOf().also { it[31] = (it[31] + 1).toByte() }))
        assertFalse(seeds.matchesCommitment("t", psc.copyOf(31)))
        assertFalse(seeds.matchesCommitment("t", psc + 0))
        assertFalse(seeds.matchesCommitment("t", ByteArray(0)))
        assertFalse(seeds.matchesCommitment("t", ByteArray(32)))
    }

    private val prf = ByteArray(32) { it.toByte() }
    private val salt = ByteArray(32) { (it + 0x10).toByte() }
    private val info = "SIROS Wallet PRF".toByteArray()

    @Test
    fun `a locked keystore throws and derives nothing`() = runTest {
        val locked = JweKeystore()
        val seeds = PrivateSeed(locked)
        assertThrows(KeystoreException::class.java) { seeds.psc("t") }
        assertThrows(KeystoreException::class.java) { seeds.matchesCommitment("t", ByteArray(32)) }
        assertThrows(KeystoreException::class.java) { seeds.derive("t") }

        val unlocked = JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }
        val unlockedSeeds = PrivateSeed(unlocked)
        unlockedSeeds.psc("t")
        unlocked.lock()
        assertThrows(KeystoreException::class.java) { unlockedSeeds.psc("t") }
    }

    @Test
    fun `the seed follows mainKey - stable across reopen, new for a new container`() = runTest {
        val first = JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }
        val before = PrivateSeed(first).psc("t")
        val reopened = JweKeystore().also { it.unlock(prf, first.exportEncryptedContainer(), salt, info) }
        assertArrayEquals(before, PrivateSeed(reopened).psc("t"))
        // Same PRF output, new container, new random mainKey: a seed derived from the PRF output would not change.
        val other = JweKeystore().also { it.unlock(prf, ByteArray(0), salt, info) }
        assertNotEquals(before.toHex(), PrivateSeed(other).psc("t").toHex())
    }

    @Test
    fun `no public keystore member returns key material`() {
        for (cls in listOf(JweKeystore::class.java, WscdKeystoreAdapter::class.java)) {
            for (m in cls.methods) {
                assertFalse("${cls.simpleName}.${m.name}", SecretKey::class.java.isAssignableFrom(m.returnType))
            }
        }
    }

    @Test
    fun `the WSCD adapter exposes the same root`() {
        val adapter = WscdKeystoreAdapter(mockk(relaxed = true))
        assertTrue(adapter is RootSecret)
        assertThrows(KeystoreException::class.java) { PrivateSeed(adapter).psc("t") }
    }

    @Test
    fun `the label is the documented one`() {
        assertEquals("org.siros.private_seed/v1", PrivateSeed.LABEL)
        assertEquals(16, PrivateSeed.SEED_BYTES)
    }
}
