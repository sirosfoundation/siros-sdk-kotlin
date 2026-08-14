// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.MessageDigest

class ZkCircuitClientTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun manifestJson(circuitsJson: String): String = """
        {
          "manifestVersion": 1,
          "generatedAt": "2026-08-01T00:00:00Z",
          "catalog": "siros-zk-circuits",
          "circuits": [$circuitsJson],
          "next": null
        }
    """.trimIndent()

    private fun circuitJson(id: String, hash: String = "deadbeef", url: String = "/v1/artifacts/sha256/deadbeef"): String = """
        {
          "id": "$id",
          "system": "longfellow",
          "systemVersion": "1.0",
          "published": true,
          "status": "active",
          "params": {"num_attributes": 3},
          "artifact": {
            "url": "$url",
            "hash": "$hash",
            "size": 4,
            "compression": "none",
            "mediaType": "application/octet-stream"
          },
          "publishedAt": "2026-08-01T00:00:00Z"
        }
    """.trimIndent()

    // ── fetchManifest ────────────────────────────────────────────────

    @Test
    fun `fetchManifest returns the parsed manifest from the first source`() = runTest {
        val client = ZkCircuitClient(httpGet = { url ->
            if (url == "https://zk-circuits.fly.dev/v1/manifest.json") {
                manifestJson(circuitJson("longfellow-mdl-v1"))
            } else {
                null
            }
        })

        val manifest = client.fetchManifest()

        assertEquals(1, manifest?.circuits?.size)
        assertEquals("longfellow-mdl-v1", manifest?.circuits?.get(0)?.id)
        assertEquals("longfellow", manifest?.circuits?.get(0)?.system)
        assertEquals("siros-zk-circuits", manifest?.catalog)
    }

    @Test
    fun `fetchManifest defaults to a single zk-circuits fly dev source`() = runTest {
        var calledUrl: String? = null
        val client = ZkCircuitClient(httpGet = { url ->
            calledUrl = url
            null
        })

        client.fetchManifest()

        assertEquals("https://zk-circuits.fly.dev/v1/manifest.json", calledUrl)
    }

    @Test
    fun `fetchManifest falls back to the second mirror when the first fails`() = runTest {
        val calledUrls = mutableListOf<String>()
        val client = ZkCircuitClient(
            sources = listOf("https://zk-circuits.fly.dev", "https://api.circuits.siros.org"),
            httpGet = { url ->
                calledUrls.add(url)
                when (url) {
                    "https://zk-circuits.fly.dev/v1/manifest.json" -> null // first mirror down
                    "https://api.circuits.siros.org/v1/manifest.json" -> manifestJson(circuitJson("longfellow-mdl-v1"))
                    else -> null
                }
            },
        )

        val manifest = client.fetchManifest()

        assertEquals(1, manifest?.circuits?.size)
        assertEquals(listOf(
            "https://zk-circuits.fly.dev/v1/manifest.json",
            "https://api.circuits.siros.org/v1/manifest.json",
        ), calledUrls)
    }

    @Test
    fun `fetchManifest does not merge across sources - only the first success is used`() = runTest {
        // Even though the second source would also succeed with a different
        // circuit, ZkCircuitClient's mirror semantics mean only the first
        // successful source's result is returned - never merged, unlike
        // Ts11RegistryClient.
        val client = ZkCircuitClient(
            sources = listOf("https://mirror-a.example.org", "https://mirror-b.example.org"),
            httpGet = { url ->
                when (url) {
                    "https://mirror-a.example.org/v1/manifest.json" -> manifestJson(circuitJson("circuit-a"))
                    "https://mirror-b.example.org/v1/manifest.json" -> manifestJson(circuitJson("circuit-b"))
                    else -> null
                }
            },
        )

        val manifest = client.fetchManifest()

        assertEquals(1, manifest?.circuits?.size)
        assertEquals("circuit-a", manifest?.circuits?.get(0)?.id)
    }

    @Test
    fun `fetchManifest returns null when every source fails`() = runTest {
        val client = ZkCircuitClient(
            sources = listOf("https://mirror-a.example.org", "https://mirror-b.example.org"),
            httpGet = { null },
        )

        assertNull(client.fetchManifest())
    }

    @Test
    fun `fetchManifest returns null for a malformed JSON response`() = runTest {
        val client = ZkCircuitClient(httpGet = { "not valid json" })

        assertNull(client.fetchManifest())
    }

    // ── fetchCircuit ─────────────────────────────────────────────────

    @Test
    fun `fetchCircuit returns the parsed descriptor by id`() = runTest {
        val client = ZkCircuitClient(httpGet = { url ->
            if (url == "https://zk-circuits.fly.dev/v1/circuits/longfellow-mdl-v1.json") {
                circuitJson("longfellow-mdl-v1")
            } else {
                null
            }
        })

        val descriptor = client.fetchCircuit("longfellow-mdl-v1")

        assertEquals("longfellow-mdl-v1", descriptor?.id)
        assertEquals("active", descriptor?.status)
        assertEquals("deadbeef", descriptor?.artifact?.hash)
    }

    @Test
    fun `fetchCircuit falls back to the second mirror when the first fails`() = runTest {
        val client = ZkCircuitClient(
            sources = listOf("https://zk-circuits.fly.dev", "https://api.circuits.siros.org"),
            httpGet = { url ->
                when (url) {
                    "https://api.circuits.siros.org/v1/circuits/longfellow-mdl-v1.json" ->
                        circuitJson("longfellow-mdl-v1")
                    else -> null
                }
            },
        )

        val descriptor = client.fetchCircuit("longfellow-mdl-v1")

        assertEquals("longfellow-mdl-v1", descriptor?.id)
    }

    @Test
    fun `fetchCircuit returns null when every source fails`() = runTest {
        val client = ZkCircuitClient(httpGet = { null })

        assertNull(client.fetchCircuit("unknown"))
    }

    // ── downloadArtifact ─────────────────────────────────────────────

    @Test
    fun `downloadArtifact returns bytes whose sha256 matches the descriptor hash`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val client = ZkCircuitClient(
            httpGetBytes = { url ->
                if (url == "https://zk-circuits.fly.dev/v1/artifacts/sha256/$hash") bytes else null
            },
        )
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = hash, url = "/v1/artifacts/sha256/$hash"))

        val downloaded = client.downloadArtifact(circuit)

        assertTrue(bytes.contentEquals(downloaded))
    }

    @Test
    fun `downloadArtifact falls back to the second mirror when the first fails to fetch`() = runTest {
        val bytes = "circuit-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val client = ZkCircuitClient(
            sources = listOf("https://zk-circuits.fly.dev", "https://api.circuits.siros.org"),
            httpGetBytes = { url ->
                when (url) {
                    "https://api.circuits.siros.org/v1/artifacts/sha256/$hash" -> bytes
                    else -> null
                }
            },
        )
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = hash, url = "/v1/artifacts/sha256/$hash"))

        val downloaded = client.downloadArtifact(circuit)

        assertTrue(bytes.contentEquals(downloaded))
    }

    @Test
    fun `downloadArtifact throws when the downloaded bytes hash does not match`() = runTest {
        val bytes = "tampered-bytes".toByteArray()
        val client = ZkCircuitClient(
            httpGetBytes = { bytes },
        )
        val circuit = json.decodeFromString(
                ZkCircuitDescriptor.serializer(),
                circuitJson("longfellow-mdl-v1", hash = "0000000000000000000000000000000000000000000000000000000000000000"),
            )

        try {
            client.downloadArtifact(circuit)
            fail("expected ZkArtifactException on hash mismatch")
        } catch (e: ZkArtifactException) {
            assertTrue(e.message?.contains("longfellow-mdl-v1") == true)
        }
    }

    @Test
    fun `downloadArtifact throws when the descriptor has no artifact`() = runTest {
        val client = ZkCircuitClient(httpGetBytes = { fail("should never fetch without an artifact"); null })
        val circuit = ZkCircuitDescriptor(
            id = "no-artifact-circuit",
            system = "longfellow",
            systemVersion = "1.0",
            published = true,
            status = "active",
            publishedAt = "2026-08-01T00:00:00Z",
        )

        try {
            client.downloadArtifact(circuit)
            fail("expected ZkArtifactException for a missing artifact")
        } catch (e: ZkArtifactException) {
            assertTrue(e.message?.contains("no-artifact-circuit") == true)
        }
    }

    @Test
    fun `downloadArtifact resolves an absolute artifact url as a single candidate, not mirrored`() = runTest {
        val bytes = "abs-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        val calledUrls = mutableListOf<String>()
        val client = ZkCircuitClient(
            sources = listOf("https://zk-circuits.fly.dev", "https://api.circuits.siros.org"),
            httpGetBytes = { url ->
                calledUrls.add(url)
                if (url == "https://cdn.example.org/blobs/$hash") bytes else null
            },
        )
        val circuit = json.decodeFromString(
                ZkCircuitDescriptor.serializer(),
                circuitJson("longfellow-mdl-v1", hash = hash, url = "https://cdn.example.org/blobs/$hash"),
            )

        val downloaded = client.downloadArtifact(circuit)

        assertTrue(bytes.contentEquals(downloaded))
        assertEquals(listOf("https://cdn.example.org/blobs/$hash"), calledUrls)
    }

    @Test
    fun `downloadArtifact constructs the artifact path from the hash when url is blank`() = runTest {
        val bytes = "blank-url-bytes".toByteArray()
        val hash = sha256Hex(bytes)
        var calledUrl: String? = null
        val client = ZkCircuitClient(
            httpGetBytes = { url ->
                calledUrl = url
                if (url == "https://zk-circuits.fly.dev/v1/artifacts/sha256/$hash") bytes else null
            },
        )
        val circuit = json.decodeFromString(ZkCircuitDescriptor.serializer(), circuitJson("longfellow-mdl-v1", hash = hash, url = ""))

        val downloaded = client.downloadArtifact(circuit)

        assertEquals("https://zk-circuits.fly.dev/v1/artifacts/sha256/$hash", calledUrl)
        assertTrue(bytes.contentEquals(downloaded))
    }
}
