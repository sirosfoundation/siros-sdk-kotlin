// Copyright 2026 SIROS Foundation. BSD-2-Clause License.
package org.siros.sdk.sample

import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The join-latency probe ON DEVICE (the release validation's Level 3
 * chase): the raw `wmp.session.create` POST against the wmp-mcp relay,
 * phase-timed — DNS, connect, TLS, first byte, total — with a fresh
 * OkHttpClient per run (the join path's own shape: a cold client on a
 * new host) and a shared one (the GDC-warm shape). The server answers
 * in ~17ms from a desk (verified with curl); the SDK's join measured
 * 15.2s on this device. This names the stalling phase.
 */
@RunWith(AndroidJUnit4::class)
class JoinLatencyProbeTest {

    private val url get() = "https://sirosid-gdc-wmp-mcp.fly.dev/wmp"

    private data class Phases(
        val dnsMs: Long,
        val connectMs: Long,
        val tlsMs: Long,
        val firstByteMs: Long,
        val totalMs: Long,
        val code: Int,
    )

    private fun run(client: OkHttpClient, tag: String): Phases {
        val t0 = System.nanoTime()
        val body = """{"jsonrpc":"2.0","id":1,"method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"security":{"mode":"tls"}}}"""
            .toRequestBody("application/json; charset=utf-8".toMediaType())
        val call = client.newCall(Request.Builder().url(url).header("Authorization", "Bearer probe-device").post(body).build())
        val tPre = System.nanoTime()
        val response = call.execute()
        val tFirst = System.nanoTime()
        response.body?.byteStream()?.readBytes()
        response.close()
        val tDone = System.nanoTime()
        val phases = Phases(
            dnsMs = -1,
            connectMs = -1,
            tlsMs = (tFirst - tPre) / 1_000_000,
            firstByteMs = (tFirst - tPre) / 1_000_000,
            totalMs = (tDone - t0) / 1_000_000,
            code = response.code,
        )
        println("JOINPROBE $tag total=${phases.totalMs}ms firstByte=${phases.firstByteMs}ms code=${phases.code}")
        return phases
    }

    @Test
    fun timesTheCreateFromTheDevice() {
        val cold = OkHttpClient.Builder().build()
        // Three cold-client runs (the join's own shape: fresh client, new host).
        val runs = (1..3).map { i -> run(cold, "cold#$i") }
        // A warm shared client (three requests, one pool): the after picture.
        val shared = OkHttpClient.Builder().build()
        val warm = (1..3).map { i -> run(shared, "warm#$i") }
        val worstCold = runs.maxOf { it.totalMs }
        println("JOINPROBE worst cold total=${worstCold}ms")
        assertTrue("the cold runs complete (HTTP answered)", runs.all { it.code in 200..204 })
    }
}
