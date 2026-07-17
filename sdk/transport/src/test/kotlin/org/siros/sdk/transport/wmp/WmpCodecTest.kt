package org.siros.sdk.transport.wmp

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WmpCodecTest {

    private val codec = WmpCodec()

    @Test
    fun encodeRequest_producesValidJsonRpc2() {
        val params = buildJsonObject {
            put("key", "value")
        }
        val bytes = codec.encodeRequest("wmp.session.create", params, id = "test-id")
        val text = bytes.toString(Charsets.UTF_8)

        assertTrue(text.contains("\"jsonrpc\":\"2.0\""))
        assertTrue(text.contains("\"method\":\"wmp.session.create\""))
        assertTrue(text.contains("\"id\":\"test-id\""))
        assertTrue(text.contains("\"key\":\"value\""))
    }

    @Test
    fun encodeNotification_omitsId() {
        val bytes = codec.encodeNotification("wmp.session.close", null)
        val text = bytes.toString(Charsets.UTF_8)

        assertTrue(text.contains("\"method\":\"wmp.session.close\""))
        // id should not be present in a notification
        val decoded = codec.decodeRequest(bytes)
        assertNull(decoded.id)
    }

    @Test
    fun decodeMessage_identifiesResponse() {
        val json = """{"jsonrpc":"2.0","id":"req-1","result":{"wmp":{"version":"0.1","session_id":"ses-123"}}}"""
        val message = codec.decodeMessage(json.toByteArray())

        assertTrue(message is WmpMessage.Response)
        val response = (message as WmpMessage.Response).response
        assertEquals("req-1", response.id)
        assertNotNull(response.result)
    }

    @Test
    fun decodeMessage_identifiesNotification() {
        val json = """{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"}}}"""
        val message = codec.decodeMessage(json.toByteArray())

        assertTrue(message is WmpMessage.Notification)
        val notification = (message as WmpMessage.Notification).notification
        assertEquals("wmp.flow.progress", notification.method)
    }

    @Test
    fun decodeMessage_identifiesRequestWithId() {
        val json = """{"jsonrpc":"2.0","id":"req-2","method":"wmp.flow.action","params":{}}"""
        val message = codec.decodeMessage(json.toByteArray())

        assertTrue(message is WmpMessage.Request)
        val request = (message as WmpMessage.Request).request
        assertEquals("req-2", request.id)
        assertEquals("wmp.flow.action", request.method)
    }

    @Test
    fun decodeResponse_handlesError() {
        val json = """{"jsonrpc":"2.0","id":"req-1","error":{"code":-31000,"message":"Session not found"}}"""
        val response = codec.decodeResponse(json.toByteArray())

        assertNotNull(response.error)
        assertEquals(-31000, response.error!!.code)
        assertEquals("Session not found", response.error!!.message)
    }

    @Test
    fun `encodeParams serializes SessionCreateParams`() {
        val params = SessionCreateParams(
            wmp = WmpMeta(sender = "test-sender"),
            auth = SessionAuth(type = "bearer", token = "test-token"),
            ttl = 3600,
        )
        val jsonObj = codec.encodeParams(params)

        assertNotNull(jsonObj["wmp"])
        assertNotNull(jsonObj["auth"])
        assertNotNull(jsonObj["ttl"])
    }
}
