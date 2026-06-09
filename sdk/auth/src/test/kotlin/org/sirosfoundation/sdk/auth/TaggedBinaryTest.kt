package org.sirosfoundation.sdk.auth

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TaggedBinaryTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun decode_unwraps_tagged_binary_recursively() {
        val input = json.parseToJsonElement(
            """
            {
              "outer": {
                "${'$'}b64u": "YWJj"
              },
              "arr": [
                { "${'$'}b64u": "ZGVm" },
                { "nested": { "${'$'}b64u": "Z2hp" } }
              ]
            }
            """.trimIndent()
        )

        val decoded = TaggedBinary.decode(input).jsonObject
        assertEquals("YWJj", decoded["outer"]?.toString()?.trim('"'))
        assertTrue(decoded["arr"].toString().contains("ZGVm"))
        assertTrue(decoded["arr"].toString().contains("Z2hp"))
    }

    @Test
    fun extract_base64url_handles_plain_and_tagged_forms() {
      val tagged = json.parseToJsonElement("""{ "${'$'}b64u": "dGVzdA" }""")
        val plain = json.parseToJsonElement(""""dGVzdDI"""")

        assertEquals("dGVzdA", TaggedBinary.extractBase64Url(tagged))
        assertEquals("dGVzdDI", TaggedBinary.extractBase64Url(plain))
    }
}
