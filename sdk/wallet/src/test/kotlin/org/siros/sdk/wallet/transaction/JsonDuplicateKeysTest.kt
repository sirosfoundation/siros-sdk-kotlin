package org.siros.sdk.wallet.transaction

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class JsonDuplicateKeysTest {
    @Test
    fun `objects without repeats pass`() {
        assertFalse(JsonDuplicateKeys.has("""{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}]}"""))
        assertFalse(JsonDuplicateKeys.has(""" { "a" : [ ] , "b" : { } } """))
        assertFalse(JsonDuplicateKeys.has("""{"a":"x,}\"y","b":-1.5e3,"c":true,"d":null}"""))
    }

    @Test
    fun `a repeated name is found at any depth`() {
        assertTrue(JsonDuplicateKeys.has("""{"a":1,"a":2}"""))
        assertTrue(JsonDuplicateKeys.has("""{"x":{"a":1,"b":2,"a":3}}"""))
        assertTrue(JsonDuplicateKeys.has("""{"x":[1,{"k":1,"k":1}]}"""))
    }

    @Test
    fun `names are compared after unescaping`() {
        assertTrue(JsonDuplicateKeys.has("""{"a":1,"a":2}"""))
        assertTrue(JsonDuplicateKeys.has("""{"a/b":1,"a\/b":2}"""))
    }

    @Test
    fun `text the scanner cannot follow counts as a duplicate`() {
        assertTrue(JsonDuplicateKeys.has("""{"a":1"""))
        assertTrue(JsonDuplicateKeys.has("""{"a" 1}"""))
        assertTrue(JsonDuplicateKeys.has("""{"a":1} trailing"""))
        assertTrue(JsonDuplicateKeys.has("""{"a":"\q"}"""))
        assertTrue(JsonDuplicateKeys.has(""))
    }
}
