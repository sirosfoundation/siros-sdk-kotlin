// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The DC API activity sits between the verifier and the wallet, so what it logs must never carry
 * a request or response body (a nonce, a presentation, a pseudonym) or an error description.
 * The activity cannot run on the JVM, so this reads its source: no log call may interpolate a payload.
 */
class DCAPIActivityLoggingTest {
    private val source = File("src/main/kotlin/org/siros/sdk/wallet/dcapi/DCAPIGetCredentialActivity.kt")

    @Test
    fun noLogCallInterpolatesARequestOrResponsePayload() {
        assertTrue("missing ${source.path}", source.exists())
        val payload = Regex("""\$\{?[\w.?]*(requestJson|responseJson|errorJson|description)\b(?!\.length)""")
        val offending = source.readLines().withIndex()
            .filter { (_, line) -> line.contains("Timber.") && !line.trimStart().startsWith("//") && payload.containsMatchIn(line) }
        assertTrue("payload logged at: ${offending.map { it.index + 1 to it.value.trim() }}", offending.isEmpty())
    }
}
