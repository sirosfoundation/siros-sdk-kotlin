// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.transport.engine

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * `WalletMetadata.DEFAULT`'s mdoc algorithm lists must match what `MdocCose` actually implements (Copilot review of #190): advertising
 * an algorithm this SDK never produces or verifies, or omitting one it does, leaves a conforming verifier's tailored Request Object
 * wrong for what the wallet will actually send.
 */
class WalletMetadataTest {
    private fun mdocAlgValues(member: String): List<Long> =
        WalletMetadata.DEFAULT.jsonObject
            .getValue("vp_formats_supported").jsonObject
            .getValue("mso_mdoc").jsonObject
            .getValue(member).jsonArray
            .map { it.jsonPrimitive.content.toLong() }

    @Test
    fun deviceAuthAdvertisesExactlyWhatMdocCoseCanProduceForADeviceSignature() {
        // MdocCose.algorithmValue maps a holder key's own algorithm to a COSE identifier: ES256 (-7) and EdDSA (-8) only.
        // -9 (ES256 fully-specified) is never emitted by sign1Detached, so advertising it would promise a value no device
        // signature this SDK builds will ever carry.
        assertEquals(listOf(-7L, -8L), mdocAlgValues("deviceauth_alg_values"))
    }

    @Test
    fun issuerAuthAdvertisesOnlyWhatMdocCoseVerify1Implements() {
        // MdocCose.verify1/jcaAlgorithmFor only implements ES256/ES384/ES512 verification, no EdDSA: -8 must not appear
        // here even though it is valid for deviceauth.
        assertEquals(listOf(-7L), mdocAlgValues("issuerauth_alg_values"))
    }

    @Test
    fun sdJwtVcAlgValuesAreAdvertisedUnderBothIdentifiers() {
        for (format in listOf("dc+sd-jwt", "vc+sd-jwt")) {
            val entry = WalletMetadata.DEFAULT.jsonObject.getValue("vp_formats_supported").jsonObject.getValue(format).jsonObject
            // sd-jwt_alg_values is the ISSUER's own signature algorithm, out of this wallet's control: ES256 only.
            assertEquals(listOf(JsonPrimitive("ES256")), entry.getValue("sd-jwt_alg_values").jsonArray.toList())
            // kb-jwt_alg_values is this wallet's OWN Key Binding JWT: WscdKeystoreAdapter signs it with whatever the
            // selected holder key's algorithm is (ES256 or EdDSA), same as the mdoc device signature.
            assertEquals(listOf(JsonPrimitive("ES256"), JsonPrimitive("EdDSA")), entry.getValue("kb-jwt_alg_values").jsonArray.toList())
        }
    }
}
