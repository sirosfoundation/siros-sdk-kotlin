// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.zk_cred_bbs.BbsSuiteId

/**
 * [BbsProofSystem]'s routing, which is the part that runs without the
 * native library.
 *
 * Everything that actually touches BBS needs the `.so` from the AAR and so
 * lives in `androidTest` - see `BbsProofSystemTest`. What is left is how a
 * verifier's request finds this system, and that is worth testing here
 * because it is where BBS deliberately behaves unlike the circuit-based
 * systems it sits beside in the registry.
 */
class BbsProofSystemRoutingTest {

    private val vct = "https://example.test/id-card"

    private fun system(vararg vcts: String) =
        BbsProofSystem(
            holderState = { null },
            supportedVcts = vcts.toSet().ifEmpty { setOf(vct) },
            suiteId = BbsSuiteId.SCHNORR,
        )

    private fun spec(system: String) = ZkSystemSpec(id = "$system-1", system = system)

    @Test
    fun itAdvertisesOneCredentialTypePerSupportedVct() {
        val s = system("https://a.test/one", "https://b.test/two")
        assertEquals(
            setOf(
                CredentialTypeRef(CredentialFormat.JWP, "https://a.test/one"),
                CredentialTypeRef(CredentialFormat.JWP, "https://b.test/two"),
            ),
            s.supportedCredentialTypes,
        )
    }

    /**
     * The format is part of the match, so a verifier asking for an mdoc
     * with a colliding type string does not land here.
     */
    @Test
    fun aCredentialTypeIsFormatPlusType() {
        val s = system(vct)
        assertTrue(CredentialTypeRef(CredentialFormat.JWP, vct) in s.supportedCredentialTypes)
        assertTrue(CredentialTypeRef(CredentialFormat.MSO_MDOC, vct) !in s.supportedCredentialTypes)
        assertTrue(CredentialTypeRef(CredentialFormat.SD_JWT_VC, vct) !in s.supportedCredentialTypes)
    }

    @Test
    fun itMatchesOnlyItsOwnSystemIdentifier() {
        val s = system()
        assertNull(s.matchingSpec(listOf(spec("longfellow-libzk-v1_8_2_4307_2945")), 1))
        assertNull(s.matchingSpec(emptyList(), 1))
        assertEquals(
            BbsProofSystem.SYSTEM_ID,
            s.matchingSpec(listOf(spec("vega-v1"), spec(BbsProofSystem.SYSTEM_ID)), 1)?.system,
        )
    }

    /**
     * **The attribute count is deliberately ignored**, which is the
     * opposite of what the interface asks of a circuit-based system.
     *
     * That requirement exists because a circuit is compiled for a fixed
     * attribute count, and proving against the wrong one yields a proof a
     * verifier rejects during deserialization. BBS has no circuit: the
     * generators are derived from the credential's own message count at
     * proving time, and the disclosed subset is chosen per presentation.
     * Filtering here would reject requests this system can satisfy.
     */
    @Test
    fun anyAttributeCountMatches() {
        val s = system()
        val requested = listOf(spec(BbsProofSystem.SYSTEM_ID))
        val matched = listOf(0, 1, 2, 17, 512).map { n -> n to s.matchingSpec(requested, n) }
        for ((n, spec) in matched) {
            assertEquals("attribute count $n must still match", BbsProofSystem.SYSTEM_ID, spec?.system)
        }
    }

    /**
     * The registry resolves through the same path a wallet would use, so
     * this checks the two ends actually meet.
     */
    @Test
    fun theRegistryResolvesAJwpRequestToThisSystem() {
        val s = system(vct)
        val registry = ZkProofSystemRegistry(listOf(s))
        val requested = listOf(spec(BbsProofSystem.SYSTEM_ID))

        val (resolved, matched) = registry.resolve(CredentialTypeRef(CredentialFormat.JWP, vct), requested, 2)!!
        assertEquals(BbsProofSystem.SYSTEM_ID, resolved.systemId)
        assertEquals(BbsProofSystem.SYSTEM_ID, matched.system)

        assertNull("a vct this wallet holds no BBS credential for", registry.resolve(CredentialTypeRef(CredentialFormat.JWP, "https://other.test/x"), requested, 2))
        assertNull("the right type in the wrong format", registry.resolve(CredentialTypeRef(CredentialFormat.MSO_MDOC, vct), requested, 2))
        assertNull("a system this wallet does not have", registry.resolve(CredentialTypeRef(CredentialFormat.JWP, vct), listOf(spec("something-else")), 2))
    }

    @Test
    fun theJwpDocumentVariantRoundTrips() {
        val compact = "aGVhZGVy.cGF5bG9hZA.c2ln"
        val doc = CredentialDocument.Jwp(compact)
        assertEquals(compact, doc.compact)
        assertEquals(doc, CredentialDocument.Jwp(compact.toByteArray()))
        assertEquals(doc.hashCode(), CredentialDocument.Jwp(compact).hashCode())
        assertTrue(doc != CredentialDocument.Jwp("aGVhZGVy.b3RoZXI.c2ln"))
        // A JWP and an SD-JWT VC over the same bytes are different things.
        assertTrue(doc != CredentialDocument.SdJwtVc(compact.toByteArray()))
    }

    @Test
    fun theJwpFormatHasItsOwnIdentifier() {
        assertEquals("jwp", CredentialFormat.JWP.value)
        // It is not a flavour of SD-JWT, despite sharing the data model.
        assertTrue(CredentialFormat.entries.count { it.value == "jwp" } == 1)
    }
}
