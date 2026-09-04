// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import uniffi.zk_cred_bbs.BbsFfiException
import uniffi.zk_cred_bbs.BbsSuiteId
import uniffi.zk_cred_bbs.jwpVerify

/**
 * The wallet's half of blind BBS issuance, on a real device.
 *
 * # What this can and cannot run
 *
 * It cannot issue. Blind-signing is deliberately absent from the wallet's
 * UniFFI surface - a wallet has no business holding an issuer key, and
 * exposing the call would put one within reach of application code. So the
 * two halves are tested against different things:
 *
 * - [BbsIssuanceParticipant.prepare] runs for real here. Its outputs are
 *   fresh per call, so what is checked is their shape, their ordering, and
 *   that they are fresh.
 * - [BbsIssuancePreparation.accept] is checked against the fixture, whose
 *   commitment and credential were produced together by the crate. That is
 *   a real issuer's output, not a stand-in.
 *
 * The full commit-then-issue loop is covered where both halves are
 * reachable: the crate's own `a_wallet_can_commit_before_it_knows_the_
 * issuers_claims`.
 *
 * The `Plain` suite is used throughout so this runs with no authenticator
 * attached. The key-bound path's device interaction is covered separately,
 * in `BbsProofSystemTest`.
 */
class BbsIssuanceParticipantTest {

    private val holderClaims = """{"device_pin_hash":"0f1e2d3c","recovery_code":"xyz"}"""

    /** Fails the test if it is ever called. */
    private val refusingSigner = ZkWitnessSigner { algorithm, _ ->
        fail("the authenticator was asked for a $algorithm signature with no key binding keys")
        ByteArray(0)
    }

    private fun participant() =
        BbsIssuanceParticipant(systemId = BbsProofSystem.SYSTEM_ID, suiteId = BbsSuiteId.PLAIN)

    // -----------------------------------------------------------------------

    private fun fixture(): JSONObject {
        val stream = javaClass.classLoader!!.getResourceAsStream("bbs_jwp_fixture.json")
            ?: error("bbs_jwp_fixture.json missing from androidTest resources")
        return JSONObject(stream.bufferedReader().readText()).getJSONObject("cases").getJSONObject("plain")
    }

    private fun String.unhex(): ByteArray =
        ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun JSONObject.hexList(key: String): List<ByteArray> =
        getJSONArray(key).let { a -> (0 until a.length()).map { a.getString(it).unhex() } }

    /**
     * The preparation as it stood when the fixture's credential was
     * issued, reconstructed from the commitment the crate recorded.
     *
     * This is why the fixture carries the commitment: `prepare` produces a
     * fresh one every call, so nothing generated here could ever match a
     * credential issued earlier.
     */
    private fun preparationFromFixture(case: JSONObject) = BbsIssuancePreparation(
        suiteId = BbsSuiteId.PLAIN,
        commitmentWithProof = case.getString("commitment").unhex(),
        holderPointers = case.getJSONArray("holder_pointers").let { a ->
            (0 until a.length()).map { a.getString(it) }
        },
        committedMessages = case.hexList("committed_messages"),
        secretProverBlind = case.getString("secret_prover_blind").unhex(),
        keybindPublicKeys = emptyList(),
    )

    /**
     * Accepting a real credential yields exactly the state needed to
     * present it - which closes the loop between the two halves of this
     * feature.
     *
     * A wallet that stored the wrong state here would find out only at the
     * first presentation, against a verifier, in front of a user.
     */
    @Test
    fun acceptYieldsTheStateNeededToPresent() = runBlocking {
        val case = fixture()
        val issuerPk = case.getString("issuer_pk").unhex()
        val issuedJwp = case.getString("issued_jwp")

        val state = preparationFromFixture(case).accept(issuedJwp, issuerPk)
        assertEquals(issuerPk.toList(), state.issuerPublicKey.toList())

        val system = BbsProofSystem(
            holderState = { state },
            supportedVcts = setOf(case.getString("vct")),
            suiteId = BbsSuiteId.PLAIN,
        )
        val result = system.generateProof(
            spec = ZkSystemSpec(
                id = "t",
                system = BbsProofSystem.SYSTEM_ID,
                params = mapOf("nonce" to "n", "aud" to "https://verifier.test"),
            ),
            document = CredentialDocument.Jwp(issuedJwp),
            sessionTranscript = "transcript".toByteArray(),
            requestedClaims = listOf("/given_name"),
            verifierIdentity = null,
            signer = refusingSigner,
        )
        val verified = jwpVerify(BbsSuiteId.PLAIN, result.proofBytes.toString(Charsets.UTF_8), issuerPk)
        assertEquals(1, verified.disclosed.size)
        assertEquals("/given_name", verified.disclosed[0].pointer)
    }

    /**
     * What `prepare` produces, and in what order.
     *
     * The ordering is the substance: the wallet commits knowing nothing
     * about the issuer's claims, and the issuer assigns message indices
     * afterwards. If the two sides ordered the holder's claims
     * differently, the credential's map would name one claim while the
     * signature covered another.
     */
    @Test
    fun prepareCommitsInTheOrderTheIssuerWillIndex() = runBlocking {
        val prepared = participant().prepare(holderClaims, emptyList(), refusingSigner)

        assertEquals(
            "sorted by pointer, not by document order",
            listOf("/device_pin_hash", "/recovery_code"),
            prepared.holderPointers,
        )
        assertEquals(2, prepared.committedMessages.size)
        assertEquals(
            "the message is the claim's JSON value",
            "\"0f1e2d3c\"",
            prepared.committedMessages[0].toString(Charsets.UTF_8),
        )
        assertTrue("a commitment must actually be produced", prepared.commitmentWithProof.isNotEmpty())
        assertEquals("the prover blind is a scalar", 32, prepared.secretProverBlind.size)
    }

    /**
     * The credential request must carry the commitment and the claim names,
     * and nothing that would let a JSON builder mangle them.
     */
    @Test
    fun theCredentialRequestFieldsAreWellFormedJson() = runBlocking {
        val prepared = participant().prepare(holderClaims, emptyList(), refusingSigner)
        val fields = prepared.credentialRequestFields

        assertEquals(
            setOf(BbsIssuanceParticipant.COMMITMENT_FIELD, BbsIssuanceParticipant.POINTERS_FIELD),
            fields.keys,
        )

        // Each value must parse as the JSON it claims to be.
        val commitment = fields.getValue(BbsIssuanceParticipant.COMMITMENT_FIELD)
        assertTrue("the commitment is a JSON string: $commitment", commitment.startsWith("\"") && commitment.endsWith("\""))
        val encoded = commitment.trim('"')
        assertTrue("base64url, unpadded", encoded.none { it == '+' || it == '/' || it == '=' })

        val pointers = JSONArray(fields.getValue(BbsIssuanceParticipant.POINTERS_FIELD))
        assertEquals(2, pointers.length())
        assertEquals("/device_pin_hash", pointers.getString(0))
        assertEquals("/recovery_code", pointers.getString(1))
    }

    /**
     * A claim name containing JSON syntax must survive intact.
     *
     * The pointer array is hand-encoded, so a name with a quote in it is
     * exactly what turns a request into malformed JSON - or, worse, into
     * valid JSON naming a different claim.
     */
    @Test
    fun hostileClaimNamesAreEscaped() = runBlocking {
        val prepared = participant().prepare("""{"a\"b":1,"c\\d":2}""", emptyList(), refusingSigner)
        val pointers = JSONArray(prepared.credentialRequestFields.getValue(BbsIssuanceParticipant.POINTERS_FIELD))
        val got = (0 until pointers.length()).map { pointers.getString(it) }
        assertEquals("both names must round-trip through the request", prepared.holderPointers, got)
        assertTrue("the quote must survive", got.any { it.contains('"') })
    }

    /**
     * Two wallets committing to the same claims must not produce the same
     * commitment.
     *
     * The blinding factor is fresh per credential. If it were not, two
     * credentials issued to the same holder would be linkable by their
     * commitments alone - before any presentation happens at all.
     */
    @Test
    fun everyCommitmentIsFresh() = runBlocking {
        val first = participant().prepare(holderClaims, emptyList(), refusingSigner)
        val second = participant().prepare(holderClaims, emptyList(), refusingSigner)

        assertNotEquals(
            "two commitments to the same claims must differ",
            first.commitmentWithProof.toList(),
            second.commitmentWithProof.toList(),
        )
        assertNotEquals(
            "the prover blind must be fresh per credential",
            first.secretProverBlind.toList(),
            second.secretProverBlind.toList(),
        )
        // The claim names are not secret and must NOT vary.
        assertEquals(first.holderPointers, second.holderPointers)
        assertEquals(first.committedMessages.map { it.toList() }, second.committedMessages.map { it.toList() })
    }

    /**
     * Accepting is the wallet's only chance to notice the issuer signed
     * something other than what was asked for.
     *
     * Each of these otherwise surfaces much later, as a presentation that
     * will not verify with nothing pointing at the cause.
     */
    @Test
    fun acceptRejectsACredentialThatIsNotWhatWasCommitted() {
        val case = fixture()
        val issuerPk = case.getString("issuer_pk").unhex()
        val issuedJwp = case.getString("issued_jwp")
        val prepared = preparationFromFixture(case)

        // Sanity: it does accept the real thing.
        prepared.accept(issuedJwp, issuerPk)

        val otherKey = issuerPk.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertThrows(BbsFfiException::class.java) { prepared.accept(issuedJwp, otherKey) }

        // A credential issued against a DIFFERENT commitment - the case
        // where an issuer hands back someone else's.
        val mismatched = BbsIssuancePreparation(
            suiteId = BbsSuiteId.PLAIN,
            commitmentWithProof = prepared.commitmentWithProof,
            holderPointers = prepared.holderPointers,
            committedMessages = prepared.committedMessages.map { it.copyOf().also { b -> b[0] = 0x41 } },
            secretProverBlind = prepared.secretProverBlind,
            keybindPublicKeys = emptyList(),
        )
        assertThrows(BbsFfiException::class.java) { mismatched.accept(issuedJwp, issuerPk) }

        // A different blinding factor: the credential is real, but not this
        // wallet's.
        val otherBlind = BbsIssuancePreparation(
            suiteId = BbsSuiteId.PLAIN,
            commitmentWithProof = prepared.commitmentWithProof,
            holderPointers = prepared.holderPointers,
            committedMessages = prepared.committedMessages,
            secretProverBlind = prepared.secretProverBlind.copyOf().also { it[31] = (it[31].toInt() xor 0x01).toByte() },
            keybindPublicKeys = emptyList(),
        )
        assertThrows(BbsFfiException::class.java) { otherBlind.accept(issuedJwp, issuerPk) }

        assertThrows(BbsFfiException::class.java) { prepared.accept("not.a.jwp", issuerPk) }
    }

    @Test
    fun claimsThatCannotBeCommittedAreRejected() = runBlocking {
        for (bad in listOf("{}", """["not","an","object"]""", "{", "\"scalar\"")) {
            try {
                participant().prepare(bad, emptyList(), refusingSigner)
                fail("prepared a commitment from $bad")
            } catch (e: BbsFfiException) {
                // expected
            }
        }
    }

    /**
     * A wallet finds the participant through the registry, without naming a
     * proof system - and gets nothing for the credential types where no
     * system takes part in issuance, which is most of them.
     */
    @Test
    fun theRegistryRoutesIssuanceWithoutNamingASystem() {
        val vct = fixture().getString("vct")
        val bbs = BbsProofSystem(
            holderState = { null },
            supportedVcts = setOf(vct),
            suiteId = BbsSuiteId.PLAIN,
        )
        val registry = ZkProofSystemRegistry(listOf(bbs))

        val found = registry.issuanceParticipant(CredentialTypeRef(CredentialFormat.JWP, vct))
        assertEquals(BbsProofSystem.SYSTEM_ID, found?.systemId)

        assertEquals(
            "an mdoc needs no wallet contribution at issuance",
            null,
            registry.issuanceParticipant(CredentialTypeRef(CredentialFormat.MSO_MDOC, "org.iso.18013.5.1.mDL")),
        )
        assertEquals(
            "nor does a vct this wallet holds no BBS credentials for",
            null,
            registry.issuanceParticipant(CredentialTypeRef(CredentialFormat.JWP, "https://other.test/x")),
        )
    }
}
