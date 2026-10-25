// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import java.util.Base64
import kotlin.reflect.full.callSuspend
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.jvm.isAccessible
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.auth.BackendApiClient
import org.siros.sdk.auth.keyAttestationNotQualifyingReason
import org.siros.sdk.credentials.BackendApiException
import org.siros.sdk.keystore.AttestationChain
import org.siros.sdk.keystore.KeyInfo
import org.siros.sdk.keystore.KeystoreManager

/** Instance-key evidence in the WIA flow (go-wallet-backend pull 486): one key per challenge, a NEW key and challenge on failure. */
@OptIn(ExperimentalCoroutinesApi::class)
class InstanceKeyEvidenceFlowTest {
    private val chain1 = AttestationChain(listOf(byteArrayOf(-1, -1, -1, -5, -17, -66), byteArrayOf(4, 5), byteArrayOf(6)), ByteArray(0), AttestationChain.FORMAT_ANDROID_KEY)
    private val chain2 = AttestationChain(listOf(byteArrayOf(9, 9, 9), byteArrayOf(8)), ByteArray(0), AttestationChain.FORMAT_ANDROID_KEY)

    private class Rig(
        val wallet: SirosWallet,
        val keystore: KeystoreManager,
        val api: BackendApiClient,
        val stored: () -> String?,
        val clock: LongArray,
        val setStored: (String?) -> Unit = {},
        val setAccount: (String?) -> Unit = {},
        val fingerprint: Array<String> = arrayOf("os-1"),
    )

    private var jwtCounter = 0

    /** A WIA-shaped JWT; [tag] makes it distinguishable. */
    private fun jwt(tag: String = "wia${jwtCounter++}"): String {
        val b = { s: String -> Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray()) }
        return b("""{"alg":"none"}""") + "." + b("""{"exp":${System.currentTimeMillis() / 1000 + 3600},"tag":"$tag"}""") + ".sig"
    }

    private fun rig(capable: Boolean = true, existingKey: String? = null, challenges: List<String> = listOf("C-1", "C-2", "C-3")): Rig {
        var stored: String? = existingKey
        var account: String? = "acct-A"
        val sessionStore = mockk<SessionStore>(relaxed = true)
        every { sessionStore.activeAccountId } answers { account }
        every { sessionStore.instanceKeyId } answers { stored }
        every { sessionStore.instanceKeyId = any() } answers { stored = firstArg() }
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.supportsAttestedKeyGeneration } returns capable
        val live = mutableListOf<String>()
        existingKey?.let { live += it }
        every { keystore.listKeys() } answers { live.map { KeyInfo(it, "ES256", 0L) } }
        coEvery { keystore.generateKey(any()) } answers { "plain-key".also { live += it } }
        var n = 0
        coEvery { keystore.generateAttestedKey(any(), any()) } answers { "attested-${++n}".also { live += it } }
        coEvery { keystore.attestationChain("attested-1") } returns chain1
        coEvery { keystore.attestationChain("attested-2") } returns chain2
        coEvery { keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = any(), extraClaims = any()) } returns "pop"
        val api = mockk<BackendApiClient>(relaxed = true)
        var c = 0
        coEvery { api.requestWIAChallenge() } answers { buildJsonObject { put("challenge", JsonPrimitive(challenges[c++])) } }
        val clock = longArrayOf(1_000_000L)
        val wallet = SirosWalletTest().newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(SupervisorJob()),
            "sessionStore" to sessionStore,
            "keystore" to keystore,
            "apiClient" to api,
            "instanceKeyMutex" to kotlinx.coroutines.sync.Mutex(),
            "wiaMutex" to kotlinx.coroutines.sync.Mutex(),
            "dpopBoundInstanceKeys" to java.util.concurrent.ConcurrentHashMap.newKeySet<String>(),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
        )
        wallet.instanceKeyClock = { clock[0] }
        val fingerprint = arrayOf("os-1")
        wallet.deviceStateFingerprint = { fingerprint[0] }
        return Rig(wallet, keystore, api, { stored }, clock, { stored = it }, { account = it }, fingerprint)
    }

    private fun obtain(wallet: SirosWallet): String? {
        val m = SirosWallet::class.declaredMemberFunctions.first { it.name == "ensureWalletInstanceAttestation" }
        m.isAccessible = true
        val tree = object : timber.log.Timber.Tree() {
            override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { if (t != null) System.err.println("TIMBER: $message $t ${t.stackTrace.take(4)}") }
        }
        timber.log.Timber.plant(tree)
        try { return runBlocking { m.callSuspend(wallet) as String? } } finally { timber.log.Timber.uproot(tree) }
    }

    private fun x5c(o: JsonObject) = o["x5c"]!!.jsonArray.map { Base64.getDecoder().decode(it.jsonPrimitive.content) }

    @Test
    fun aCapableKeystore_generatesTheKeyForTheChallengeFirst_andSendsTheChainWithThatVeryChallenge() {
        val r = rig()
        val challengeBytes = slot<ByteArray>()
        coEvery { r.keystore.generateAttestedKey("ES256", capture(challengeBytes)) } returns "attested-1"
        val evidence = slot<JsonObject>()
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = capture(evidence)) } returns jwt()
        assertNotNull(obtain(r.wallet))
        assertArrayEquals(InstanceKeyEvidence.challengeHash("C-1"), challengeBytes.captured)
        coVerify(exactly = 1) { r.api.requestWIAChallenge() } // C is fetched once and reused for the PoP and the request
        assertEquals("android_key", evidence.captured["type"]!!.jsonPrimitive.content)
        assertEquals(chain1.certificates.map { it.toList() }, x5c(evidence.captured).map { it.toList() }) // leaf first, standard base64
        assertEquals("attested-1", r.stored())
    }

    @Test
    fun aKeystoreWithoutTheCapability_keepsThePlainKeyAndSendsNoEvidence() {
        val r = rig(capable = false)
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = null) } returns jwt()
        assertNotNull(obtain(r.wallet))
        coVerify(exactly = 0) { r.keystore.generateAttestedKey(any(), any()) }
        coVerify(exactly = 1) { r.keystore.generateKey("ES256") }
        coVerify(exactly = 0) { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = matchNullable<JsonObject> { it != null }) }
    }

    @Test
    fun anExistingInstanceKey_isNeverReplacedOrAttestedRetroactively() {
        val r = rig(existingKey = "old-key")
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = null) } returns jwt()
        assertNotNull(obtain(r.wallet))
        coVerify(exactly = 0) { r.keystore.generateAttestedKey(any(), any()) }
        assertEquals("old-key", r.stored())
    }

    @Test
    fun refusedEvidence_isRetriedOnceWithANewKeyAndANewChallenge_andTheOldKeyIsDeleted() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws
            BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
        val second = slot<JsonObject>()
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-2", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = capture(second)) } returns jwt()
        assertNotNull(obtain(r.wallet))
        assertEquals(chain2.certificates.map { it.toList() }, x5c(second.captured).map { it.toList() })
        assertEquals("attested-2", r.stored())
        coVerify(exactly = 1) { r.keystore.deleteKey("attested-1") }
    }

    @Test
    fun anUnavailableVerdict_isRetriedOnceToo_andTwoFailuresEndAsNoWia_neverBlockingIssuance() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws
            BackendApiException(503, "unavailable", """{"error":"KEY_ATTESTATION_UNAVAILABLE"}""")
        assertNull(obtain(r.wallet))
        coVerify(exactly = 2) { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) }
    }

    @Test
    fun aBackendThatDoesNotKnowTheEvidenceType_isAskedAgainAtOnceWithoutIt_onTheSameUnconsumedChallenge() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = matchNullable<JsonObject> { it != null }) } throws
            BackendApiException(400, "unsupported", """{"error":"KEY_ATTESTATION_TYPE_UNSUPPORTED"}""")
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = null) } returns jwt()
        assertNotNull(obtain(r.wallet))
        coVerify(exactly = 1) { r.api.requestWIAChallenge() }
        assertEquals("attested-1", r.stored()) // no rotation: nothing was consumed
    }

    @Test
    fun aPolicyRefusalIsNotAnEvidenceFailure_noKeyIsRotated() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws
            BackendApiException(403, "refused", """{"error":"WIA_REFUSED_BY_POLICY"}""")
        assertNull(obtain(r.wallet))
        coVerify(exactly = 1) { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) }
        coVerify(exactly = 0) { r.keystore.deleteKey(any()) }
    }

    @Test
    fun aChallengeThatWentStaleBeforeUse_isNotSpent_theKeyIsReplacedInstead() {
        val r = rig()
        // The key is created when something else needs it (a DPoP request), long before the WIA is asked for.
        val ensure = SirosWallet::class.declaredMemberFunctions.first { it.name == "ensureInstanceKeyId" }
        ensure.isAccessible = true
        runBlocking { ensure.callSuspend(r.wallet) }
        r.clock[0] += 10 * 60 * 1000
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-2", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } returns jwt()
        assertNotNull(obtain(r.wallet))
        coVerify(exactly = 0) { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) }
        assertEquals("attested-2", r.stored())
    }

    @Test
    fun evidenceIsBuiltOnlyFromAnAndroidChainWithinTheBackendsBounds() {
        assertNotNull(InstanceKeyEvidence.androidKey(chain1))
        assertNull(InstanceKeyEvidence.androidKey(null))
        assertNull("a FIDO2 attestation object is not an x5c", InstanceKeyEvidence.androidKey(chain1.copy(format = AttestationChain.FORMAT_FIDO2_PACKED)))
        assertNull("a leaf alone", InstanceKeyEvidence.androidKey(chain1.copy(certificates = listOf(byteArrayOf(1)))))
        assertNull("too many", InstanceKeyEvidence.androidKey(chain1.copy(certificates = List(9) { byteArrayOf(1) })))
        assertNull("a certificate over 8 KiB", InstanceKeyEvidence.androidKey(chain1.copy(certificates = listOf(ByteArray(8 * 1024 + 1), byteArrayOf(1)))))
        assertNull("over 32 KiB in all", InstanceKeyEvidence.androidKey(chain1.copy(certificates = List(5) { ByteArray(7 * 1024) })))
        assertNull("an empty certificate", InstanceKeyEvidence.androidKey(chain1.copy(certificates = listOf(byteArrayOf(1), byteArrayOf()))))
        // The challenge: SHA-256("siros-instance-key-v1" || C), C as issued; the backend's own vector for "AAAA".
        assertEquals(
            "2b720816b6d9f97343b4ac4e5821bdedcf26915d1795396c869b1706f142d428",
            InstanceKeyEvidence.challengeHash("AAAA").joinToString("") { "%02x".format(it) },
        )
    }

    private fun invoke(wallet: SirosWallet, name: String): Any? {
        val m = SirosWallet::class.declaredMemberFunctions.first { it.name == name }
        m.isAccessible = true
        return runBlocking { m.callSuspend(wallet) }
    }

    @Test
    fun twoConcurrentCallers_shareOneAcquisition_neitherUsesAKeyTheOtherReplaces() {
        val r = rig()
        var calls = 0
        coEvery { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } coAnswers {
            kotlinx.coroutines.delay(50)
            if (++calls == 1) throw BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
            jwt()
        }
        val results = runBlocking {
            val a = async(kotlinx.coroutines.Dispatchers.Default) { invoke(r.wallet, "ensureWalletInstanceAttestation") as String? }
            val b = async(kotlinx.coroutines.Dispatchers.Default) { invoke(r.wallet, "ensureWalletInstanceAttestation") as String? }
            listOf(a.await(), b.await())
        }
        assertTrue(results.all { it != null })
        assertEquals("both callers got the one WIA", results[0], results[1])
        assertEquals("one failed attempt and its retry, no second acquisition", 2, calls)
        coVerify(exactly = 1) { r.keystore.deleteKey("attested-1") }
        assertEquals("attested-2", r.stored())
    }

    @Test
    fun aFailureAfterAnAccountSwitch_neverTouchesTheNewAccountsKey() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } coAnswers {
            // While account A's request is in flight the user switches to B, who has a key of their own.
            r.setAccount("acct-B")
            r.setStored("B-key")
            throw BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
        }
        assertNull(obtain(r.wallet))
        assertEquals("B's key is untouched", "B-key", r.stored())
        coVerify(exactly = 0) { r.keystore.deleteKey(any()) }
        coVerify(exactly = 1) { r.keystore.generateAttestedKey(any(), any()) } // only A's original key
    }

    @Test
    fun theKeyForDpopIsOnlyHandedOutAfterItsInitialAttestationSettled() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws
            BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-2", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } returns jwt()
        // A DPoP request is the first thing to need the instance key: it must get the REPLACEMENT, never the key that was rotated away.
        val keyForDpop = invoke(r.wallet, "settledInstanceKeyId") as String
        assertEquals("attested-2", keyForDpop)
        assertEquals("attested-2", r.stored())
    }

    @Test
    fun aKeyThatTokensAreBoundToIsRetainedWhenItIsReplaced_anUnreferencedOneIsDeleted() {
        val r = rig()
        @Suppress("UNCHECKED_CAST")
        (getFieldOf(r.wallet, "dpopBoundInstanceKeys") as MutableSet<String>).add("attested-1")
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws
            BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-2", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } returns jwt()
        assertNotNull(obtain(r.wallet))
        assertEquals("attested-2", r.stored())
        coVerify(exactly = 0) { r.keystore.deleteKey("attested-1") }
    }

    private fun getFieldOf(target: Any, name: String): Any? {
        val f = target.javaClass.getDeclaredField(name)
        f.isAccessible = true
        return f.get(target)
    }

    private fun notQualifying(reason: String) = BackendApiException(
        400, "not qualifying",
        """{"error":"KEY_ATTESTATION_NOT_QUALIFYING","message":"secret-message-text","details":{"reason":"$reason"}}""",
    )

    @Test
    fun notQualifying_isAHardFailureForThatKey_noRetryNoNewKey_andOnlyTheReasonIsLogged() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws notQualifying("bootloader_unlocked")
        val logged = StringBuilder()
        val tree = object : timber.log.Timber.Tree() {
            override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { logged.append(message).append('\n') }
        }
        timber.log.Timber.plant(tree)
        try {
            assertNull("best-effort: no WIA, issuance goes on", obtain(r.wallet))
        } finally {
            timber.log.Timber.uproot(tree)
        }
        coVerify(exactly = 1) { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) }
        coVerify(exactly = 1) { r.keystore.generateAttestedKey(any(), any()) }
        coVerify(exactly = 0) { r.keystore.deleteKey(any()) }
        assertTrue(logged.toString(), logged.contains("reason=bootloader_unlocked"))
        assertTrue("the message body is never logged", !logged.contains("secret-message-text"))
    }

    @Test
    fun anUnknownNotQualifyingReasonIsLoggedAsOther() {
        assertEquals("other", notQualifying("something_new").keyAttestationNotQualifyingReason())
        assertEquals("other", BackendApiException(400, "x", "not json").keyAttestationNotQualifyingReason())
        assertEquals("untrusted_root", notQualifying("untrusted_root").keyAttestationNotQualifyingReason())
    }

    @Test
    fun aNewAttemptAfterNotQualifying_needsTheDeviceStateToHaveChanged_andOneCallIsOneKey() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws notQualifying("patch_level_too_old")
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-2", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } returns jwt()
        assertNull(obtain(r.wallet))
        // Same device state: refused, nothing generated.
        assertEquals(false, runBlocking { r.wallet.retryInstanceKeyAttestation() })
        coVerify(exactly = 1) { r.keystore.generateAttestedKey(any(), any()) }
        // The device was updated: one new key and challenge.
        r.fingerprint[0] = "os-2"
        assertEquals(true, runBlocking { r.wallet.retryInstanceKeyAttestation() })
        coVerify(exactly = 2) { r.keystore.generateAttestedKey(any(), any()) }
        assertEquals("attested-2", r.stored())
    }

    @Test
    fun aSessionSwitchWhileTheReplacementIsBeingGenerated_discardsTheReplacementAndTouchesNothingOfTheOtherAccount() {
        val r = rig()
        var challenges = 0
        coEvery { r.api.requestWIAChallenge() } coAnswers {
            val n = ++challenges
            if (n == 2) { r.setAccount("acct-B"); r.setStored("B-key") } // the REPLACEMENT's challenge fetch: the user switches meanwhile
            buildJsonObject { put("challenge", JsonPrimitive("C-$n")) }
        }
        coEvery { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws
            BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
        assertNull(obtain(r.wallet))
        assertEquals("B's key is untouched", "B-key", r.stored())
        coVerify(exactly = 1) { r.keystore.deleteKey("attested-2") } // the unused replacement was discarded
        coVerify(exactly = 0) { r.keystore.deleteKey("B-key") }
    }

    @Test
    fun aDpopCallerArrivingWhileAnAcquisitionIsInFlight_waitsAndGetsTheFinalKey() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } coAnswers {
            kotlinx.coroutines.delay(150)
            throw BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
        }
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-2", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } returns jwt()
        val keyForDpop = runBlocking {
            val acquisition = async(kotlinx.coroutines.Dispatchers.Default) { invoke(r.wallet, "ensureWalletInstanceAttestation") }
            kotlinx.coroutines.delay(60) // the acquisition consumed its pending marker and is waiting for the backend
            val dpop = async(kotlinx.coroutines.Dispatchers.Default) { invoke(r.wallet, "settledInstanceKeyId") as String }
            acquisition.await()
            dpop.await()
        }
        assertEquals("the DPoP caller got the key the acquisition ended with, not the one it replaced", "attested-2", keyForDpop)
    }

    @Test
    fun anExplicitRetryRunsUnderTheWiaLock_soAnInFlightAcquisitionCannotCacheAWiaForTheRetiredKey() {
        val r = rig()
        val slowOld = jwt("old-key-wia")
        val fresh = jwt("replacement-wia")
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-1", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } coAnswers {
            kotlinx.coroutines.delay(200)
            slowOld
        }
        coEvery { r.api.generateWIA(pop = any(), challenge = "C-2", clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } returns fresh
        r.fingerprint[0] = "os-2"
        val cached = runBlocking {
            val acquisition = async(kotlinx.coroutines.Dispatchers.Default) { invoke(r.wallet, "ensureWalletInstanceAttestation") }
            kotlinx.coroutines.delay(60)
            val retry = async(kotlinx.coroutines.Dispatchers.Default) { r.wallet.retryInstanceKeyAttestation() }
            acquisition.await()
            retry.await()
            getFieldOf(r.wallet, "cachedWia") as String?
        }
        assertEquals("the cache holds the replacement key's WIA, never the retired key's", fresh, cached)
    }

    @Test
    fun oneRotationBudgetIsSharedByTheStaleReplacementTheInvalidRetryAndTheExplicitRetry() {
        // (a) a stale challenge consumes the budget: a following INVALID does not rotate again.
        val a = rig()
        val ensure = SirosWallet::class.declaredMemberFunctions.first { it.name == "ensureInstanceKeyId" }
        ensure.isAccessible = true
        runBlocking { ensure.callSuspend(a.wallet) }
        a.clock[0] += 10 * 60 * 1000
        coEvery { a.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws
            BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
        assertNull(obtain(a.wallet))
        coVerify(exactly = 2) { a.keystore.generateAttestedKey(any(), any()) } // the original and the ONE replacement
        coVerify(exactly = 1) { a.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) }
        // (b) an explicit retry makes exactly one key even when its acquisition is refused.
        val b = rig()
        coEvery { b.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } returns jwt()
        assertNotNull(obtain(b.wallet))
        coEvery { b.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws
            BackendApiException(400, "invalid", """{"error":"KEY_ATTESTATION_INVALID"}""")
        runBlocking { b.wallet.retryInstanceKeyAttestation() } // refused: false, and no second key
        coVerify(exactly = 2) { b.keystore.generateAttestedKey(any(), any()) } // the original and the retry's ONE key, no second
    }

    @Test
    fun afterNotQualifying_noOtherAcquisitionReSendsTheSameRejectedKey() {
        val r = rig()
        coEvery { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) } throws notQualifying("bootloader_unlocked")
        assertNull(obtain(r.wallet))
        // A DPoP request (settlement) and another acquisition: the rejected key is not sent again, with or without a fresh challenge.
        invoke(r.wallet, "settledInstanceKeyId")
        assertNull(obtain(r.wallet))
        coVerify(exactly = 1) { r.api.generateWIA(pop = any(), challenge = any(), clientId = any(), nativeAttestation = any(), credentialId = any(), keyAttestation = any()) }
    }
}
