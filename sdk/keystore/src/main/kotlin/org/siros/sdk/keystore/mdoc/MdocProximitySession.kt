// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import org.siros.sdk.credentials.CredentialFamily
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.StoredCredential
import timber.log.Timber

/** The user's answer to a [RequestProximityConsent] prompt. */
sealed interface ProximityConsentResult {
    data class Approved(val family: CredentialFamily) : ProximityConsentResult
    data object Denied : ProximityConsentResult
}

/**
 * Asks the user to approve a proximity presentation before it's signed and
 * sent - shared by both BLE roles ([MdocProximitySession] is transport-role
 * agnostic) so central and peripheral mode go through the same UI contract,
 * implemented by the host app as a suspending bridge to its own consent UI.
 *
 * @param docType the requested document type.
 * @param requestedClaims the flattened element identifiers the reader asked for.
 * @param matchingFamilies every credential family whose docType matches
 *   (never empty - [MdocProximitySession] only invokes this once at least
 *   one match exists; see [CredentialFamily] for why this is families, not
 *   raw instances), for the user to choose among if there's more than one
 *   (e.g. the same docType from two different issuers).
 */
typealias RequestProximityConsent = suspend (
    docType: String,
    requestedClaims: List<String>,
    matchingFamilies: List<CredentialFamily>,
) -> ProximityConsentResult

/**
 * ISO 18013-5 §8.3.3.1.1/§11.1.3 mdoc-side proximity session logic, shared by
 * both BLE roles (`BlePeripheralServer`'s "mdoc peripheral server mode" and
 * `BleCentralClient`'s "mdoc central client mode" in each host app): given a
 * raw `SessionEstablishment` message, derives the session keys (trying both
 * the QR and NFC static-handover transcripts, since BLE alone can't tell
 * which one a real reader used), decrypts and parses the mdoc request,
 * matches stored credentials by `docType`, asks the host to obtain user
 * consent, filters to eligible (unconsumed) instances, picks one at random
 * (preserving unlinkability across repeated presentations), then signs and
 * encrypts the `DeviceResponse`.
 *
 * Deliberately excludes anything BLE/GATT-specific (chunking/reassembly,
 * characteristic reads/writes, MTU negotiation, completion signaling) - the
 * two host-app BLE classes differ in exactly those respects (e.g. GATT
 * notify vs GATT write + `STATE_END`), so they stay thin transport glue
 * calling into one instance of this class per session.
 *
 * One instance is scoped to exactly one proximity session: [deviceCipher]
 * is derived once inside [handleSessionEstablishment] and reused if a host
 * ever needs to encrypt/decrypt further `SessionData` after the initial
 * request/response (not currently exercised by either host app).
 */
class MdocProximitySession(
    private val engagement: DeviceEngagement.Engagement,
    /**
     * Returns the NFC static handover's `HandoverSelect` message bytes for
     * this engagement, if the host is also offering NFC handover for it, or
     * null if only QR is offered. Deliberately a callback rather than a
     * plain field: on Android, this value is only knowable via the
     * `MdocHostApduService`-scoped singleton the host app owns (an Android
     * HCE service the platform instantiates independently of app/session
     * lifecycle), which this SDK-level class must stay decoupled from.
     */
    private val getHandoverSelectBytes: () -> ByteArray?,
    /** Mirrors `SirosWallet.getCredentials` - injected rather than taking a `SirosWallet` directly, keeping this class independent of the wallet facade. */
    private val getCredentials: suspend () -> List<StoredCredential>,
    /** Mirrors `SirosWallet.signMdocPresentationForProximity`. */
    private val signPresentation: suspend (credentialId: Long, disclosedClaims: List<String>?, sessionTranscriptBytes: ByteArray) -> ByteArray,
    /** See [RequestProximityConsent]'s doc comment. */
    private val requestConsent: RequestProximityConsent,
    /**
     * Mirrors `CredentialUtils.eligibleInstances` bound to the caller's
     * current `SirosWallet.credentialConsumptionPolicy`/`presentationHistory` -
     * excludes instances the active consumption policy considers already
     * used up, so a family the user approves can't sign with an exhausted
     * instance even if [requestConsent]'s UI failed to grey it out.
     */
    private val filterEligible: (List<StoredCredential>) -> List<StoredCredential>,
    /** Reports a canonical step token (see `FlowStepCatalog.proximitySteps`) for driving the same progress-bar UI the issuance/presentation flows use. */
    private val onStep: (String) -> Unit,
    /** Log-tag prefix distinguishing which BLE role a given session belongs to in shared logs (e.g. "BlePeripheralServer", "BleCentralClient"). */
    private val logTag: String,
) {
    /** Outcome of [handleSessionEstablishment] - the caller decides how to actually transmit [Response.sessionData] (GATT notify vs GATT write) and how to signal completion. */
    sealed interface Result {
        /** An encrypted `SessionData` response ready to send back to the reader. */
        data class Response(val sessionData: ByteArray) : Result
        /** The user declined the consent prompt. */
        data object Denied : Result
        /** [reason] is log-only context, not user-facing. */
        data class Failed(val reason: String) : Result
    }

    private var deviceCipher: ProximitySessionCrypto.SessionCipher? = null

    /** True once session keys have been successfully derived for this session. */
    val established: Boolean get() = deviceCipher != null

    suspend fun handleSessionEstablishment(message: ByteArray): Result {
        onStep("parsing_request")
        val establishment = ProximitySessionMessages.parseSessionEstablishment(message)
        val eReaderPublicKey = ProximitySessionCrypto.parseEReaderKeyPublic(establishment.eReaderKeyBytes)

        // This engagement may be offered simultaneously via both QR and NFC
        // static handover - the Handover field of the SessionTranscript
        // differs by which one the reader actually used, and BLE has no way
        // to know which. Try the QR transcript (Handover = null) first since
        // it's the common case; if AEAD decryption fails, retry with the NFC
        // transcript (Handover = [HandoverSelect, null]) before giving up.
        // NB: not `listOfNotNull(null, ...)` - that drops the literal null
        // entry (it's designed to filter nulls out), which would silently
        // skip the QR candidate entirely.
        val candidateHandovers: List<ByteArray?> = buildList {
            add(null)
            getHandoverSelectBytes()?.let { add(it) }
        }
        var requestBytes: ByteArray? = null
        var sessionTranscript: ByteArray = ProximitySessionTranscript.build(
            deviceEngagementBytes = engagement.deviceEngagementBytes,
            eReaderKeyBytes = establishment.eReaderKeyBytes,
            handoverSelectMessageBytes = null,
        )
        var keys: ProximitySessionCrypto.SessionKeys? = null
        for (handoverSelectMessageBytes in candidateHandovers) {
            val transcript = ProximitySessionTranscript.build(
                deviceEngagementBytes = engagement.deviceEngagementBytes,
                eReaderKeyBytes = establishment.eReaderKeyBytes,
                handoverSelectMessageBytes = handoverSelectMessageBytes,
            )
            val candidateKeys = ProximitySessionCrypto.deriveSessionKeys(engagement.privateKey, eReaderPublicKey, transcript)
            requestBytes = try {
                ProximitySessionCrypto.readerCipher(candidateKeys.skReader).decrypt(establishment.encryptedData)
            } catch (e: javax.crypto.AEADBadTagException) {
                null
            }
            if (requestBytes != null) {
                sessionTranscript = transcript
                keys = candidateKeys
                break
            }
        }
        if (requestBytes == null || keys == null) {
            Timber.w("$logTag: session key derivation failed for both QR and NFC handover transcripts")
            return Result.Failed("session key derivation failed")
        }
        deviceCipher = ProximitySessionCrypto.deviceCipher(keys.skDevice)

        val docRequests = DeviceRequestParser.parse(requestBytes)
        val docRequest = docRequests.firstOrNull()
        if (docRequest == null) {
            Timber.w("$logTag: request contained no documents")
            return Result.Failed("no documents requested")
        }

        onStep("match_credentials")
        val matches = CredentialMatcher.matchMdocDocType(getCredentials(), docRequest.docType)
        if (matches.isEmpty()) {
            Timber.w("$logTag: no stored credential matches requested docType '${docRequest.docType}'")
            return Result.Failed("no matching credential")
        }
        val families = CredentialUtils.groupIntoFamilies(matches)
        onStep("awaiting_consent")
        val consent = requestConsent(docRequest.docType, docRequest.disclosedClaims(), families)
        val family = when (consent) {
            is ProximityConsentResult.Approved -> consent.family
            ProximityConsentResult.Denied -> return Result.Denied
        }
        val eligible = filterEligible(family.instances)
        if (eligible.isEmpty()) {
            Timber.w("$logTag: no eligible (unused) instances remain for the approved credential")
            return Result.Failed("no eligible instances")
        }
        // Pick a random instance from the batch rather than always the same
        // one - each instance is bound to its own device key specifically so
        // repeated presentations of "the same" credential can't be
        // correlated by a verifier via a reused public key. Always picking
        // instance 0 would quietly throw that unlinkability away.
        val credential = eligible.random()

        onStep("submitting_response")
        val response = signPresentation(credential.id, docRequest.disclosedClaims(), sessionTranscript)
        val encrypted = deviceCipher!!.encrypt(response)
        val sessionData = ProximitySessionMessages.buildSessionData(encryptedData = encrypted)
        return Result.Response(sessionData)
    }
}
