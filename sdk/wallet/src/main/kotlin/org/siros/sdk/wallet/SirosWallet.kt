// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import android.app.Activity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.putJsonObject
import org.siros.sdk.auth.AuthSession
import org.siros.sdk.auth.AuthServerClient
import org.siros.sdk.auth.AuthTokens
import org.siros.sdk.auth.BackendApiClient
import org.siros.sdk.auth.AuthProvider
import org.siros.sdk.auth.CredentialManagerAuthProvider
import org.siros.sdk.auth.LocalAuthProvider
import org.siros.sdk.auth.PrfOutput
import org.siros.sdk.auth.WebAuthnAuthClient
import org.siros.sdk.credentials.AuthException
import org.siros.sdk.credentials.BackendApiException
import org.siros.sdk.credentials.KeystoreException
import org.siros.sdk.credentials.NetworkException
import org.siros.sdk.credentials.SirosException
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.credentials.InMemoryCredentialStore
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.CredentialOffer
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.IssuerEntry
import org.siros.sdk.credentials.IssuerMetadata
import org.siros.sdk.credentials.CredentialConfiguration
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.Vctm
import org.siros.sdk.credentials.VctmFetcher
import org.siros.sdk.credentials.MddlSchemaFetcher
import org.siros.sdk.keystore.DCAPIResponseEncryption
import org.siros.sdk.keystore.JweKeystore
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.wallet.dcapi.DCAPIRequest
import org.siros.sdk.wallet.dcapi.DCAPIRequestParser
import org.siros.sdk.transport.CredentialNotifier
import org.siros.sdk.transport.engine.CredentialMatch
import org.siros.sdk.transport.engine.CredentialNotificationEvent
import org.siros.sdk.transport.engine.ProofObject
import org.siros.sdk.transport.engine.WalletEngineSession
import okhttp3.OkHttpClient
import okhttp3.Request
import timber.log.Timber
import java.security.SecureRandom
import java.util.Base64

/**
 * Main entry point for the SIROS Wallet SDK.
 *
 * Provides a single, self-contained API for wallet apps:
 *
 * ```kotlin
 * val wallet = SirosWallet.create(activity, WalletConfig("https://wallet.sirosid.dev"))
 * wallet.login()               // WebAuthn + PRF + keystore + engine — all automatic
 * wallet.state.collect { ... }  // observe state to drive UI
 * ```
 *
 * The SDK handles WebAuthn authentication with PRF extension, HKDF key
 * derivation, JWE keystore unlock, encrypted private-data sync with the
 * backend, and the engine WebSocket session for issuance/presentation flows.
 *
 * The only things the host app is responsible for are:
 * 1. Providing an [Activity] context (for the passkey system UI).
 * 2. Observing [state] and rendering the appropriate screens.
 * 3. Implementing [WalletEventListener] for credential-selection UX.
 */

/**
 * Context saved from an `authorization_required` progress message, needed to resume
 * an OID4VCI flow after the OAuth browser redirects back to the app.
 *
 * The WebSocket session that started the flow very often will not survive the
 * redirect step - Android backgrounds/throttles the app while the external browser
 * (or Custom Tab) is in the foreground, and the engine session dies with it (see
 * [SirosWallet.completeAuthorization]). [offerJson] is the exact `credential_offer`
 * object the backend already parsed, round-tripped verbatim so resume never needs
 * to re-fetch a possibly single-use `credential_offer_uri`.
 */
private data class PendingAuthorization(
    val offerJson: String?,
    val redirectUri: String,
    val codeVerifier: String?,
    val state: String,
)

class SirosWallet private constructor(
    private val activity: Activity,
    private val config: WalletConfig,
) {
    // ── Public API ──────────────────────────────────────────────────

    private val _state = MutableStateFlow<WalletState>(WalletState.Disconnected())

    /** Observable wallet state. Collect this from your UI layer. */
    val state: StateFlow<WalletState> = _state.asStateFlow()

    /** Helper: build Disconnected with current cached accounts. */
    private fun disconnectedState() = WalletState.Disconnected(
        cachedAccounts = accountRegistry.listLoginableAccounts(),
    )

    /** Helper: build Ready with current cached accounts. */
    private fun readyState(userId: String, displayName: String?, credentials: List<org.siros.sdk.credentials.StoredCredential>) =
        WalletState.Ready(userId = userId, displayName = displayName, credentials = credentials,
            cachedAccounts = accountRegistry.listAccounts())

    /** All known accounts across all tenants. Survives logout. */
    fun listAccounts(): List<CachedAccount> = accountRegistry.listAccounts()

    /** Accounts that have passkeys and can log in. */
    fun listLoginableAccounts(): List<CachedAccount> = accountRegistry.listLoginableAccounts()

    /**
     * Get a valid access token for authenticated API calls (e.g., IDV backend).
     * Returns the raw JWT string. Throws if no session is active.
     */
    suspend fun getAccessToken(): String {
        return authTokens.ensureBackendToken().raw
    }

    /** Remove a cached account (forgets it from the login screen). */
    fun forgetAccount(accountId: String) {
        accountRegistry.removeAccount(accountId)
        if (accountRegistry.activeAccountId == accountId) {
            logout()
        } else {
            // Re-emit state so UI reflects the removed account
            _state.value = disconnectedState()
        }
    }

    /**
     * Delete the currently active account: removes it from the local account
     * registry (so it no longer lingers as a cached "Welcome back" entry on
     * the login screen) and logs out. There's no server-side account
     * deletion endpoint - this is [forgetAccount] scoped to whichever
     * account is currently active, which is what "delete" is expected to do
     * from the logged-in Settings screen.
     */
    fun deleteAccount() {
        val activeId = accountRegistry.activeAccountId
        if (activeId != null) {
            forgetAccount(activeId)
        } else {
            logout()
        }
    }

    // ── Passkey Management ──────────────────────────────────────────

    /**
     * Passkeys registered for the active account.
     * Returns from the local AccountRegistry cache (not the backend).
     */
    fun listPasskeys(): List<CachedPasskey> {
        val active = accountRegistry.activeAccountId ?: return emptyList()
        return accountRegistry.findAccount(active)?.passkeys ?: emptyList()
    }

    /**
     * Rename a passkey (local only — updates the AccountRegistry).
     */
    fun renamePasskey(credentialId: String, nickname: String) {
        val active = accountRegistry.activeAccountId ?: return
        val account = accountRegistry.findAccount(active) ?: return
        val updated = account.copy(
            passkeys = account.passkeys.map {
                if (it.credentialId == credentialId) it.copy(nickname = nickname) else it
            }
        )
        accountRegistry.upsertAccount(updated)
    }

    /** Set a listener for events that require user interaction (credential picker, etc.). */
    fun setEventListener(listener: WalletEventListener) {
        eventListener = listener
    }

    /**
     * Register a new user with a passkey.
     *
     * This single call:
     * 1. Gets a registration challenge from the backend.
     * 2. Creates a passkey via the system UI (with PRF extension).
     * 3. Derives an encryption key from the PRF output.
     * 4. Initialises an empty encrypted keystore.
     * 5. Sends the encrypted keystore to the backend as `privateData`.
     * 6. Opens the engine WebSocket.
     *
     * @param displayName the user's display name for the passkey.
     * @throws WalletException if registration fails.
     * @throws IllegalArgumentException if displayName is blank or too long.
     */
    suspend fun register(displayName: String) {
        require(displayName.isNotBlank() && displayName.length <= 256) {
            "displayName must be 1-256 characters"
        }
        _state.value = WalletState.Connecting
        try {
            ensureAuthMode()
            when (authMode) {
                AuthMode.LEGACY_AS -> legacyRegister(displayName)
                else -> newAsRegister(displayName)
            }
        } catch (e: SirosException) {
            Timber.e(e, "Registration failed")
            rollbackLocalCredential()
            _state.value = WalletState.Error(e.message ?: "Registration failed")
        } catch (e: Exception) {
            Timber.e(e, "Registration failed")
            rollbackLocalCredential()
            _state.value = WalletState.Error(e.message ?: "Registration failed")
            throw WalletException("Registration failed", e)
        }
    }

    private suspend fun newAsRegister(displayName: String) {
        // Generate a fresh PRF salt for this registration
        val prfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfInfo = HKDF_INFO.toByteArray(Charsets.UTF_8)

        // Step 1: Get challenge from AS
        val challengeResponse = authServerClient.registerBegin()
        val challengeId = challengeResponse["challengeId"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing challengeId in register begin response")
        val createOptions = challengeResponse["createOptions"]?.jsonObject
            ?: throw WalletException("Missing createOptions")
        val publicKey = createOptions["publicKey"]?.jsonObject
            ?: throw WalletException("Missing publicKey in createOptions")

        val rpObj = publicKey["rp"]?.jsonObject
            ?: throw WalletException("Missing rp in publicKey")
        val rpId = rpObj["id"]?.jsonPrimitive?.contentOrNull ?: throw WalletException("Missing rp.id")
        val rpName = rpObj["name"]?.jsonPrimitive?.contentOrNull ?: rpId
        val challenge = WebAuthnAuthClient.decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing challenge"))
        val userObj = publicKey["user"]?.jsonObject
            ?: throw WalletException("Missing user in publicKey")
        val userId = WebAuthnAuthClient.decodeBase64Url(userObj["id"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing user.id"))
        val userName = userObj["name"]?.jsonPrimitive?.contentOrNull ?: displayName

        // Step 2: Create credential via platform AuthProvider
        val result = authProvider.register(
            org.siros.sdk.auth.RegisterOptions(
                rpId = rpId,
                rpName = rpName,
                userId = userId,
                userName = userName,
                userDisplayName = displayName,
                challenge = challenge,
                prfSalt = prfSalt,
            )
        )

        // Step 3: Complete registration with AS
        val credentialJson = kotlinx.serialization.json.buildJsonObject {
            put("id", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
            put("rawId", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
            put("type", kotlinx.serialization.json.JsonPrimitive("public-key"))
            put("response", kotlinx.serialization.json.buildJsonObject {
                put("attestationObject", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.attestationObject)))
                put("clientDataJSON", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.clientDataJSON)))
            })
        }
        val session = authServerClient.registerFinish(
            challengeId = challengeId,
            credential = credentialJson,
            displayName = displayName,
        )
        Timber.i("Registration successful: ${session.uuid}")

        val credId = extractLastCredentialId()
            ?: throw WalletException("No credential ID after registration")
        val prfOutput = extractLastPrfOutput()
            ?: throw WalletException("PRF not supported by authenticator — cannot encrypt wallet data")

        finishRegistration(
            userId = session.uuid,
            displayName = session.displayName,
            givenDisplayName = displayName,
            credId = credId,
            prfOutput = prfOutput,
            prfSalt = prfSalt,
            hkdfSalt = hkdfSalt,
            hkdfInfo = hkdfInfo,
            appToken = null,
        )
    }

    private suspend fun legacyRegister(displayName: String) {
        // Generate a fresh PRF salt for this registration
        val prfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfInfo = HKDF_INFO.toByteArray(Charsets.UTF_8)

        val session = legacyAuthClient.register(displayName = displayName, prfSalt = prfSalt)
        Timber.i("Legacy registration successful: ${session.uuid}")

        val credId = extractLastCredentialId()
            ?: throw WalletException("No credential ID after registration")
        val prfOutput = extractLastPrfOutput()
            ?: throw WalletException("PRF not supported by authenticator — cannot encrypt wallet data")

        finishRegistration(
            userId = session.uuid,
            displayName = session.displayName,
            givenDisplayName = displayName,
            credId = credId,
            prfOutput = prfOutput,
            prfSalt = prfSalt,
            hkdfSalt = hkdfSalt,
            hkdfInfo = hkdfInfo,
            appToken = session.appToken,
        )
    }

    private suspend fun finishRegistration(
        userId: String,
        displayName: String?,
        givenDisplayName: String,
        credId: ByteArray,
        prfOutput: PrfOutput,
        prfSalt: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
        appToken: String?,
    ) {
        // Derive key and initialise empty keystore
        keystore.unlock(prfOutput.first, ByteArray(0), hkdfSalt, hkdfInfo)
        keystore.setCredentialId(credId)
        val encryptedContainer = try {
            keystore.exportEncryptedContainer()
        } catch (_: UnsupportedOperationException) { null }

        // Register account in the persistent registry (survives logout)
        val accountId = "${config.tenantId}:${userId}"
        accountRegistry.upsertAccount(CachedAccount(
            userId = userId,
            tenantId = config.tenantId,
            displayName = givenDisplayName,
            backendUrl = config.backendUrl,
            passkeys = listOf(CachedPasskey(
                credentialId = b64UrlEncode(credId),
                prfSalt = b64Encode(prfSalt),
            )),
            hkdfSalt = b64Encode(hkdfSalt),
            hkdfInfo = b64Encode(hkdfInfo),
        ))
        accountRegistry.activeAccountId = accountId

        // Scope session store to this account
        sessionStore.activeAccountId = accountId
        sessionStore.userId = userId
        sessionStore.displayName = displayName ?: givenDisplayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = b64UrlEncode(credId)
        sessionStore.prfSalt = b64Encode(prfSalt)
        sessionStore.hkdfSalt = b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = b64Encode(hkdfInfo)
        encryptedContainer?.let {
            sessionStore.privateDataJwe = String(it, Charsets.UTF_8)
        }

        if (appToken != null) {
            setupApiClient(AuthSession(appToken = appToken, uuid = userId, displayName = displayName))
            legacyAppToken = appToken
            sessionStore.appToken = appToken
        } else {
            setupApiClientWithTokens()
        }
        syncPrivateDataToBackend()

        // Connect engine with anonymous token (new AS) or app token (legacy AS)
        connectEngineWithToken()

        _state.value = WalletState.Ready(
            userId = userId,
            displayName = displayName ?: givenDisplayName,
            credentials = credentialStore.getAll(),
        )
    }

    /**
     * Login with an existing passkey.
     *
     * This single call:
     * 1. Gets a login challenge from the backend.
     * 2. Authenticates via the system passkey UI (with PRF extension).
     * 3. Derives the encryption key from the PRF output.
     * 4. Downloads the encrypted keystore (`privateData`) from the backend.
     * 5. Unlocks the keystore.
     * 6. Opens the engine WebSocket.
     */
    /**
     * @param accountId if given, log in as this specific cached account
     *   (e.g. the user tapped "Welcome back, <name>") - the WebAuthn ceremony
     *   is scoped to just that account's own passkey(s). If null, every
     *   loginable account's passkeys are offered as candidates via WebAuthn's
     *   `prf.evalByCredential` extension (see [loginCandidates]), since which
     *   one the user actually authenticates with is only known once the
     *   discoverable-credential ceremony completes.
     */
    suspend fun login(accountId: String? = null) {
        _state.value = WalletState.Connecting
        try {
            ensureAuthMode()
            if (accountId != null) {
                sessionStore.activeAccountId = accountId
            } else {
                restoreActiveAccountForLogin()
            }
            when (authMode) {
                AuthMode.LEGACY_AS -> legacyLogin(accountId)
                else -> newAsLogin(accountId)
            }
        } catch (e: SirosException) {
            Timber.e(e, "Login failed")
            _state.value = WalletState.Error(e.message ?: "Login failed")
        } catch (e: Exception) {
            Timber.e(e, "Login failed")
            _state.value = WalletState.Error(e.message ?: "Login failed")
            throw WalletException("Login failed", e)
        }
    }

    /**
     * Ensure [sessionStore] has *some* account scoped before login, purely so
     * reads made before the WebAuthn ceremony resolves (e.g. UI state) have
     * something sensible to show - [scopeSessionStoreToCredential] is what
     * actually matters for correctness, since it re-scopes to whichever
     * account the ceremony resolves to. Falls back to the single loginable
     * account when there's exactly one, since [logout] clears
     * [AccountRegistry.activeAccountId] and there's nothing else to restore
     * from at that point.
     */
    private fun restoreActiveAccountForLogin() {
        if (sessionStore.activeAccountId != null) return
        accountRegistry.activeAccountId?.let {
            sessionStore.activeAccountId = it
            return
        }
        accountRegistry.listLoginableAccounts().singleOrNull()?.let {
            sessionStore.activeAccountId = it.accountId
        }
    }

    /**
     * Build (credentialId, prfSalt) pairs for every passkey login should
     * offer as a candidate - mirrors WebAuthn's `prf.evalByCredential`
     * extension (see [org.siros.sdk.auth.AuthenticateOptions.prfSaltsByCredential],
     * and wallet-frontend's `makeAssertionPrfExtensionInputs`). Scoped to
     * just [accountId]'s own passkeys when given; otherwise every loginable
     * account's passkeys are offered, so the platform authenticator can
     * evaluate PRF with the right salt no matter which credential the user
     * picks, all within one ceremony - no fixed/shared salt, no guessing the
     * account in advance, no second prompt.
     */
    private fun loginCandidates(accountId: String?): List<Pair<ByteArray, ByteArray>> {
        val accounts = accountId?.let { listOfNotNull(accountRegistry.findAccount(it)) }
            ?: accountRegistry.listLoginableAccounts()
        return accounts.flatMap { account ->
            account.passkeys.mapNotNull { passkey ->
                if (passkey.prfSalt.isBlank()) return@mapNotNull null
                b64UrlDecode(passkey.credentialId) to b64Decode(passkey.prfSalt)
            }
        }
    }

    /**
     * Scope [sessionStore] to whichever cached account owns [credId], now
     * that the login ceremony has resolved which credential was actually
     * used. [finishLogin] reads sessionStore.hkdfSalt/hkdfInfo before it
     * derives an accountId from the server's confirmed userId, so this must
     * run before that call, or the wrong (or a freshly-generated, WRONG)
     * salt gets used to derive the decryption key and the correctly-resolved
     * PRF output from [loginCandidates] ends up wasted.
     */
    private fun scopeSessionStoreToCredential(credId: ByteArray) {
        val credIdB64url = b64UrlEncode(credId)
        accountRegistry.listAccounts()
            .find { acc -> acc.passkeys.any { it.credentialId == credIdB64url } }
            ?.let { sessionStore.activeAccountId = it.accountId }
    }

    private suspend fun newAsLogin(accountId: String?) {
        val prfCandidates = loginCandidates(accountId)

        // Step 1: Get challenge from AS
        val challengeResponse = authServerClient.loginBegin()
        val challengeId = challengeResponse["challengeId"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing challengeId in login begin response")
        val getOptions = challengeResponse["getOptions"]?.jsonObject
            ?: throw WalletException("Missing getOptions")
        val publicKey = getOptions["publicKey"]?.jsonObject
            ?: throw WalletException("Missing publicKey in getOptions")

        val rpId = publicKey["rpId"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing rpId")
        val challenge = WebAuthnAuthClient.decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.contentOrNull
            ?: throw WalletException("Missing challenge"))

        // Step 2: Authenticate via platform AuthProvider
        val result = authProvider.authenticate(
            org.siros.sdk.auth.AuthenticateOptions(
                rpId = rpId,
                challenge = challenge,
                prfSaltsByCredential = prfCandidates.ifEmpty { null },
            )
        )

        // Step 3: Complete login with AS
        val credentialJson = kotlinx.serialization.json.buildJsonObject {
            put("id", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
            put("rawId", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
            put("type", kotlinx.serialization.json.JsonPrimitive("public-key"))
            put("response", kotlinx.serialization.json.buildJsonObject {
                put("authenticatorData", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.authenticatorData)))
                put("clientDataJSON", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.clientDataJSON)))
                put("signature", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.signature)))
                result.userHandle?.let { put("userHandle", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(it))) }
            })
        }
        val session = authServerClient.loginFinish(
            challengeId = challengeId,
            credential = credentialJson,
        )
        Timber.i("Login successful: ${session.uuid}")

        val credId = extractLastCredentialId()
            ?: throw WalletException("No credential ID after login")
        scopeSessionStoreToCredential(credId)
        val prfOutput = extractLastPrfOutput()
            ?: throw WalletException("PRF not supported by authenticator — cannot decrypt wallet data")

        // Set up API client with AuthTokens and fetch private data
        setupApiClientWithTokens()
        finishLogin(session.uuid, session.displayName, credId, prfOutput)
    }

    private suspend fun legacyLogin(accountId: String?) {
        val prfCandidates = loginCandidates(accountId)
        val session = legacyAuthClient.login(prfSaltsByCredential = prfCandidates.ifEmpty { null })
        Timber.i("Legacy login successful: ${session.uuid}")

        val credId = extractLastCredentialId()
            ?: throw WalletException("No credential ID after login")
        scopeSessionStoreToCredential(credId)
        val prfOutput = extractLastPrfOutput()
            ?: throw WalletException("PRF not supported by authenticator — cannot decrypt wallet data")

        setupApiClient(session)
        legacyAppToken = session.appToken
        sessionStore.appToken = session.appToken
        finishLogin(session.uuid, session.displayName, credId, prfOutput)
    }

    private suspend fun finishLogin(
        userId: String,
        displayName: String?,
        credId: ByteArray,
        prfOutput: PrfOutput,
    ) {
        val privateData = fetchPrivateData()

        val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
            ?: ByteArray(32).also { SecureRandom().nextBytes(it) }
        val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }
            ?: HKDF_INFO.toByteArray(Charsets.UTF_8)
        val prfSaltBytes = sessionStore.prfSalt?.let { b64Decode(it) }
            ?: ByteArray(32).also { SecureRandom().nextBytes(it) }

        keystore.unlock(prfOutput.first, privateData, hkdfSalt, hkdfInfo)

        // Scope session store to this account
        val accountId = "${config.tenantId}:${userId}"
        sessionStore.activeAccountId = accountId
        accountRegistry.activeAccountId = accountId
        sessionStore.userId = userId
        sessionStore.displayName = displayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = b64UrlEncode(credId)
        sessionStore.prfSalt = b64Encode(prfSaltBytes)
        sessionStore.hkdfSalt = b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = b64Encode(hkdfInfo)

        // Connect engine with anonymous token (new AS) or app token (legacy AS)
        connectEngineWithToken()

        _state.value = WalletState.Ready(
            userId = userId,
            displayName = displayName,
            credentials = credentialStore.getAll(),
        )
        hydrateReloadedCredentials()
    }

    /**
     * After loading credentials from a reimported private-data container
     * (fresh login here, or [unlockKeystore] after [resumeSession]), re-fetch
     * VCTM display metadata and re-derive issuedAt/expiresAt for any
     * credential that's missing them.
     *
     * privatedata-spec's container format doesn't persist `metadata`/
     * `issuedAt`/`expiresAt` at all - wallet-frontend's own schema
     * (`WalletSessionEventNewCredential`) has no such fields either, since it
     * re-fetches/derives this live rather than snapshotting it into the
     * encrypted container. Without this, a freshly-reimported credential
     * would display with no VCTM styling/claim labels or expiry indefinitely
     * (metadata is never null for a credential saved earlier in the same
     * session, only for one just reconstructed from a container).
     *
     * Fire-and-forget: re-emits [WalletState.Ready] with the refreshed list
     * once done, rather than blocking login/unlock on however many VCTM
     * fetches are needed.
     */
    private fun hydrateReloadedCredentials() {
        scope.launch {
            var changed = false
            for (cred in credentialStore.getAll()) {
                if (cred.metadata != null) continue
                val issuerIdent = cred.credentialIssuerIdentifier
                val configId = cred.credentialConfigurationId

                if (cred.format == "mso_mdoc") {
                    // mdoc has no JWT iat/exp claims to re-derive here (ISO
                    // 18013-5 validity lives in the MSO's validityInfo, inside
                    // issuerAuth - deliberately not parsed by this wallet, see
                    // MdocCbor's doc comment: MSO parsing is a verifier-side
                    // concern this holder doesn't need). Only metadata (via
                    // MDDLSchema) is re-hydrated here.
                    if (issuerIdent.isNullOrBlank() || configId.isNullOrBlank()) continue
                    val mddlSchema = try {
                        mddlSchemaFetcher.fetch(issuerUrl = issuerIdent, scope = configId)
                    } catch (e: Exception) {
                        Timber.w(e, "Failed to re-fetch MDDL schema for reloaded credential ${cred.id}")
                        null
                    } ?: continue
                    val metadata = CredentialUtils.buildMdocMetadata(
                        offer = CredentialOffer(
                            credentialConfigurationId = configId,
                            credentialIssuerIdentifier = issuerIdent,
                            credentialName = cred.format,
                            issuerName = issuerIdent,
                        ),
                        mddlSchema = mddlSchema,
                    )
                    credentialStore.save(cred.copy(metadata = metadata))
                    changed = true
                    continue
                }

                val payload = CredentialUtils.parseJwtPayload(cred.raw) ?: continue
                val issuedAt = payload["iat"]?.jsonPrimitive?.longOrNull
                val expiresAt = payload["exp"]?.jsonPrimitive?.longOrNull
                val vct = payload["vct"]?.jsonPrimitive?.contentOrNull
                val vctm = if (!issuerIdent.isNullOrBlank() && !configId.isNullOrBlank()) {
                    try {
                        vctmFetcher.fetch(issuerUrl = issuerIdent, scope = configId, vct = vct)
                    } catch (e: Exception) {
                        Timber.w(e, "Failed to re-fetch VCTM for reloaded credential ${cred.id}")
                        null
                    }
                } else {
                    null
                }
                val metadata = vctm?.let {
                    CredentialUtils.buildMetadata(
                        offer = CredentialOffer(
                            credentialConfigurationId = configId ?: "",
                            credentialIssuerIdentifier = issuerIdent ?: "",
                            credentialName = cred.format,
                            issuerName = issuerIdent ?: "",
                        ),
                        vctm = it,
                        rawCredential = cred.raw,
                    )
                }
                if (metadata != null || issuedAt != null || expiresAt != null) {
                    credentialStore.save(
                        cred.copy(
                            metadata = metadata ?: cred.metadata,
                            issuedAt = issuedAt ?: cred.issuedAt,
                            expiresAt = expiresAt ?: cred.expiresAt,
                        )
                    )
                    changed = true
                }
            }
            if (changed) {
                val current = _state.value
                if (current is WalletState.Ready) {
                    _state.value = current.copy(credentials = credentialStore.getAll())
                }
            }
        }
    }

    /**
     * Detect whether the backend uses the new standalone AS or the legacy
     * wallet-backend-integrated auth endpoints.
     *
     * Probes `/auth/passkey/login/begin`. A 404 means the backend predates
     * the new AS and we should fall back to `/user/login-webauthn-*`.
     */
    private suspend fun detectAuthMode(): AuthMode {
        Timber.i("Detecting auth mode for ${config.backendUrl} (tenant=${config.tenantId})")
        return try {
            authServerClient.loginBegin()
            Timber.i("Detected new AS at ${config.backendUrl}")
            AuthMode.NEW_AS
        } catch (e: AuthException) {
            if (e.code == 404) {
                Timber.i("Detected legacy AS at ${config.backendUrl} (404 on /auth/passkey/login/begin)")
                AuthMode.LEGACY_AS
            } else {
                Timber.e(e, "Auth mode probe failed with HTTP ${e.code} at ${config.backendUrl}; surfacing error")
                throw e
            }
        } catch (e: Exception) {
            Timber.e(e, "Auth mode detection failed at ${config.backendUrl}; surfacing error")
            throw e
        }
    }

    private suspend fun ensureAuthMode() {
        if (authMode == AuthMode.UNKNOWN) {
            authMode = detectAuthMode()
        }
    }

    /**
     * Disconnect from the wallet backend, lock the keystore,
     * and clear session data.
     */
    fun logout() {
        engineSession?.disconnect()
        engineSession = null
        scope.launch { wmpPeer?.close() }
        wmpPeer = null
        credentialNotifier = null
        keystore.lock()
        sessionStore.clear()  // clears active account's session only
        accountRegistry.activeAccountId = null
        apiClient = null
        legacyAppToken = null
        scope.launch {
            try {
                authTokens.clear()
                authServerClient.logout()
            } catch (e: Exception) {
                Timber.w(e, "AS logout failed (non-fatal)")
            }
        }
        _state.value = disconnectedState()
        Timber.i("Logged out")
    }

    /**
     * Resume a previous session without requiring a new WebAuthn assertion.
     *
     * Uses stored `appToken` + `refreshToken` from the previous login.
     * If the stored token is expired, it will be refreshed automatically.
     * Falls back to [WalletState.Disconnected] if no session is stored.
     *
     * Call this on app startup before showing the login screen.
     */
    suspend fun resumeSession() {
        // Restore the active account ID so the session store reads the right data
        val activeId = accountRegistry.activeAccountId
        if (activeId != null) {
            sessionStore.activeAccountId = activeId
        }
        val userId = sessionStore.userId
        if (userId == null) {
            Timber.d("No stored session to resume")
            return
        }
        _state.value = WalletState.Connecting
        try {
            ensureAuthMode()
            val displayName = sessionStore.displayName

            if (authMode == AuthMode.LEGACY_AS) {
                // Legacy mode: verify the stored appToken is still valid by fetching account info
                val storedAppToken = sessionStore.appToken
                if (storedAppToken.isNullOrBlank()) {
                    Timber.i("No stored legacy appToken, need re-login")
                    sessionStore.clear()
                    _state.value = disconnectedState()
                    return
                }
                legacyAppToken = storedAppToken
                setupApiClient(AuthSession(appToken = storedAppToken, uuid = userId, displayName = displayName))
                try {
                    apiClient?.getAccountInfo()
                } catch (e: Exception) {
                    Timber.i("Legacy session invalid, need re-login")
                    sessionStore.clear()
                    apiClient = null
                    legacyAppToken = null
                    _state.value = disconnectedState()
                    return
                }
            } else {
                // Set up the API client using AuthTokens (session cookie handles auth)
                setupApiClientWithTokens()

                // Verify the session is still valid by requesting a backend token
                try {
                    authTokens.ensureBackendToken()
                } catch (e: AuthException) {
                    Timber.i("Session cookie expired, need re-login")
                    sessionStore.clear()
                    apiClient = null
                    _state.value = disconnectedState()
                    return
                }
            }

            // Unlock keystore from stored private data if available
            val storedJwe = sessionStore.privateDataJwe
            val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
            val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }

            // Connect the engine with the appropriate token
            connectEngineWithToken()

            if (storedJwe != null && hkdfSalt != null && hkdfInfo != null) {
                _state.value = WalletState.KeystoreLocked(
                    userId = userId,
                    displayName = displayName,
                )
                Timber.i("Session resumed for user $userId (keystore locked — call unlockKeystore())")
            } else {
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = emptyList(),
                )
                Timber.i("Session resumed for user $userId (no private data)")
            }
        } catch (e: SirosException) {
            Timber.e(e, "Session resume failed")
            _state.value = disconnectedState()
        } catch (e: Exception) {
            Timber.e(e, "Session resume failed")
            _state.value = disconnectedState()
        }
    }

    /**
     * Unlock the keystore after a session resume.
     *
     * Call this when the wallet is in [WalletState.KeystoreLocked].
     * Triggers a WebAuthn assertion (biometric prompt) to obtain the PRF
     * output needed to decrypt the keystore and credentials.
     *
     * After a successful unlock the state transitions to [WalletState.Ready].
     */
    suspend fun unlockKeystore() {
        val current = _state.value
        if (current !is WalletState.KeystoreLocked) {
            Timber.w("unlockKeystore called but state is $current")
            return
        }
        try {
            val storedPrfSalt = sessionStore.prfSalt?.let { b64Decode(it) }
            val prfOutput = if (authMode == AuthMode.LEGACY_AS) {
                // Legacy backend: re-authenticate via the wallet-backend endpoint
                val session = legacyAuthClient.login(prfSalt = storedPrfSalt)
                legacyAppToken = session.appToken
                sessionStore.appToken = session.appToken
                extractLastPrfOutput()
                    ?: throw WalletException("PRF not available from authenticator")
            } else {
                // New AS: use AS login flow to get PRF output via biometric assertion
                val challengeResponse = authServerClient.loginBegin()
                val challengeId = challengeResponse["challengeId"]?.jsonPrimitive?.contentOrNull
                    ?: throw WalletException("Missing challengeId")
                val getOptions = challengeResponse["getOptions"]?.jsonObject
                    ?: throw WalletException("Missing getOptions")
                val publicKey = getOptions["publicKey"]?.jsonObject
                    ?: throw WalletException("Missing publicKey")
                val rpId = publicKey["rpId"]?.jsonPrimitive?.contentOrNull
                    ?: throw WalletException("Missing rpId")
                val challenge = WebAuthnAuthClient.decodeBase64Url(publicKey["challenge"]?.jsonPrimitive?.contentOrNull
                    ?: throw WalletException("Missing challenge"))

                val result = authProvider.authenticate(
                    org.siros.sdk.auth.AuthenticateOptions(
                        rpId = rpId,
                        challenge = challenge,
                        prfSalt = storedPrfSalt,
                    )
                )

                // Complete login with AS (also refreshes the session cookie)
                val credentialJson = kotlinx.serialization.json.buildJsonObject {
                    put("id", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
                    put("rawId", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.credentialId)))
                    put("type", kotlinx.serialization.json.JsonPrimitive("public-key"))
                    put("response", kotlinx.serialization.json.buildJsonObject {
                        put("authenticatorData", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.authenticatorData)))
                        put("clientDataJSON", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.clientDataJSON)))
                        put("signature", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(result.signature)))
                        result.userHandle?.let { put("userHandle", kotlinx.serialization.json.JsonPrimitive(WebAuthnAuthClient.encodeBase64Url(it))) }
                    })
                }
                authServerClient.loginFinish(challengeId = challengeId, credential = credentialJson)

                extractLastPrfOutput()
                    ?: throw WalletException("PRF not available from authenticator")
            }

            val storedJwe = sessionStore.privateDataJwe
            val hkdfSalt = sessionStore.hkdfSalt?.let { b64Decode(it) }
                ?: throw WalletException("Missing HKDF salt")
            val hkdfInfo = sessionStore.hkdfInfo?.let { b64Decode(it) }
                ?: HKDF_INFO.toByteArray(Charsets.UTF_8)

            val privateData = storedJwe?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
            keystore.unlock(prfOutput.first, privateData, hkdfSalt, hkdfInfo)

            _state.value = WalletState.Ready(
                userId = current.userId,
                displayName = current.displayName,
                credentials = credentialStore.getAll(),
            )
            hydrateReloadedCredentials()
            Timber.i("Keystore unlocked after session resume")
        } catch (e: KeystoreException) {
            Timber.e(e, "Keystore unlock failed: corrupt container")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        } catch (e: AuthException) {
            Timber.e(e, "Keystore unlock failed: authentication error")
            _state.value = WalletState.Error(e.message ?: "Authentication failed")
        } catch (e: SirosException) {
            Timber.e(e, "Keystore unlock failed")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        } catch (e: Exception) {
            Timber.e(e, "Keystore unlock failed")
            _state.value = WalletState.Error(e.message ?: "Keystore unlock failed")
        }
    }

    /**
     * Release all resources held by this wallet instance.
     *
     * Call this when the host Activity is destroyed or the wallet is
     * no longer needed. After calling [destroy], this instance must
     * not be used again — create a new one with [create].
     */
    fun destroy() {
        engineSession?.disconnect()
        engineSession = null
        scope.launch { wmpPeer?.close() }
        wmpPeer = null
        credentialNotifier = null
        keystore.lock()
        apiClient = null
        supervisorJob.cancel()
        Timber.i("Wallet instance destroyed")
    }

    /**
     * Get credentials, excluding expired ones.
     *
     * @param includeExpired when true, returns all credentials including expired.
     */
    suspend fun getCredentials(includeExpired: Boolean = false): List<StoredCredential> {
        val all = credentialStore.getAll()
        if (includeExpired) return all
        val now = System.currentTimeMillis() / 1000
        return all.filter { cred ->
            val exp = cred.expiresAt
            exp == null || exp > now
        }
    }

    /**
     * Fetch the list of available credential issuers from the backend.
     *
     * Requires an active session (call after [login] or [register]).
     * Each [IssuerEntry] contains the issuer URL; call [getAvailableCredentials]
     * to discover what credentials each issuer offers.
     */
    suspend fun getIssuers(): List<IssuerEntry> = withContext(Dispatchers.IO) {
        val client = apiClient ?: throw WalletException("Not connected")
        val response = client.getIssuers()
        // Backend user API returns a plain JSON array, admin API wraps in {"issuers": [...]}
        val arr = when (response) {
            is kotlinx.serialization.json.JsonArray -> response
            is kotlinx.serialization.json.JsonObject ->
                response["issuers"]?.jsonArray
                    ?: response["data"]?.jsonArray
                    ?: throw WalletException("Unexpected issuer list format")
            else -> throw WalletException("Unexpected issuer response type")
        }
        arr.map { json.decodeFromJsonElement(IssuerEntry.serializer(), it) }
            .filter { it.visible }
    }

    /**
     * Fetch OpenID4VCI credential issuer metadata for a given issuer URL.
     *
     * Prefers the backend proxy (which caches metadata and handles
     * internal network access). Falls back to a direct HTTP call if
     * no authenticated session is available.
     */
    suspend fun getIssuerMetadata(issuerUrl: String): IssuerMetadata = withContext(Dispatchers.IO) {
        val url = issuerUrl.trimEnd('/') + "/.well-known/openid-credential-issuer"
        val request = Request.Builder().url(url).get().build()
        val response = httpClient.newCall(request).execute()
        val body = response.body?.string()
            ?: throw WalletException("Empty metadata response from $issuerUrl")
        if (!response.isSuccessful) {
            throw WalletException("Metadata fetch failed: ${response.code}")
        }
        json.decodeFromString(IssuerMetadata.serializer(), body)
    }

    /**
     * Discover all available credentials across all visible issuers.
     *
     * Returns a flat list of [CredentialOffer] items ready for display in a
     * picker UI. Each item can be passed to [startIssuanceByOffer].
     */
    suspend fun getAvailableCredentials(): List<CredentialOffer> = withContext(Dispatchers.IO) {
        val issuers = getIssuers()
        Timber.d("getAvailableCredentials: ${issuers.size} issuers")
        val client = apiClient ?: throw WalletException("Not connected")
        val offers = mutableListOf<CredentialOffer>()

        for (issuer in issuers) {
            try {
                val metadataJson = client.getIssuerMetadata(issuer.id)
                val metadata = json.decodeFromJsonElement(IssuerMetadata.serializer(), metadataJson)
                val issuerDisplay = metadata.display?.firstOrNull()
                val issuerName = issuerDisplay?.name
                    ?: java.net.URI(issuer.credentialIssuerIdentifier).host
                    ?: issuer.credentialIssuerIdentifier

                for ((configId, config) in metadata.credentialConfigurationsSupported) {
                    val credDisplay = config.credentialMetadata?.display?.firstOrNull()
                    val credName = credDisplay?.name ?: configId
                    offers.add(CredentialOffer(
                        credentialConfigurationId = configId,
                        credentialIssuerIdentifier = issuer.credentialIssuerIdentifier,
                        credentialName = credName,
                        credentialDescription = credDisplay?.description,
                        issuerName = issuerName,
                        backgroundColor = credDisplay?.backgroundColor
                            ?: issuerDisplay?.backgroundColor,
                        textColor = credDisplay?.textColor
                            ?: issuerDisplay?.textColor,
                        logoUri = credDisplay?.logo?.uri,
                        issuerLogoUri = issuerDisplay?.logo?.uri,
                    ))
                }
            } catch (e: Exception) {
                Timber.w(e, "Failed to fetch metadata for ${issuer.credentialIssuerIdentifier}")
            }
        }
        offers
    }

    /**
     * Start an issuance flow for a specific credential offer.
     *
     * Constructs the OID4VCI credential_offer and sends it to the engine.
     */
    suspend fun startIssuanceByOffer(offer: CredentialOffer) {
        val engine = engineSession ?: throw WalletException("Not connected")
        ensureEngineConnected(engine)
        activeOffer = offer
        activeVctm = try {
            vctmFetcher.fetch(
                issuerUrl = offer.credentialIssuerIdentifier,
                scope = offer.credentialConfigurationId,
            )
        } catch (e: Exception) {
            Timber.w(e, "Failed to fetch VCTM for ${offer.credentialConfigurationId}")
            null
        }
        val credentialOffer = kotlinx.serialization.json.buildJsonObject {
            put("credential_issuer", kotlinx.serialization.json.JsonPrimitive(
                offer.credentialIssuerIdentifier
            ))
            put("credential_configuration_ids", kotlinx.serialization.json.buildJsonArray {
                add(kotlinx.serialization.json.JsonPrimitive(offer.credentialConfigurationId))
            })
            put("grants", kotlinx.serialization.json.buildJsonObject {
                if (offer.preAuthorizedCode != null) {
                    put("urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        kotlinx.serialization.json.buildJsonObject {
                            put("pre-authorized_code", kotlinx.serialization.json.JsonPrimitive(
                                offer.preAuthorizedCode
                            ))
                            if (offer.txCode != null) {
                                put("tx_code", kotlinx.serialization.json.buildJsonObject {
                                    put("input_mode", kotlinx.serialization.json.JsonPrimitive("text"))
                                })
                            }
                        })
                } else {
                    put("authorization_code", kotlinx.serialization.json.buildJsonObject {})
                }
            })
        }
        engine.startIssuance(
            offer = credentialOffer.toString(),
            redirectUri = config.redirectUri.ifBlank { null },
        )
    }

    /**
     * Start a credential issuance flow with a raw offer or URI.
     *
     * @param offerUri a credential_offer_uri or raw JSON credential_offer string.
     */
    suspend fun startIssuance(offerUri: String) {
        val engine = engineSession ?: throw WalletException("Not connected")
        ensureEngineConnected(engine)
        val redirectUri = config.redirectUri.ifBlank { null }
        if (offerUri.startsWith("openid-credential-offer://")) {
            // Deep-link URI with inline offer — send as "offer" so the engine
            // extracts the credential_offer query parameter instead of HTTP-fetching.
            engine.startIssuance(offer = offerUri, redirectUri = redirectUri)
        } else if (offerUri.startsWith("http")) {
            engine.startIssuance(credentialOfferUri = offerUri, redirectUri = redirectUri)
        } else {
            engine.startIssuance(offer = offerUri, redirectUri = redirectUri)
        }
    }

    /**
     * Start a credential presentation flow.
     *
     * @param requestUri the OID4VP request URI.
     */
    suspend fun startPresentation(requestUri: String) {
        val engine = engineSession ?: throw WalletException("Not connected")
        ensureEngineConnected(engine)
        engine.startPresentation(requestUri = requestUri)
    }

    /**
     * The final payload to hand back to the OS/browser for a W3C Digital
     * Credentials API presentation - Android's `PendingIntentHandler` (or
     * the equivalent on other platforms) wraps [responseJson] as the
     * `DigitalCredential`'s response data.
     *
     * For `response_mode=dc_api` (unencrypted): `{"vp_token": {...}}`.
     * For `response_mode=dc_api.jwt`: `{"response": "<jwe-compact>"}` per
     * OpenID4VP 1.0 Appendix A.3.2.
     */
    data class DCAPIPresentationResult(
        val responseJson: String,
        val credentialIds: List<String>,
    )

    /**
     * Process an incoming W3C Digital Credentials API (DC API) OpenID4VP
     * presentation request entirely client-side - mirrors wallet-frontend's
     * proven architecture rather than the [startPresentation]/engine-relay
     * pattern: there is no `WalletEngineSession` involvement and no
     * DC-API-specific backend call. The only backend calls made are the SAME
     * generic trust-evaluation ([evaluateTrustDirect]) and presentation-history
     * persistence the redirect flow already uses (see task #74's revised
     * finding - go-wallet-backend needs no `origin:`/`dc_api.jwt`/
     * `OpenID4VPDCAPIHandover` support under this architecture).
     *
     * @param rawRequestJson the raw request data string from the OS/browser -
     *   either a raw OpenID4VP request JSON object (unsigned protocol
     *   variant) or `{"request": "<JWT>"}` (signed/multisigned JAR variant).
     * @param origin the browser/page origin that made the
     *   `navigator.credentials.get()` call, as verified by the platform
     *   (e.g. Android's Credential Manager) - NOT read from the request body,
     *   which is untrusted until the platform attests it.
     * @throws WalletException if the user declines, or if not connected.
     */
    suspend fun handleDCAPIRequest(rawRequestJson: String, origin: String): DCAPIPresentationResult {
        val request = DCAPIRequestParser.parse(rawRequestJson)

        val subjectId = request.clientId ?: origin
        val trustResult = try {
            evaluateTrustDirect(
                subjectId = subjectId,
                subjectType = "credential_verifier",
                keyMaterialType = when {
                    request.keyMaterial?.x5c != null -> "x5c"
                    request.keyMaterial?.jwk != null -> "jwk"
                    else -> null
                },
                x5c = request.keyMaterial?.x5c?.let { chain ->
                    kotlinx.serialization.json.buildJsonArray {
                        chain.forEach { add(kotlinx.serialization.json.JsonPrimitive(it)) }
                    }
                },
                jwk = request.keyMaterial?.jwk,
                context = null,
            )
        } catch (e: Exception) {
            Timber.w(e, "DC API trust evaluation failed for $subjectId")
            trustCache.get(subjectId) ?: TrustResult(trusted = false, identifier = subjectId, reason = e.message)
        }

        val allCreds = credentialStore.getAll()
        val dcqlOutput = if (request.dcqlQuery != null) {
            CredentialMatcher.matchDcql(request.dcqlQuery, allCreds)
        } else {
            CredentialMatcher.DcqlMatchOutput(
                queryResults = listOf(CredentialMatcher.MatchResult(
                    queryId = "_default", format = null, candidates = allCreds, requestedClaims = emptyList(),
                )),
                credentialSets = null,
                satisfiableOptions = emptyList(),
            )
        }
        val matchResults = dcqlOutput.queryResults
        val candidates = matchResults.flatMap { it.candidates }.distinctBy { it.id }

        val listener = eventListener
        val selectedIds = if (listener != null && candidates.isNotEmpty()) {
            listener.onCredentialSelectionRequired(
                PresentationRequest(
                    verifierName = trustResult.entityName,
                    trustResult = trustResult,
                    matchResults = matchResults,
                    candidates = candidates,
                    credentialSets = dcqlOutput.credentialSets,
                    satisfiableOptions = dcqlOutput.satisfiableOptions,
                )
            )
        } else {
            candidates.map { it.id }
        }

        if (selectedIds.isEmpty()) {
            throw WalletException("User declined the DC API presentation request")
        }

        // "origin:<value>" per OpenID4VP 1.0 Appendix A is only used for the
        // VP token audience claim at signing time - trust evaluation above
        // uses the bare origin, matching wallet-frontend's useOID4VPFlow.ts.
        val audience = "origin:$origin"
        val encryptionJwk = if (request.responseMode == "dc_api.jwt") {
            findEncryptionJwk(request.clientMetadata)
                ?: throw WalletException("dc_api.jwt response_mode requires client_metadata.jwks with an encryption key")
        } else {
            null
        }
        val encryptionThumbprint = encryptionJwk?.computeThumbprint()?.toString()

        val vpTokenObj = kotlinx.serialization.json.buildJsonObject {
            for (id in selectedIds) {
                val cred = allCreds.find { it.id == id } ?: continue
                val matchResult = matchResults.firstOrNull { r -> r.candidates.any { it.id == id } }
                val queryId = matchResult?.queryId ?: "_default"
                val disclosedClaims = matchResult?.requestedClaims?.mapNotNull { it.lastOrNull() }

                val token = if (cred.format == "mso_mdoc") {
                    val credBytes = android.util.Base64.decode(
                        cred.raw, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
                    )
                    val deviceResponse = keystore.signMdocPresentationForDCAPI(
                        credentialBytes = credBytes,
                        disclosedClaims = disclosedClaims,
                        nonce = request.nonce,
                        origin = origin,
                        encryptionPublicJwkThumbprint = encryptionThumbprint,
                    )
                    android.util.Base64.encodeToString(
                        deviceResponse, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
                    )
                } else {
                    keystore.signVpToken(
                        credential = cred.raw,
                        disclosedClaims = disclosedClaims,
                        nonce = request.nonce,
                        audience = audience,
                    )
                }
                put(queryId, kotlinx.serialization.json.JsonPrimitive(token))
            }
        }

        val responseBody = kotlinx.serialization.json.buildJsonObject {
            put("vp_token", vpTokenObj)
        }.toString()

        val finalResponseJson = if (request.responseMode == "dc_api.jwt") {
            val jwe = DCAPIResponseEncryption.encryptResponse(responseBody, encryptionJwk!!)
            kotlinx.serialization.json.buildJsonObject {
                put("response", kotlinx.serialization.json.JsonPrimitive(jwe))
            }.toString()
        } else {
            responseBody
        }

        _presentationHistory.add(0, PresentationRecord(
            id = java.util.UUID.randomUUID().toString(),
            flowId = "dc-api-${java.util.UUID.randomUUID()}",
            verifierName = trustResult.entityName,
            credentialIds = selectedIds,
            credentialNames = selectedIds.mapNotNull { id -> allCreds.find { it.id == id }?.metadata?.name },
            requestedClaims = matchResults.flatMap { it.requestedClaims.flatten() }.distinct(),
            timestamp = System.currentTimeMillis(),
        ))

        return DCAPIPresentationResult(responseJson = finalResponseJson, credentialIds = selectedIds)
    }

    /** Find the verifier's response-encryption key (`use: "enc"`) from DC API `client_metadata.jwks`. */
    private fun findEncryptionJwk(clientMetadata: kotlinx.serialization.json.JsonObject?): com.nimbusds.jose.jwk.JWK? {
        val keys = clientMetadata
            ?.get("jwks")?.jsonObject
            ?.get("keys")?.let { it as? kotlinx.serialization.json.JsonArray }
            ?: return null
        val jwkObj = keys.map { it.jsonObject }
            .firstOrNull { it["use"]?.jsonPrimitive?.contentOrNull == "enc" }
            ?: keys.map { it.jsonObject }.firstOrNull()
            ?: return null
        return com.nimbusds.jose.jwk.JWK.parse(jwkObj.toString())
    }

    /**
     * Force a fresh engine WebSocket connection before starting a new flow,
     * rather than trusting a connection that may have gone idle since the last
     * one. Mirrors [completeAuthorization]'s existing zombie-connection handling
     * (see [WalletEngineSession.forceReconnect]'s doc comment) - the same failure
     * mode isn't unique to the post-OAuth-redirect gap: a connection left open
     * across a backend restart or any other silent network drop can look
     * connected (no onClosing/onFailure fired yet) while actually discarding
     * every send. Confirmed live: [startIssuanceByOffer] sent a flow_start over
     * such a connection with no exception, no engine-side log, and no trace of
     * the message ever reaching the backend.
     */
    private suspend fun ensureEngineConnected(engine: WalletEngineSession) {
        engine.forceReconnect()
        engine.awaitConnected()
    }

    /**
     * Perform identity verification via a plugin provider and automatically start
     * credential issuance with the resulting offer.
     *
     * This is the primary integration point for IDV flows (FaceTec, iProov, etc.).
     * The provider handles all capture UI and backend communication; this method
     * bridges the IDV result into the standard OID4VCI issuance flow.
     *
     * @param provider An [IdentityVerificationProvider] implementation.
     * @param activity The hosting Activity for presenting the IDV UI.
     * @throws IDVException if verification fails.
     * @throws WalletException if issuance fails.
     */
    suspend fun verifyIdentityAndIssue(
        provider: org.siros.sdk.idv.IdentityVerificationProvider,
        activity: android.app.Activity,
    ) {
        if (!provider.isAvailable()) {
            throw org.siros.sdk.idv.IDVException.Unavailable(
                "${provider.name} is not available on this device"
            )
        }
        val result = provider.startVerification(activity)
        startIssuance(result.credentialOfferURI)
    }

    /**
     * Cancel an in-progress flow and return the wallet to the Ready state.
     *
     * If there is an active flow, sends a decline message to the backend.
     * If no flow is active, simply resets to Ready state.
     */
    fun cancelCurrentFlow() {
        val current = _state.value
        if (current is WalletState.FlowActive) {
            try {
                engineSession?.cancelFlow(current.flowId)
            } catch (e: Exception) {
                Timber.w(e, "Failed to send cancel to backend")
            }
            _state.value = readyState(current.userId, current.displayName, current.credentials)
        }
    }

    /**
     * Complete an OAuth authorization flow after the user has approved in the browser.
     *
     * Call this from your app's deep link handler when the browser redirects
     * back with `code` and `state` query parameters.
     *
     * The original flow's WebSocket session very often will not still be alive at this
     * point - Android backgrounds/throttles the app for however long the user spends in
     * the external browser/Custom Tab completing the OAuth login, and the engine's
     * WebSocket session (and with it, all server-side flow state) commonly dies within
     * seconds of the browser taking over. This resumes on a brand-new, stateless
     * flow_start (auth_code + code_verifier + the original credential_offer) instead of
     * a flow_action on the possibly-gone original flow_id - the same resume contract the
     * web client and native-android-wrapper already rely on (see go-wallet-backend's
     * `resumeWithAuthCode`, which re-derives everything else from what's supplied here).
     *
     * Also forces a fresh engine WebSocket connection first (see
     * [WalletEngineSession.forceReconnect]) rather than trusting the existing one:
     * confirmed live that a connection left idle across the background/browser gap
     * can become a "zombie" that still accepts local sends but never actually
     * delivers them, silently losing the resumed flow's trust-evaluation reply (the
     * backend then fails the flow 2 minutes later with a wait timeout that never
     * reaches the app either, since the same dead connection can't deliver that
     * error back either - see [WalletEventListener.onFlowError] for how a genuine
     * failure here gets surfaced instead).
     *
     * @param flowId The flow ID from [WalletEventListener.onAuthorizationRequired].
     * @param code The authorization code from the redirect.
     * @param state The state parameter from the redirect (for CSRF validation).
     */
    fun completeAuthorization(flowId: String, code: String, state: String) {
        val engine = engineSession ?: throw WalletException("Not connected")
        val pending = pendingAuthorizations.remove(flowId)
        if (pending == null) {
            Timber.w("No saved resume context for flow $flowId; falling back to same-session completion")
            val payload = buildJsonObject {
                put("code", kotlinx.serialization.json.JsonPrimitive(code))
                put("state", kotlinx.serialization.json.JsonPrimitive(state))
            }
            engine.sendFlowAction(flowId, "authorization_complete", payload)
            return
        }
        if (pending.state != state) {
            throw WalletException("Authorization state mismatch for flow $flowId (possible CSRF)")
        }
        scope.launch {
            try {
                engine.forceReconnect()
                engine.awaitConnected()
                engine.resumeIssuance(
                    offer = pending.offerJson,
                    redirectUri = pending.redirectUri,
                    authCode = code,
                    codeVerifier = pending.codeVerifier,
                )
            } catch (e: Exception) {
                Timber.e(e, "Failed to resume authorization for flow $flowId")
                eventListener?.onFlowError(flowId, e.message ?: "Failed to resume authorization")
            }
        }
    }

    /**
     * Delete a credential by ID.
     * Also syncs the updated keystore to the backend.
     */
    suspend fun deleteCredential(credentialId: String) {
        credentialStore.delete(credentialId)
        val current = _state.value
        if (current is WalletState.Ready) {
            _state.value = current.copy(credentials = credentialStore.getAll())
        }
        persistAndSyncKeystore()
    }

    // ── Internal wiring ─────────────────────────────────────────────

    private val supervisorJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.Main + supervisorJob)
    private val sessionStore = SessionStore(activity)
    private val accountRegistry = AccountRegistry(activity)
    private val authProvider = createAuthProvider(activity, config)
    private val keystore: KeystoreManager = config.keystore ?: JweKeystore()
    private val credentialStore: CredentialStore =
        config.credentialStore ?: KeystoreBackedCredentialStore(keystore)
    private val json = Json { ignoreUnknownKeys = true }
    private val httpClient = config.httpClient ?: OkHttpClient()

    /** Stores trust evaluation results keyed by flow ID for use in credential selection UI. */
    private val lastTrustResults = mutableMapOf<String, TrustResult>()

    /** Resume context for in-progress OAuth authorizations, keyed by flow ID - see [PendingAuthorization]. */
    private val pendingAuthorizations = mutableMapOf<String, PendingAuthorization>()

    /** Persistent trust cache for degraded-mode operation. */
    private val trustCache = TrustCache()
    private val vctmFetcher = VctmFetcher(httpGet = { url ->
        val request = Request.Builder().url(url).get().build()
        val response = httpClient.newCall(request).execute()
        if (response.isSuccessful) response.body?.string() else null
    })
    private val mddlSchemaFetcher = MddlSchemaFetcher(httpGet = { url ->
        val request = Request.Builder().url(url).get().build()
        val response = httpClient.newCall(request).execute()
        if (response.isSuccessful) response.body?.string() else null
    })

    // New AS-based auth
    private val authServerClient = AuthServerClient(
        context = activity,
        baseUrl = config.backendUrl,
        tenantId = config.tenantId,
    )
    private val legacyAuthClient = WebAuthnAuthClient(
        baseUrl = config.backendUrl,
        tenantId = config.tenantId,
        authProvider = authProvider,
        httpClient = httpClient,
        json = json,
    )

    private enum class AuthMode { UNKNOWN, NEW_AS, LEGACY_AS }
    private var authMode: AuthMode = AuthMode.UNKNOWN
    private var legacyAppToken: String? = null

    private val authTokens = AuthTokens(authServerClient, config.tenantId).apply {
        onSessionRejected = {
            Timber.w("Session rejected — forcing logout")
            scope.launch { logout() }
        }
    }

    private val _presentationHistory = mutableListOf<PresentationRecord>()

    /** Presentation history — most recent first. */
    val presentationHistory: List<PresentationRecord> get() = _presentationHistory.toList()

    private var apiClient: BackendApiClient? = null
    private var engineSession: WalletEngineSession? = null
    /** Transport-independent notifier for OID4VCI §10 events. */
    private var credentialNotifier: CredentialNotifier? = null
    private var eventListener: WalletEventListener? = null
    private var activeOffer: CredentialOffer? = null
    private var activeVctm: Vctm? = null

    /**
     * Extract the last credential ID from the auth provider, regardless of type.
     */
    private fun extractLastCredentialId(): ByteArray? = when (authProvider) {
        is LocalAuthProvider -> authProvider.lastCredentialId
        is CredentialManagerAuthProvider -> authProvider.lastCredentialId
        else -> null
    }

    /**
     * Roll back a locally-stored credential after a failed registration.
     * Prevents orphaned passkeys from appearing in the "Welcome back" picker.
     */
    private fun rollbackLocalCredential() {
        if (authProvider is LocalAuthProvider) {
            authProvider.rollbackLastRegistration()
        }
    }

    /**
     * Extract the last PRF output from the auth provider, regardless of type.
     */
    private fun extractLastPrfOutput(): PrfOutput? = when (authProvider) {
        is LocalAuthProvider -> authProvider.lastPrfOutput
        is CredentialManagerAuthProvider -> authProvider.lastPrfOutput
        else -> null
    }

    private fun setupApiClient(session: AuthSession) {
        Timber.d("setupApiClient: legacy authenticated session established")
        apiClient = BackendApiClient(config.backendUrl, config.tenantId, httpClient = httpClient).apply {
            setAppToken(session.appToken)
        }
    }

    private fun setupApiClientWithTokens() {
        Timber.d("setupApiClient: using AuthTokens for automatic token management")
        apiClient = BackendApiClient(config.backendUrl, config.tenantId, httpClient = httpClient).apply {
            setAuthTokens(authTokens)
        }
    }

    private suspend fun fetchPrivateData(): ByteArray {
        val client = apiClient ?: throw WalletException("Not authenticated")
        return try {
            val response = client.getPrivateData()
            val pdElement = response["privateData"]
            if (pdElement != null) {
                // Backend returns {"privateData": {"$b64u": "base64url-encoded-container"}}
                val containerBytes = when (pdElement) {
                    is kotlinx.serialization.json.JsonObject -> {
                        val b64u = pdElement["\$b64u"]?.jsonPrimitive?.content
                        if (b64u != null) {
                            b64UrlDecode(b64u)
                        } else {
                            // Container is inline JSON
                            pdElement.toString().toByteArray(Charsets.UTF_8)
                        }
                    }
                    is kotlinx.serialization.json.JsonPrimitive -> {
                        // Plain string (legacy or direct JWE)
                        pdElement.content.toByteArray(Charsets.UTF_8)
                    }
                    else -> ByteArray(0)
                }
                if (containerBytes.isNotEmpty()) {
                    sessionStore.privateDataJwe = String(containerBytes, Charsets.UTF_8)
                }
                containerBytes
            } else {
                ByteArray(0)
            }
        } catch (e: NetworkException) {
            Timber.w(e, "Could not fetch privateData (network), starting with empty keystore")
            ByteArray(0)
        } catch (e: BackendApiException) {
            Timber.w(e, "Could not fetch privateData (HTTP ${e.code}), starting with empty keystore")
            ByteArray(0)
        } catch (e: Exception) {
            Timber.w(e, "Could not fetch privateData, starting with empty keystore")
            ByteArray(0)
        }
    }

    private suspend fun syncPrivateDataToBackend() {
        val client = apiClient ?: return
        val containerJson = sessionStore.privateDataJwe ?: return
        try {
            // Send the full container JSON as the POST body,
            // matching the wallet-frontend's format.
            val body = Json.parseToJsonElement(containerJson).jsonObject
            client.updatePrivateData(body)
            Timber.d("Private data synced to backend")
        } catch (e: Exception) {
            Timber.e(e, "Failed to sync private data to backend")
            eventListener?.onFlowError("sync", "Private data sync failed: ${e.message}")
        }
    }

    /**
     * Persist the current keystore state to local storage and sync to backend.
     *
     * Called after any credential mutation to minimise the data-loss window.
     */
    private suspend fun persistAndSyncKeystore() {
        if (!keystore.isUnlocked) return
        try {
            val container = keystore.exportEncryptedContainer()
            sessionStore.privateDataJwe = String(container, Charsets.UTF_8)
            syncPrivateDataToBackend()
        } catch (e: Exception) {
            Timber.e(e, "Failed to persist keystore")
        }
    }

    /**
     * Connect the engine using an anonymous token from the AS (new AS)
     * or the authenticated app token (legacy AS).
     */
    private suspend fun connectEngineWithToken() {
        val token = legacyAppToken ?: authTokens.ensureAnonymousToken().raw
        if (config.useWmpProtocol) {
            connectViaWmp(token)
        } else {
            connectEngine(token)
        }
    }

    // ── WMP Protocol Path ─────────────────────────────────────────────

    private var wmpPeer: org.siros.sdk.transport.wmp.WmpPeer? = null

    private suspend fun connectViaWmp(appToken: String) {
        // Resolve engine URL: explicit config > discovery > same as backend
        val engineBaseUrl = (config.engineUrl
            ?: WalletConfig.discoverEngineUrl(config.backendUrl)
            ?: config.backendUrl).trimEnd('/')
        val wsUrl = engineBaseUrl.replace("http://", "ws://").replace("https://", "wss://") +
            "/api/v2/wallet?tenant_id=${config.tenantId}"

        val transport = org.siros.sdk.transport.wmp.WmpWebSocketTransport(wsUrl)
        val session = org.siros.sdk.transport.wmp.WmpSession(transport)
        val peer = org.siros.sdk.transport.wmp.WmpPeer(session)

        val profile = org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile(
            org.siros.sdk.transport.wmp.openid4x.OpenID4xConfig(
                onSignRequest = { flowId, params -> handleWmpSignRequest(flowId, params) },
                onMatchRequest = { flowId, payload -> handleWmpMatchRequest(flowId, payload) },
                onTrustEvaluation = { flowId, payload -> handleWmpTrustEvaluation(flowId, payload) },
                onComplete = { flowId, _ ->
                    Timber.i("WMP flow $flowId complete")
                    eventListener?.onFlowComplete(flowId)
                },
                onError = { flowId, code, message ->
                    Timber.e("WMP flow $flowId error: $code — $message")
                    eventListener?.onFlowError(flowId, "$code: $message")
                },
            )
        )
        peer.use(profile)
        peer.connect(appToken)
        wmpPeer = peer
        // WMP peer handles credential notifications via the profile
        credentialNotifier = null // Notifications go through WmpPeer.sendCredentialNotification()

        Timber.i("Connected via WMP protocol to $wsUrl")
    }

    /** Transport-agnostic description of one generated OID4VCI proof. */
    private data class GeneratedProofData(
        val proofType: String,
        val jwt: String? = null,
        val attestation: String? = null,
    )

    /**
     * Decide which OID4VCI proof type to produce and generate it - shared by
     * both the legacy WebSocket engine and the WMP transport, since both
     * ultimately talk to the same wallet-backend engine (internal/engine/oid4vci.go's
     * requestProofs), which advertises the issuer's proof_types_supported the
     * same way regardless of which transport carried the request.
     *
     * Prefers `jwt` (simple, one proof-of-possession JWT per credential,
     * per [org.siros.sdk.transport.wmp.openid4x.ProofType.JWT]) when the
     * issuer supports it - unchanged from prior behavior. Falls back to
     * `attestation` (OID4VCI Appendix F.3: a single Key Attestation JWT
     * covering the whole batch via `attested_keys`) only when `jwt` isn't
     * listed - e.g. a real-world mdoc issuer that requires the wallet to
     * assert the key storage/user-authentication security properties of the
     * credential-binding keys instead of a plain signed proof.
     *
     * [proofTypesSupported] (from the issuer's metadata, relayed by the
     * backend) takes precedence when present; [proofTypeHint] is a fallback
     * for a transport that only forwards a single pre-decided type.
     */
    private suspend fun generateProofsForRequest(
        audience: String,
        nonce: String,
        count: Int,
        proofTypesSupported: Set<String>?,
        proofTypeHint: String?,
    ): List<GeneratedProofData> {
        val chosen = when {
            !proofTypesSupported.isNullOrEmpty() ->
                if ("jwt" in proofTypesSupported) "jwt"
                else proofTypesSupported.firstOrNull { it == "attestation" } ?: proofTypesSupported.first()
            !proofTypeHint.isNullOrBlank() -> proofTypeHint
            else -> "jwt"
        }
        return if (chosen == "attestation") {
            val attestationJwt = keystore.generateKeyAttestation(nonce = nonce, count = count)
            listOf(GeneratedProofData(proofType = "attestation", attestation = attestationJwt))
        } else {
            (1..count).map {
                val proofJwt = keystore.generateProof(
                    audience = audience,
                    nonce = nonce,
                    freshKey = count > 1,
                )
                GeneratedProofData(proofType = "jwt", jwt = proofJwt)
            }
        }
    }

    private suspend fun handleWmpSignRequest(
        flowId: String,
        params: org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams,
    ): org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult {
        return when (params.action) {
            "generate_proof" -> {
                val count = params.count ?: 1
                val generated = generateProofsForRequest(
                    audience = params.audience,
                    nonce = params.nonce,
                    count = count,
                    proofTypesSupported = params.proofTypesSupported?.keys,
                    proofTypeHint = params.proofType,
                )
                val proofs = generated.map {
                    org.siros.sdk.transport.wmp.openid4x.ProofObject(
                        proofType = it.proofType, jwt = it.jwt, attestation = it.attestation,
                    )
                }
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult(proofs = proofs)
            }
            "sign_presentation" -> {
                val vpToken = keystore.signPresentation(
                    nonce = params.nonce,
                    audience = params.audience,
                    credentialIds = emptyList(),
                )
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult(vpToken = vpToken)
            }
            else -> throw IllegalArgumentException("Unknown sign action: ${params.action}")
        }
    }

    private suspend fun handleWmpMatchRequest(
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject?,
    ): org.siros.sdk.transport.wmp.openid4x.MatchResult {
        val allCreds = credentialStore.getAll()
        val matches = allCreds.map { cred ->
            org.siros.sdk.transport.wmp.openid4x.CredentialMatch(
                credentialId = cred.id,
                credentialQueryId = null,
                disclosedClaims = null,
            )
        }
        return org.siros.sdk.transport.wmp.openid4x.MatchResult(matches = matches)
    }

    private suspend fun handleWmpTrustEvaluation(
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject?,
    ): org.siros.sdk.transport.wmp.openid4x.TrustResult {
        // Delegate to the existing trust evaluation logic via BackendApiClient
        val subjectId = payload?.get("request")?.jsonObject
            ?.get("subject_id")?.jsonPrimitive?.contentOrNull

        if (subjectId.isNullOrBlank()) {
            return org.siros.sdk.transport.wmp.openid4x.TrustResult(
                trusted = false, reason = "Missing subject_id"
            )
        }

        return try {
            val request = payload?.get("request")?.jsonObject
            val keyMaterial = request?.get("key_material")?.jsonObject
            val evaluationRequest = kotlinx.serialization.json.buildJsonObject {
                putJsonObject("subject") {
                    put("type", kotlinx.serialization.json.JsonPrimitive("key"))
                    put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
                }
                putJsonObject("resource") {
                    val kmType = keyMaterial?.get("type")?.jsonPrimitive?.contentOrNull ?: "x5c"
                    put("type", kotlinx.serialization.json.JsonPrimitive(kmType))
                    put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
                    val x5c = keyMaterial?.get("x5c")
                    val jwk = keyMaterial?.get("jwk")
                    if (x5c != null) put("key", x5c)
                    else if (jwk != null) put("key", kotlinx.serialization.json.buildJsonArray { add(jwk) })
                }
                putJsonObject("action") {
                    put("name", kotlinx.serialization.json.JsonPrimitive("credential-issuer"))
                }
                request?.get("context")?.let { put("context", it) }
            }
            val response = apiClient!!.evaluateTrust(evaluationRequest)
            val decision = response["decision"]?.jsonPrimitive?.boolean ?: false
            org.siros.sdk.transport.wmp.openid4x.TrustResult(trusted = decision)
        } catch (e: Exception) {
            Timber.e(e, "WMP trust evaluation failed")
            org.siros.sdk.transport.wmp.openid4x.TrustResult(
                trusted = false, reason = e.message
            )
        }
    }

    // ── Legacy Engine Path ────────────────────────────────────────────

    private suspend fun connectEngine(appToken: String) {
        // Resolve engine URL: explicit config > discovery > same as backend
        val engineBaseUrl = config.engineUrl
            ?: WalletConfig.discoverEngineUrl(config.backendUrl)
            ?: config.backendUrl
        val engine = createEngineSession(engineBaseUrl, config.tenantId)
        engineSession = engine
        credentialNotifier = engine
        engine.connect(appToken)
        engine.awaitConnected()

        // Observe sign requests → auto-sign with keystore
        scope.launch {
            engine.signRequests().collect { msg ->
                try {
                    Timber.d("Sign request: ${msg.action} for flow ${msg.flowId}")
                    when (msg.action) {
                        "generate_proof" -> {
                            val params = msg.params
                            val count = params?.count ?: 1
                            val generated = generateProofsForRequest(
                                audience = params?.audience ?: "",
                                nonce = params?.nonce ?: "",
                                count = count,
                                proofTypesSupported = params?.proofTypesSupported?.keys,
                                proofTypeHint = params?.proofType,
                            )
                            val proofs = generated.map {
                                ProofObject(proofType = it.proofType, jwt = it.jwt, attestation = it.attestation)
                            }
                            Timber.d("Sending sign response with ${proofs.size} proofs for flow ${msg.flowId}, messageId=${msg.messageId}")
                            engine.sendSignResponse(msg.flowId, proofs = proofs, messageId = msg.messageId)
                            Timber.d("Sign response sent successfully for flow ${msg.flowId}")
                        }
                        "sign_presentation" -> {
                            val params = msg.params
                            val nonce = params?.nonce ?: ""
                            val audience = params?.audience ?: ""
                            val credsToInclude = params?.credentialsToInclude

                            // Validate audience matches trusted verifier identity
                            validateAudience(msg.flowId, audience)

                            val vpToken = if (!credsToInclude.isNullOrEmpty()) {
                                val allCreds = credentialStore.getAll()
                                val vpParts = credsToInclude.mapNotNull { ref ->
                                    val cred = allCreds.find { it.id == ref.credentialId }
                                    if (cred == null) {
                                        Timber.w("Credential ...${ref.credentialId.takeLast(4)} not found in store for VP signing")
                                        return@mapNotNull null
                                    }

                                    if (cred.format == "mso_mdoc") {
                                        // mDoc DeviceResponse (ISO 18013-5)
                                        val credBytes = android.util.Base64.decode(cred.raw, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
                                        val deviceResponse = keystore.signMdocPresentation(
                                            credentialBytes = credBytes,
                                            disclosedClaims = ref.disclosedClaims,
                                            nonce = nonce,
                                            audience = audience,
                                            responseUri = params?.responseUri ?: "",
                                            verifierJwkThumbprint = params?.verifierJwkThumbprint,
                                        )
                                        android.util.Base64.encodeToString(deviceResponse, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
                                    } else {
                                        // SD-JWT VP token with KB-JWT
                                        keystore.signVpToken(
                                            credential = cred.raw,
                                            disclosedClaims = ref.disclosedClaims,
                                            nonce = nonce,
                                            audience = audience,
                                        )
                                    }
                                }
                                // For single credential presentations (most common), return the token directly.
                                // For multiple credentials, join with newline for WMP transport.
                                // Note: The backend assembles the OID4VP-compliant vp_token JSON
                                // object (keyed by credential query ID, §8.1) before submission
                                // to the verifier.
                                vpParts.joinToString("\n")
                            } else {
                                // Fallback: legacy plain VP JWT (no credential data)
                                keystore.signPresentation(
                                    nonce = nonce,
                                    audience = audience,
                                    credentialIds = emptyList(),
                                )
                            }
                            Timber.d("Sending VP sign response for flow ${msg.flowId}, messageId=${msg.messageId}")
                            engine.sendSignResponse(msg.flowId, vpToken = vpToken, messageId = msg.messageId)
                            Timber.d("VP sign response sent successfully for flow ${msg.flowId}")
                        }
                        else -> {
                            Timber.w("Unknown sign action: ${msg.action}")
                        }
                    }
                } catch (e: KeystoreException) {
                    Timber.e(e, "Error handling sign request: keystore error")
                } catch (e: Exception) {
                    Timber.e(e, "Error handling sign request")
                }
            }
        }

        // Observe match requests → DCQL-filtered credential matching
        scope.launch {
            engine.matchRequests().collect { msg ->
                try {
                    Timber.d("Match request for flow ${msg.flowId}")
                    val allCreds = credentialStore.getAll()
                    val listener = eventListener

                    // Filter credentials using DCQL query from the verifier
                    val dcqlQuery = msg.dcqlQuery?.jsonObject
                    val dcqlOutput = if (dcqlQuery != null) {
                        CredentialMatcher.matchDcql(dcqlQuery, allCreds)
                    } else {
                        // No DCQL query — fall back to all credentials
                        CredentialMatcher.DcqlMatchOutput(
                            queryResults = listOf(CredentialMatcher.MatchResult(
                                queryId = "_default",
                                format = null,
                                candidates = allCreds,
                                requestedClaims = emptyList(),
                            )),
                            credentialSets = null,
                            satisfiableOptions = emptyList(),
                        )
                    }

                    val matchResults = dcqlOutput.queryResults
                    val candidates = matchResults.flatMap { it.candidates }.distinctBy { it.id }

                    // Let the app filter further via user selection
                    val selectedIds = if (listener != null && candidates.isNotEmpty()) {
                        listener.onCredentialSelectionRequired(
                            PresentationRequest(
                                verifierName = null,
                                matchResults = matchResults,
                                candidates = candidates,
                                credentialSets = dcqlOutput.credentialSets,
                                satisfiableOptions = dcqlOutput.satisfiableOptions,
                            )
                        )
                    } else {
                        candidates.map { it.id }
                    }

                    // Track this presentation
                    _presentationHistory.add(0, PresentationRecord(
                        id = java.util.UUID.randomUUID().toString(),
                        flowId = msg.flowId,
                        credentialIds = selectedIds,
                        credentialNames = selectedIds.mapNotNull { id ->
                            allCreds.find { it.id == id }?.metadata?.name
                        },
                        requestedClaims = matchResults.flatMap { it.requestedClaims.flatten() }.distinct(),
                        timestamp = System.currentTimeMillis(),
                    ))

                    val matches = selectedIds.mapNotNull { id ->
                        allCreds.find { it.id == id }?.let { cred ->
                            val queryId = matchResults.firstOrNull { r ->
                                r.candidates.any { it.id == id }
                            }?.queryId
                            CredentialMatch(
                                credentialQueryId = queryId,
                                credentialId = cred.id,
                                format = cred.format,
                                vct = cred.metadata?.vct,
                                availableClaims = extractAvailableClaims(cred),
                            )
                        }
                    }
                    engine.sendMatchResponse(msg.flowId, matches)
                } catch (e: SirosException) {
                    Timber.e(e, "Error handling match request")
                } catch (e: Exception) {
                    Timber.e(e, "Error handling match request")
                }
            }
        }

        // Observe flow progress
        scope.launch {
            engine.flowProgress().collect { msg ->
                Timber.d("Flow ${msg.flowId} progress: ${msg.step}")

                // Handle trust evaluation — matching wallet-frontend reference implementation
                if ((msg.step == "evaluating_trust" || msg.step == "evaluating_verifier_trust") &&
                    msg.payload?.jsonObject?.get("trust_evaluation_required")?.jsonPrimitive?.boolean == true
                ) {
                    handleTrustEvaluation(engine, msg.flowId, msg.payload!!.jsonObject)
                }

                // Handle server-side issuer trust result (informational, no response needed).
                // This is distinct from the verifier trust flow — it does NOT overwrite
                // lastTrustResults (which is used for credential selection consent UI).
                if (msg.step == "trust_evaluated" &&
                    msg.payload?.jsonObject?.get("issuer_trust_evaluated")?.jsonPrimitive?.contentOrNull == "true"
                ) {
                    val payload = msg.payload?.jsonObject
                    val trustResult = TrustResult(
                        trusted = payload?.get("trusted")?.jsonPrimitive?.contentOrNull == "true",
                        framework = payload?.get("framework")?.jsonPrimitive?.contentOrNull,
                        reason = payload?.get("reason")?.jsonPrimitive?.contentOrNull,
                        entityName = null,
                        identifier = payload?.get("issuer")?.jsonPrimitive?.contentOrNull,
                    )
                    // Only populate the trust cache — do NOT store in lastTrustResults
                    // (that map is for verifier consent UI in credential_selection step)
                    trustCache.put(trustResult.identifier ?: "", trustResult)
                    Timber.i("Server-side issuer trust: trusted=${trustResult.trusted} for ${trustResult.identifier}")
                }

                // Handle credential selection — verifier wants credentials, user must consent
                if (msg.step == "credential_selection") {
                    handleCredentialSelection(engine, msg.flowId, msg.payload?.jsonObject)
                }

                // Handle authorization required — user must approve in browser
                if (msg.step == "authorization_required") {
                    val payload = msg.payload?.jsonObject
                    Timber.d("Authorization required payload: $payload")

                    // Handle tx_code (PIN input) for pre-authorized code flow
                    val payloadType = payload?.get("type")?.jsonPrimitive?.contentOrNull
                    if (payloadType == "tx_code") {
                        val txCode = eventListener?.onTxCodeRequired(
                            flowId = msg.flowId,
                            description = payload?.get("message")?.jsonPrimitive?.contentOrNull,
                        )
                        if (txCode != null) {
                            Timber.i("Providing tx_code for flow ${msg.flowId}")
                            engine.sendFlowAction(msg.flowId, "provide_pin",
                                kotlinx.serialization.json.buildJsonObject {
                                    put("tx_code", kotlinx.serialization.json.JsonPrimitive(txCode))
                                })
                        } else {
                            Timber.w("No tx_code provided for flow ${msg.flowId}")
                        }
                    } else {
                        val authUrl = payload?.get("authorization_url")?.jsonPrimitive?.contentOrNull
                        val redirectUri = payload?.get("expected_redirect_uri")?.jsonPrimitive?.contentOrNull
                        val state = payload?.get("state")?.jsonPrimitive?.contentOrNull
                        val codeVerifier = payload?.get("code_verifier")?.jsonPrimitive?.contentOrNull
                        val offerJson = payload?.get("credential_offer")?.let { json.encodeToString(JsonElement.serializer(), it) }
                        if (authUrl != null) {
                            // Apply URL rewriter if configured
                            val rewrittenUrl = config.urlRewriter?.invoke(authUrl) ?: authUrl
                            // Extract state from URL query params if not in payload
                            val effectiveState = state ?: android.net.Uri.parse(rewrittenUrl).getQueryParameter("state") ?: ""
                            Timber.d("Authorization required: url=$rewrittenUrl state=$effectiveState")
                            // Save resume context BEFORE handing off to the browser - see
                            // completeAuthorization() for why the flow can't just be resumed
                            // on its original flow_id/session.
                            if (redirectUri != null) {
                                pendingAuthorizations[msg.flowId] = PendingAuthorization(
                                    offerJson = offerJson,
                                    redirectUri = redirectUri,
                                    codeVerifier = codeVerifier,
                                    state = effectiveState,
                                )
                            }
                            eventListener?.onAuthorizationRequired(
                                flowId = msg.flowId,
                                authorizationUrl = rewrittenUrl,
                                redirectUri = redirectUri ?: "",
                                state = effectiveState,
                            )
                        }
                    }
                }

                val current = _state.value
                if (current is WalletState.Ready || current is WalletState.FlowActive) {
                    val userId = (current as? WalletState.Ready)?.userId
                        ?: (current as? WalletState.FlowActive)?.userId ?: ""
                    val displayName = (current as? WalletState.Ready)?.displayName
                        ?: (current as? WalletState.FlowActive)?.displayName
                    _state.value = WalletState.FlowActive(
                        userId = userId,
                        displayName = displayName,
                        flowId = msg.flowId,
                        flowType = msg.step ?: "unknown",
                        status = msg.step ?: "in_progress",
                        credentials = credentialStore.getAll(),
                    )
                }
            }
        }

        // Observe flow completion → sync new credentials
        scope.launch {
            engine.flowComplete().collect { msg ->
                Timber.i("Flow ${msg.flowId} complete")

                // Store any new credentials from the flow result
                msg.credentials?.forEach { cred ->
                    if (cred.format == "mso_mdoc") {
                        // mso_mdoc credentials are base64url-encoded CBOR (a
                        // DeviceResponse-shaped envelope, per
                        // wallet-frontend#191), never JWT-shaped - the
                        // parseJwtPayload-based validation/expiry/metadata
                        // path below doesn't apply and would always fail
                        // (base64url text has no "." characters, so
                        // parseJwtPayload always returns null for it),
                        // silently dropping every issued mdoc credential.
                        val parsed = try {
                            val bytes = android.util.Base64.decode(
                                cred.credential,
                                android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP,
                            )
                            org.siros.sdk.credentials.mdoc.MdocCbor.parseStoredCredential(bytes)
                        } catch (e: Exception) {
                            Timber.w(e, "Skipping unparseable mdoc credential in flow ${msg.flowId}")
                            return@forEach
                        }
                        val metadata = activeOffer?.let { offer ->
                            val mddlSchema = try {
                                mddlSchemaFetcher.fetch(
                                    issuerUrl = offer.credentialIssuerIdentifier,
                                    scope = offer.credentialConfigurationId,
                                )
                            } catch (e: Exception) {
                                Timber.w(e, "Failed to fetch MDDL schema for ${offer.credentialConfigurationId}")
                                null
                            }
                            CredentialUtils.buildMdocMetadata(offer = offer, mddlSchema = mddlSchema)
                        }
                        val stored = StoredCredential(
                            id = java.util.UUID.randomUUID().toString(),
                            format = cred.format,
                            raw = cred.credential,
                            metadata = metadata,
                            notificationId = cred.notificationId,
                            credentialIssuerIdentifier = activeOffer?.credentialIssuerIdentifier,
                            credentialConfigurationId = activeOffer?.credentialConfigurationId,
                        )
                        credentialStore.save(stored)
                        eventListener?.onCredentialReceived(stored)
                        Timber.d("Stored mdoc credential docType=${parsed.docType}")

                        cred.notificationId?.let { notificationId ->
                            credentialNotifier?.sendCredentialNotification(
                                flowId = msg.flowId,
                                notificationId = notificationId,
                                event = CredentialNotificationEvent.ACCEPTED,
                            )
                        }
                        return@forEach
                    }

                    // Basic validation: ensure credential is parseable
                    val payload = CredentialUtils.parseJwtPayload(cred.credential)
                    if (payload == null) {
                        Timber.w("Skipping unparseable credential in flow ${msg.flowId}")
                        return@forEach
                    }
                    // Check expiry — don't store already-expired credentials
                    val exp = payload["exp"]?.jsonPrimitive?.longOrNull
                    val now = System.currentTimeMillis() / 1000
                    if (exp != null && exp < now) {
                        Timber.w("Skipping expired credential (exp=$exp, now=$now)")
                        return@forEach
                    }
                    val metadata = activeOffer?.let { offer ->
                        CredentialUtils.buildMetadata(
                            offer = offer,
                            vctm = activeVctm,
                            rawCredential = cred.credential,
                        )
                    }
                    val stored = StoredCredential(
                        id = java.util.UUID.randomUUID().toString(),
                        format = cred.format,
                        raw = cred.credential,
                        metadata = metadata,
                        issuedAt = payload["iat"]?.jsonPrimitive?.longOrNull,
                        expiresAt = exp,
                        notificationId = cred.notificationId,
                        credentialIssuerIdentifier = activeOffer?.credentialIssuerIdentifier,
                        credentialConfigurationId = activeOffer?.credentialConfigurationId,
                    )
                    credentialStore.save(stored)
                    eventListener?.onCredentialReceived(stored)

                    // OID4VCI §10: once the credential is stored, tell the backend
                    // to forward a credential_accepted notification to the issuer.
                    cred.notificationId?.let { notificationId ->
                        credentialNotifier?.sendCredentialNotification(
                            flowId = msg.flowId,
                            notificationId = notificationId,
                            event = CredentialNotificationEvent.ACCEPTED,
                        )
                    }
                }
                activeOffer = null
                activeVctm = null

                // Persist locally + sync to backend immediately
                persistAndSyncKeystore()

                eventListener?.onFlowComplete(msg.flowId)

                val current = _state.value
                val userId = (current as? WalletState.FlowActive)?.userId
                    ?: (current as? WalletState.Ready)?.userId ?: ""
                val displayName = (current as? WalletState.FlowActive)?.displayName
                    ?: (current as? WalletState.Ready)?.displayName
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = credentialStore.getAll(),
                )
            }
        }

        // Observe flow errors
        scope.launch {
            engine.flowErrors().collect { msg ->
                Timber.e("Flow ${msg.flowId} error: ${msg.error.code} — ${msg.error.message}")
                val fid = msg.flowId ?: "unknown"
                eventListener?.onFlowError(fid, msg.error.message)

                val current = _state.value
                val userId = (current as? WalletState.FlowActive)?.userId
                    ?: (current as? WalletState.Ready)?.userId ?: ""
                val displayName = (current as? WalletState.FlowActive)?.displayName
                    ?: (current as? WalletState.Ready)?.displayName
                _state.value = WalletState.Ready(
                    userId = userId,
                    displayName = displayName,
                    credentials = credentialStore.getAll(),
                )
            }
        }
    }

    /**
     * Validates that the audience for VP signing matches the trusted verifier identity.
     *
     * This is a defense-in-depth check: if a MITM between the backend engine and
     * the signing step tries to redirect the presentation to a different verifier,
     * this will log a warning. We don't throw (to avoid breaking existing flows
     * where the trust evaluation step may not have run), but the mismatch is logged.
     */
    private fun validateAudience(flowId: String, audience: String) {
        val trustResult = lastTrustResults[flowId] ?: return
        val expectedId = trustResult.identifier ?: return

        // The audience should contain or match the trusted identifier
        if (audience.isNotBlank() && expectedId.isNotBlank() && audience != expectedId) {
            Timber.w(
                "Audience mismatch for flow $flowId: " +
                    "sign_request audience='$audience' != trusted identifier='$expectedId'"
            )
        }
    }

    /**
     * Extracts a human-readable string from an AuthZEN evaluation response's
     * context.reason (or similar) field, which per go-trust's
     * EvaluationResponseContext.Reason (map[string]interface{}, e.g.
     * {"user": "...", "admin": "..."}) may be a structured JSON object, not a
     * plain string. Calling .jsonPrimitive directly on a JsonObject throws
     * (it's not a safe cast) - that previously crashed EVERY trust
     * evaluation whose response included a reason, which the outer catch
     * turned into "trusted = false" regardless of what the PDP actually
     * decided (decision was already true in the same response).
     */
    private fun reasonText(element: kotlinx.serialization.json.JsonElement?): String? = when (element) {
        null -> null
        is kotlinx.serialization.json.JsonObject ->
            element["user"]?.jsonPrimitive?.contentOrNull
                ?: element["admin"]?.jsonPrimitive?.contentOrNull
                ?: element.toString()
        else -> element.jsonPrimitive.contentOrNull
    }

    /**
     * Handles trust evaluation step from the engine.
     *
     * 1. Extract subject_id and key material from the progress payload
     * 2. Build an AuthZEN evaluation request
     * 3. Call POST /v1/evaluate on the backend
     * 4. Send back a trust_result flow action
     */
    private fun handleTrustEvaluation(
        engine: WalletEngineSession,
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject,
    ) {
        scope.launch {
            val request = payload["request"]?.jsonObject
            val subjectId = request?.get("subject_id")?.jsonPrimitive?.contentOrNull

            try {
                val subjectType = request?.get("subject_type")?.jsonPrimitive?.contentOrNull

                if (subjectId.isNullOrBlank()) {
                    Timber.e("Trust evaluation request missing subject_id")
                    engine.sendTrustResult(flowId, false, "Missing subject_id")
                    return@launch
                }

                Timber.d("Trust evaluation: subject=$subjectId type=$subjectType")

                val keyMaterial = request?.get("key_material")?.jsonObject
                val trustResult = evaluateTrustDirect(
                    subjectId = subjectId,
                    subjectType = subjectType,
                    keyMaterialType = keyMaterial?.get("type")?.jsonPrimitive?.contentOrNull,
                    x5c = keyMaterial?.get("x5c"),
                    jwk = keyMaterial?.get("jwk"),
                    context = request?.get("context"),
                ).copy(
                    clientIdScheme = request?.get("context")?.jsonObject
                        ?.get("client_id_scheme")?.jsonPrimitive?.contentOrNull,
                )

                // Store for use in credential selection UI
                lastTrustResults[flowId] = trustResult

                // Populate trust cache (only positive results are stored)
                trustCache.put(subjectId, trustResult)

                Timber.i(
                    "Trust evaluation result: decision=${trustResult.trusted} " +
                        "framework=${trustResult.framework} for $subjectId"
                )

                engine.sendTrustResult(flowId, trustResult.trusted)
            } catch (e: Exception) {
                Timber.e(e, "Trust evaluation failed")

                // Degraded mode: check cache for a recent positive result
                val cached = trustCache.get(subjectId ?: "")
                if (cached != null) {
                    Timber.w("Using cached trust result for $subjectId (backend unreachable)")
                    lastTrustResults[flowId] = cached
                    engine.sendTrustResult(flowId, true)
                } else {
                    engine.sendTrustResult(flowId, false, e.message ?: "Trust evaluation failed")
                }
            }
        }
    }

    /**
     * Shared low-level trust evaluation: builds an AuthZEN request from raw
     * subject/key-material/context fields and calls `POST /v1/evaluate`.
     *
     * Used by both the engine-relayed `trust_evaluation` step above (payload
     * comes from go-wallet-backend) and [handleDCAPIRequest] (built directly
     * from a parsed OpenID4VP request) - there is no engine/backend relay
     * for DC API presentation (see task #74's revised finding: go-wallet-backend
     * needs no DC-API-specific support because the whole flow, including
     * this SAME generic trust call, runs client-side, mirroring
     * wallet-frontend's proven architecture).
     */
    private suspend fun evaluateTrustDirect(
        subjectId: String,
        subjectType: String?,
        keyMaterialType: String?,
        x5c: kotlinx.serialization.json.JsonElement?,
        jwk: kotlinx.serialization.json.JsonElement?,
        context: kotlinx.serialization.json.JsonElement?,
    ): TrustResult {
        val client = apiClient ?: throw WalletException("Not connected")

        val evaluationRequest = kotlinx.serialization.json.buildJsonObject {
            putJsonObject("subject") {
                put("type", kotlinx.serialization.json.JsonPrimitive("key"))
                put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
            }
            putJsonObject("resource") {
                put("type", kotlinx.serialization.json.JsonPrimitive(keyMaterialType ?: "x5c"))
                put("id", kotlinx.serialization.json.JsonPrimitive(subjectId))
                if (x5c != null) {
                    put("key", x5c)
                } else if (jwk != null) {
                    put("key", kotlinx.serialization.json.buildJsonArray { add(jwk) })
                }
            }
            putJsonObject("action") {
                put("name", kotlinx.serialization.json.JsonPrimitive(
                    if (subjectType == "credential_verifier") "credential-verifier"
                    else "credential-issuer"
                ))
            }
            context?.let { put("context", it) }
        }

        Timber.d("Calling /v1/evaluate for $subjectId")
        val response = client.evaluateTrust(evaluationRequest)

        val decision = response["decision"]?.jsonPrimitive?.boolean ?: false
        val respContext = response["context"]?.jsonObject

        return TrustResult(
            trusted = decision,
            framework = respContext?.get("framework")?.jsonPrimitive?.contentOrNull,
            reason = reasonText(respContext?.get("reason"))
                ?: reasonText(respContext?.get("message")),
            entityName = respContext?.get("entity_name")?.jsonPrimitive?.contentOrNull,
            entityLogo = respContext?.get("logo_uri")?.jsonPrimitive?.contentOrNull,
            clientIdScheme = null,
            identifier = subjectId,
            domain = respContext?.get("domain")?.jsonPrimitive?.contentOrNull,
        )
    }

    /**
     * Handle credential_selection step from the engine.
     *
     * The backend sends DCQL query + verifier info in a flow_progress message.
     * We match credentials locally, show a consent UI via the event listener,
     * and respond with a consent or decline action.
     */
    private fun handleCredentialSelection(
        engine: WalletEngineSession,
        flowId: String,
        payload: kotlinx.serialization.json.JsonObject?,
    ) {
        scope.launch {
            try {
                val dcqlQuery = payload?.get("dcql_query")?.jsonObject
                val verifierInfo = payload?.get("verifier")?.jsonObject
                val verifierName = verifierInfo?.get("name")?.jsonPrimitive?.contentOrNull
                    ?: verifierInfo?.get("client_id")?.jsonPrimitive?.contentOrNull

                val allCreds = credentialStore.getAll()
                val matchResults = if (dcqlQuery != null) {
                    CredentialMatcher.match(dcqlQuery, allCreds)
                } else {
                    listOf(CredentialMatcher.MatchResult(
                        queryId = "_default",
                        format = null,
                        candidates = allCreds,
                        requestedClaims = emptyList(),
                    ))
                }
                val candidates = matchResults.flatMap { it.candidates }.distinctBy { it.id }

                val listener = eventListener
                val selectedIds = if (listener != null && candidates.isNotEmpty()) {
                    listener.onCredentialSelectionRequired(
                        PresentationRequest(
                            verifierName = verifierName,
                            trustResult = lastTrustResults.remove(flowId),
                            matchResults = matchResults,
                            candidates = candidates,
                        )
                    )
                } else {
                    candidates.map { it.id }
                }

                if (selectedIds.isEmpty()) {
                    // User declined
                    val declinePayload = kotlinx.serialization.json.buildJsonObject {
                        put("reason", kotlinx.serialization.json.JsonPrimitive("user_declined"))
                    }
                    engine.sendFlowAction(flowId, "decline", declinePayload)
                    return@launch
                }

                // Record presentation history
                _presentationHistory.add(0, PresentationRecord(
                    id = java.util.UUID.randomUUID().toString(),
                    flowId = flowId,
                    verifierName = verifierName,
                    credentialIds = selectedIds,
                    credentialNames = selectedIds.mapNotNull { id ->
                        allCreds.find { it.id == id }?.metadata?.name
                    },
                    requestedClaims = matchResults.flatMap { it.requestedClaims.flatten() }.distinct(),
                    timestamp = System.currentTimeMillis(),
                ))

                // Build consent payload with selected credentials
                // Must match backend ConsentSelection: credential_query_id, credential_id, disclosed_claims
                val consentPayload = kotlinx.serialization.json.buildJsonObject {
                    put("selected_credentials", kotlinx.serialization.json.buildJsonArray {
                        for (id in selectedIds) {
                            allCreds.find { it.id == id } ?: continue
                            val matchResult = matchResults.firstOrNull { r ->
                                r.candidates.any { it.id == id }
                            }
                            add(kotlinx.serialization.json.buildJsonObject {
                                matchResult?.queryId?.let {
                                    put("credential_query_id", kotlinx.serialization.json.JsonPrimitive(it))
                                }
                                put("credential_id", kotlinx.serialization.json.JsonPrimitive(id))
                                // Include disclosed_claims from DCQL match so backend can
                                // round-trip them into sign_request's credentials_to_include
                                val requestedClaims = matchResult?.requestedClaims
                                    ?.flatten()
                                    ?.distinct()
                                    ?: emptyList()
                                put("disclosed_claims", kotlinx.serialization.json.buildJsonArray {
                                    for (claim in requestedClaims) {
                                        add(kotlinx.serialization.json.JsonPrimitive(claim))
                                    }
                                })
                            })
                        }
                    })
                }
                engine.sendFlowAction(flowId, "consent", consentPayload)
            } catch (e: Exception) {
                Timber.e(e, "Error handling credential selection")
                val declinePayload = kotlinx.serialization.json.buildJsonObject {
                    put("reason", kotlinx.serialization.json.JsonPrimitive("error: ${e.message}"))
                }
                engine.sendFlowAction(flowId, "decline", declinePayload)
            }
        }
    }

    private fun saveSession(
        session: AuthSession,
        credentialId: ByteArray,
        prfSalt: ByteArray,
        hkdfSalt: ByteArray,
        hkdfInfo: ByteArray,
    ) {
        sessionStore.appToken = session.appToken
        sessionStore.refreshToken = session.refreshToken
        sessionStore.userId = session.uuid
        sessionStore.displayName = session.displayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = b64UrlEncode(credentialId)
        sessionStore.prfSalt = b64Encode(prfSalt)
        sessionStore.hkdfSalt = b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = b64Encode(hkdfInfo)
    }

    /**
     * Extract available claim names from a stored credential.
     *
     * For SD-JWT credentials, parses disclosures to get claim names.
     * Falls back to credential metadata claims if available.
     */
    private fun extractAvailableClaims(cred: StoredCredential): List<String> {
        val claims = mutableSetOf<String>()

        // Extract from SD-JWT disclosures: each is base64url(["salt","claim_name","value"])
        if (cred.raw.contains("~")) {
            val parts = cred.raw.split("~")
            for (disclosure in parts.drop(1).filter { it.isNotEmpty() }) {
                try {
                    val decoded = java.util.Base64.getUrlDecoder().decode(disclosure)
                    val arr = json.parseToJsonElement(String(decoded, Charsets.UTF_8))
                    val claimName = arr.jsonArray.getOrNull(1)?.jsonPrimitive?.contentOrNull
                    if (claimName != null) {
                        claims.add(claimName)
                    }
                } catch (_: Exception) {
                    // Skip unparseable disclosures
                }
            }
        }

        // Supplement from metadata claims if available
        cred.metadata?.claims?.forEach { claimMeta ->
            val name = claimMeta.path.lastOrNull()
            if (name != null) {
                claims.add(name)
            }
        }

        return claims.toList()
    }

    companion object {
        internal const val HKDF_INFO = "eDiplomas PRF"
        internal var createEngineSession: (String, String) -> WalletEngineSession =
            { baseUrl, tenantId -> WalletEngineSession(baseUrl, tenantId) }

        private val b64 = Base64.getEncoder()
        private val b64Dec = Base64.getDecoder()
        private val b64Url = Base64.getUrlEncoder().withoutPadding()

        private fun b64Encode(data: ByteArray): String = b64.encodeToString(data)
        private fun b64Decode(data: String): ByteArray = b64Dec.decode(data)
        private fun b64UrlEncode(data: ByteArray): String = b64Url.encodeToString(data)
        private fun b64UrlDecode(data: String): ByteArray = Base64.getUrlDecoder().decode(data)

        /**
         * Create the appropriate [AuthProvider] based on config.
         *
         * Defaults to [CredentialManagerAuthProvider], which delegates to the
         * system Credential Manager: it handles biometric/device-credential
         * authorization itself and supports roaming authenticators (hybrid
         * phone-as-authenticator, USB/NFC/BLE security keys) — required for
         * SIROS ID's passkey-protects-private-data model. Set
         * [WalletConfig.useSystemCredentialManager] to `false` to use
         * [LocalAuthProvider] instead: a from-scratch KeyStore-backed passkey
         * manager with no roaming-authenticator support, intended only as a
         * fallback for environments without a working Credential Manager
         * provider (e.g. some emulators).
         */
        private fun createAuthProvider(activity: Activity, config: WalletConfig): AuthProvider {
            return if (config.useSystemCredentialManager) {
                Timber.i("Using system CredentialManager for passkeys")
                CredentialManagerAuthProvider(activity)
            } else {
                Timber.i("Using local KeyStore-backed passkey provider")
                LocalAuthProvider(activity, requireUserAuth = config.requireUserAuth)
            }
        }

        /**
         * Create a new [SirosWallet] instance.
         *
         * @param activity The host Activity (required for passkey UI).
         * @param config   Backend URL and tenant ID.
         */
        fun create(activity: Activity, config: WalletConfig): SirosWallet {
            return SirosWallet(activity, config)
        }
    }
}

