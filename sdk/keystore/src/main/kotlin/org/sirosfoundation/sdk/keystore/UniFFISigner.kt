package org.sirosfoundation.sdk.keystore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.siros_wscd_manager.FfiAlgorithm
import uniffi.siros_wscd_manager.FfiAuthCallback
import uniffi.siros_wscd_manager.FfiCertificationLevel
import uniffi.siros_wscd_manager.FfiGeneratedKey
import uniffi.siros_wscd_manager.FfiHttpTransport
import uniffi.siros_wscd_manager.FfiKeyStorageType
import uniffi.siros_wscd_manager.FfiMigrationResult
import uniffi.siros_wscd_manager.FfiOperationProgress
import uniffi.siros_wscd_manager.FfiPakeClient
import uniffi.siros_wscd_manager.FfiProgressCallback
import uniffi.siros_wscd_manager.FfiR2psConfig
import uniffi.siros_wscd_manager.FfiWscdConfig
import uniffi.siros_wscd_manager.FfiWscdException
import uniffi.siros_wscd_manager.FfiWscdManager

/**
 * [UniFFISigner] wraps the Rust `siros-wscd-manager` UniFFI bindings
 * into the SDK's [Signer] interface.
 *
 * This enables the native SDK to use any WSCD plugin (softkey, R2PS,
 * FIDO2) through the same interface used by the software [JweKeystore].
 *
 * @param config WSCD manager configuration.
 * @param authProvider Callback invoked when user authentication is needed
 *   (e.g. PIN entry for R2PS signing). If null, auth callbacks will throw.
 */
class UniFFISigner(
    config: FfiWscdConfig,
    private val authProvider: AuthProvider? = null,
) : Signer {

    private val ffi: FfiWscdManager = FfiWscdManager(config)

    /** Map of key ID → JWK JSON bytes, populated during generateKey. */
    private val publicKeyCache = mutableMapOf<String, ByteArray>()

    init {
        ffi.registerSoftkeyPlugin()
    }

    /**
     * Register the R2PS remote HSM plugin.
     *
     * @param r2psConfig R2PS server connection parameters.
     * @param httpTransport HTTP transport for R2PS protocol messages.
     * @param pakeClient OPAQUE (RFC 9807) client for PAKE authentication.
     */
    fun registerR2psPlugin(
        r2psConfig: FfiR2psConfig,
        httpTransport: FfiHttpTransport,
        pakeClient: FfiPakeClient,
    ) {
        ffi.registerR2psPlugin(r2psConfig, httpTransport, pakeClient)
    }

    override suspend fun generateKey(algorithm: String): String = withContext(Dispatchers.IO) {
        val ffiAlgorithm = algorithm.toFfiAlgorithm()
        val result: FfiGeneratedKey = ffi.generateKey(
            ffiAlgorithm,
            authCallbackBridge(),
            noOpProgress(),
        )
        publicKeyCache[result.kid] = result.publicKeyJwk.toByteArray(Charsets.UTF_8)
        result.kid
    }

    override suspend fun sign(keyId: String, data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        val result = ffi.sign(
            keyId,
            data,
            FfiAlgorithm.ES256, // algorithm is inferred from the key by the manager
            authCallbackBridge(),
            noOpProgress(),
        )
        result.data
    }

    override suspend fun listKeys(): List<SignerKeyInfo> = withContext(Dispatchers.IO) {
        ffi.listKeys().map { keyInfo ->
            SignerKeyInfo(
                keyId = keyInfo.kid,
                algorithm = keyInfo.algorithm.toSdkAlgorithm(),
            )
        }
    }

    override suspend fun deleteKey(keyId: String) = withContext(Dispatchers.IO) {
        ffi.deleteKey(keyId)
        publicKeyCache.remove(keyId)
        Unit
    }

    override suspend fun attestationChain(keyId: String): List<ByteArray>? = withContext(Dispatchers.IO) {
        ffi.attestationChain(keyId)?.certificates
    }

    override suspend fun exportPublicKey(keyId: String): ByteArray = withContext(Dispatchers.IO) {
        publicKeyCache[keyId]
            ?: throw IllegalStateException(
                "Public key not cached for $keyId. Key was generated before this session or on another device."
            )
    }

    override suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult =
        withContext(Dispatchers.IO) {
            when (val result = ffi.migrateKey(keyId, targetPlugin, authCallbackBridge())) {
                is FfiMigrationResult.Migrated -> MigrationResult.Migrated(result.newKid)
                is FfiMigrationResult.ReEnrollmentRequired -> MigrationResult.ReEnrollmentRequired(result.oldKid)
            }
        }

    override suspend fun securityProperties(keyId: String): SignerSecurityProperties =
        withContext(Dispatchers.IO) {
            val props = ffi.securityProperties(keyId)
            SignerSecurityProperties(
                keyStorage = listOf(props.keyStorage.toSdkKeyStorage()),
                userAuthentication = props.userAuthentication,
                certification = props.certification.toSdkCertification(),
                amr = props.amr,
            )
        }

    /**
     * Export the softkey plugin container as JSON bytes for encrypted backup.
     * The caller is responsible for JWE-wrapping the result.
     */
    fun exportSoftkeyContainer(): ByteArray = ffi.exportSoftkeyContainer()

    /**
     * Import a softkey container (JSON bytes) to restore keys from backup.
     */
    fun importSoftkeyContainer(container: ByteArray) {
        ffi.importSoftkeyContainer(container)
    }

    // ─── Auth callback bridge ────────────────────────────────────────────────

    private fun authCallbackBridge(): FfiAuthCallback = object : FfiAuthCallback {
        override fun requestPin(): ByteArray {
            val provider = authProvider
                ?: throw FfiWscdException.AuthCancelled("No AuthProvider configured")
            return provider.requestPin()
        }

        override fun requestWebauthnAssertion(
            challenge: ByteArray,
            rpId: String,
            allowedCredentials: List<ByteArray>,
        ): ByteArray {
            val provider = authProvider
                ?: throw FfiWscdException.AuthCancelled("No AuthProvider configured")
            return provider.requestWebauthnAssertion(challenge, rpId, allowedCredentials)
        }
    }

    private fun noOpProgress(): FfiProgressCallback = object : FfiProgressCallback {
        override fun onProgress(progress: FfiOperationProgress) { /* no-op */ }
    }

    // ─── Type mapping helpers ────────────────────────────────────────────────

    private fun String.toFfiAlgorithm(): FfiAlgorithm = when (this.uppercase()) {
        "ES256" -> FfiAlgorithm.ES256
        "EDDSA", "ED25519" -> FfiAlgorithm.ED_DSA
        else -> throw IllegalArgumentException("Unsupported algorithm: $this")
    }

    private fun FfiAlgorithm.toSdkAlgorithm(): String = when (this) {
        FfiAlgorithm.ES256 -> "ES256"
        FfiAlgorithm.ED_DSA -> "EdDSA"
    }

    private fun FfiKeyStorageType.toSdkKeyStorage(): String = when (this) {
        FfiKeyStorageType.SOFTWARE -> "software"
        FfiKeyStorageType.HARDWARE -> "hardware"
        FfiKeyStorageType.REMOTE_HSM -> "remote_hsm"
        FfiKeyStorageType.TRUSTED_EXECUTION -> "trusted_execution"
    }

    private fun FfiCertificationLevel.toSdkCertification(): CertificationInfo = when (this) {
        FfiCertificationLevel.NONE -> CertificationInfo.None
        FfiCertificationLevel.BASELINE -> CertificationInfo.Certified("EUCC", "baseline")
        FfiCertificationLevel.SUBSTANTIAL -> CertificationInfo.Certified("EUCC", "substantial")
        FfiCertificationLevel.HIGH -> CertificationInfo.Certified("EUCC", "high")
    }
}
