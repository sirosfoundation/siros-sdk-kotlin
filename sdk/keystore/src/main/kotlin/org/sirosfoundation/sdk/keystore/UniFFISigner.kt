package org.sirosfoundation.sdk.keystore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

// NOTE: This file requires the siros-wscd-manager AAR dependency.
// Until the AAR is published, this file compiles conditionally.
// Uncomment the import when the AAR is available:
// import org.sirosfoundation.wscd.*

/**
 * [UniFFISigner] wraps the Rust `siros-wscd-manager` UniFFI bindings
 * into the SDK's [Signer] interface.
 *
 * **This is a placeholder.** All methods throw [NotImplementedError] until the
 * siros-wscd-manager AAR is published. Do not instantiate in production code.
 *
 * @param config WSCD manager configuration (default plugin, plugin configs).
 * @param transport Optional CTAP2 transport provider for FIDO2 plugin.
 */
@Deprecated(
    message = "UniFFISigner is a placeholder until the siros-wscd-manager AAR is published. Do not use in production.",
    level = DeprecationLevel.WARNING,
)
class UniFFISigner(
    config: Any, /* FfiWscdConfig — typed when AAR is available */
    transport: Ctap2TransportProvider? = null,
) : Signer {

    // Placeholder — uncomment when AAR dependency is added:
    // private val ffi: FfiWscdManager = FfiWscdManager(
    //     config = config as FfiWscdConfig,
    //     transport = transport?.let { Ctap2TransportBridge(it) }
    // )

    override suspend fun generateKey(algorithm: String): String = withContext(Dispatchers.IO) {
        // ffi.generateKey(algorithm)
        TODO("Requires siros-wscd-manager AAR dependency")
    }

    override suspend fun sign(keyId: String, data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        // val result = ffi.sign(keyId, data, null)
        // result.signature
        TODO("Requires siros-wscd-manager AAR dependency")
    }

    override suspend fun listKeys(): List<SignerKeyInfo> = withContext(Dispatchers.IO) {
        // ffi.listKeys().map { SignerKeyInfo(it.kid, it.algorithm) }
        TODO("Requires siros-wscd-manager AAR dependency")
    }

    override suspend fun deleteKey(keyId: String) = withContext(Dispatchers.IO) {
        // ffi.deleteKey(keyId)
        TODO("Requires siros-wscd-manager AAR dependency")
    }

    override suspend fun attestationChain(keyId: String): List<ByteArray>? = withContext(Dispatchers.IO) {
        // ffi.attestationChain(keyId)
        TODO("Requires siros-wscd-manager AAR dependency")
    }

    override suspend fun exportPublicKey(keyId: String): ByteArray = withContext(Dispatchers.IO) {
        // ffi.exportPublicKey(keyId)
        TODO("Requires siros-wscd-manager AAR dependency")
    }

    override suspend fun migrateKey(keyId: String, targetPlugin: String): MigrationResult =
        withContext(Dispatchers.IO) {
            // val result = ffi.migrateKey(keyId, targetPlugin)
            // when (result) {
            //     is FfiMigrationResult.Migrated -> MigrationResult.Migrated(result.newKid)
            //     is FfiMigrationResult.ReEnrollmentRequired -> MigrationResult.ReEnrollmentRequired(result.oldKid)
            // }
            TODO("Requires siros-wscd-manager AAR dependency")
        }

    override suspend fun securityProperties(keyId: String): SignerSecurityProperties =
        withContext(Dispatchers.IO) {
            // val props = ffi.securityProperties(keyId)
            // SignerSecurityProperties(
            //     keyStorage = props.keyStorage,  // List<String> from FFI
            //     userAuthentication = props.userAuthentication,
            //     certification = CertificationInfo.None, // TODO: map from FFI
            //     amr = props.amr,
            // )
            TODO("Requires siros-wscd-manager AAR dependency")
        }
}

/**
 * Bridges the SDK's [Ctap2TransportProvider] to the UniFFI `FfiCtap2Transport` callback.
 */
private class Ctap2TransportBridge(
    private val provider: Ctap2TransportProvider,
) /* : FfiCtap2Transport — uncomment when AAR available */ {

    fun send(command: ByteArray): ByteArray = runBlocking {
        provider.send(command)
    }

    fun isAvailable(): Boolean = runBlocking {
        provider.isAvailable()
    }
}
