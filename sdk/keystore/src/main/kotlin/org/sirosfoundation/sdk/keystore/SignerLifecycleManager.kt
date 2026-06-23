package org.sirosfoundation.sdk.keystore

/**
 * Explicit lifecycle operations for WSCD-backed signers.
 *
 * This is intentionally separate from [Signer] so existing key-operation
 * integrations remain source-compatible.
 */
interface SignerLifecycleManager {
    suspend fun lifecycleStatus(pluginId: String, contextId: String): LifecycleStatus

    suspend fun registerLifecycle(request: RegisterLifecycleRequest): RegistrationOutcome

    suspend fun activateLifecycle(request: ActivateLifecycleRequest): ActivationOutcome

    suspend fun rotateLifecycle(request: RotateLifecycleRequest): RotationOutcome

    suspend fun destroyLifecycle(request: DestroyLifecycleRequest): DestructionOutcome
}

enum class FactorKind {
    Opaque,
    WebAuthn,
    RawSign,
}

enum class LifecycleState {
    Uninitialized,
    Registered,
    Active,
    Suspended,
    Destroyed,
}

enum class DestroyMode {
    LocalOnly,
    RemoteRevokeIfSupported,
    Strict,
}

data class LifecycleStatus(
    val contextId: String,
    val pluginId: String,
    val factorKind: FactorKind,
    val state: LifecycleState,
    val updatedAt: Long,
)

data class RegisterLifecycleRequest(
    val pluginId: String,
    val contextId: String,
    val factorKind: FactorKind,
)

data class ActivateLifecycleRequest(
    val pluginId: String,
    val contextId: String,
)

data class RotateLifecycleRequest(
    val pluginId: String,
    val contextId: String,
)

data class DestroyLifecycleRequest(
    val pluginId: String,
    val contextId: String,
    val mode: DestroyMode,
    val reason: String? = null,
)

data class RegistrationOutcome(
    val contextId: String,
    val state: LifecycleState,
)

data class ActivationOutcome(
    val contextId: String,
    val state: LifecycleState,
)

data class RotationOutcome(
    val contextId: String,
    val state: LifecycleState,
)

data class DestructionOutcome(
    val contextId: String,
    val state: LifecycleState,
    val remotePerformed: Boolean,
)