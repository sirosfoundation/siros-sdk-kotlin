package org.siros.sdk.auth

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Authenticator abstraction for FIDO2/WebAuthn operations.
 * SDK consumers can provide their own implementation or use the
 * platform default ([CredentialManagerAuthProvider]).
 */
interface AuthProvider {
    /** Create a new passkey credential (registration). */
    suspend fun register(options: RegisterOptions): RegisterResult

    /** Authenticate with an existing passkey (assertion). */
    suspend fun authenticate(options: AuthenticateOptions): AuthenticateResult

    /** Obtain PRF output for keystore key derivation. */
    suspend fun getPrfOutput(credentialId: ByteArray, salt: ByteArray): PrfOutput
}

data class RegisterOptions(
    val rpId: String,
    val rpName: String,
    val userId: ByteArray,
    val userName: String,
    val userDisplayName: String,
    val challenge: ByteArray,
    val attestation: String = "none",
    val authenticatorSelection: AuthenticatorSelection? = null,
    val prfSalt: ByteArray? = null,
)

data class AuthenticatorSelection(
    val authenticatorAttachment: String? = null,
    val residentKey: String = "required",
    val userVerification: String = "preferred",
)

data class RegisterResult(
    val credentialId: ByteArray,
    val attestationObject: ByteArray,
    val clientDataJSON: ByteArray,
    val prfOutput: PrfOutput? = null,
)

data class AuthenticateOptions(
    val rpId: String,
    val challenge: ByteArray,
    val allowCredentials: List<AllowCredential>? = null,
    val userVerification: String = "preferred",
    val prfSalt: ByteArray? = null,
)

data class AllowCredential(
    val id: ByteArray,
    val type: String = "public-key",
)

data class AuthenticateResult(
    val credentialId: ByteArray,
    val authenticatorData: ByteArray,
    val clientDataJSON: ByteArray,
    val signature: ByteArray,
    val userHandle: ByteArray?,
    val prfOutput: PrfOutput? = null,
)

data class PrfOutput(
    val first: ByteArray,
    val second: ByteArray? = null,
)

/** Session tokens returned after successful authentication. */
@Serializable
data class AuthSession(
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("user_id") val userId: String,
    @SerialName("display_name") val displayName: String? = null,
)
