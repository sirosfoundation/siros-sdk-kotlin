// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.auth

/**
 * What `POST /user/session/webauthn/register-begin` returned: the passkey to
 * create ([createOptions]) and, when the account already has a passkey, the
 * assertion one of them must make to authorise the addition ([authorization]).
 *
 * Both ceremonies are answered in the one `register-finish`. The challenge is
 * single use and expires after five minutes; a refused finish consumes it.
 */
class PasskeyEnrollmentChallenge(
    val challengeId: String,
    val username: String?,
    /** The credential to create, as the backend asked for it (without a PRF salt; the caller adds its own). */
    val createOptions: RegisterOptions,
    /** The assertion an existing passkey must make, or null for an account with no passkey yet. */
    val authorization: AuthenticateOptions?,
)

/** The backend's answer to `POST /user/session/webauthn/register-begin`. */
sealed interface AddPasskeyBegin {
    /** `200`: the ceremonies to run. */
    data class Ready(val challenge: PasskeyEnrollmentChallenge) : AddPasskeyBegin

    /** `403`: the token lacks the scope to enrol a passkey. */
    data class Forbidden(val message: String?) : AddPasskeyBegin

    /** `401`: the bearer token is revoked or expired. */
    data class SessionRevoked(val message: String?) : AddPasskeyBegin
}

/**
 * The backend's answer to `POST /user/session/webauthn/register-finish`, for
 * every outcome it defines. Except for [Added], every outcome leaves the
 * account unchanged, and a refused finish has consumed its challenge: start
 * again from [BackendApiClient.passkeyRegisterBegin].
 */
sealed interface AddPasskeyOutcome {
    /** `200`: the passkey was added. [credentialId] is the backend's id for it. */
    data class Added(val credentialId: String?) : AddPasskeyOutcome

    /** `401 ENROLLMENT_AUTHORIZATION_REQUIRED`: the account has a passkey and no `authorization` was sent. */
    data class AuthorizationRequired(val message: String?) : AddPasskeyOutcome

    /** `401 ENROLLMENT_AUTHORIZATION_FAILED`: the assertion is not from one of the caller's passkeys, is over another challenge, or does not verify. */
    data class AuthorizationFailed(val message: String?) : AddPasskeyOutcome

    /** `404`: the challenge is unknown, expired or already consumed. */
    data class RetryNeeded(val message: String?) : AddPasskeyOutcome

    /** `412`: the private data changed on the backend since it was read. [currentEtag] is the backend's current ETag. */
    data class PrivateDataConflict(val currentEtag: String?) : AddPasskeyOutcome

    /** `400` / `403` (not the authorization code): the new passkey was refused (it did not verify, or its authenticator is not allowed). */
    data class RegistrationRejected(val status: Int, val message: String?) : AddPasskeyOutcome

    /** `401` without an enrollment code: the bearer token is revoked or expired. */
    data class SessionRevoked(val message: String?) : AddPasskeyOutcome
}

internal const val ERROR_ENROLLMENT_AUTHORIZATION_REQUIRED = "ENROLLMENT_AUTHORIZATION_REQUIRED"
internal const val ERROR_ENROLLMENT_AUTHORIZATION_FAILED = "ENROLLMENT_AUTHORIZATION_FAILED"
