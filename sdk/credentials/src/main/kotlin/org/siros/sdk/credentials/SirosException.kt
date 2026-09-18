// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

/**
 * Base exception type for the SIROS Wallet SDK.
 *
 * All SDK-specific exceptions extend this class, allowing integrators
 * to catch every SDK error uniformly:
 *
 * ```kotlin
 * try {
 *     wallet.login()
 * } catch (e: SirosException) {
 *     // handle any SDK error
 * }
 * ```
 *
 * Subtypes enable fine-grained recovery:
 * ```kotlin
 * try { wallet.login() }
 * catch (e: NetworkException) { /* retry later */ }
 * catch (e: AuthException)    { /* re-authenticate */ }
 * catch (e: KeystoreException) { /* keystore corrupt / locked */ }
 * catch (e: SirosException)   { /* generic fallback */ }
 * ```
 *
 * Each exception carries a machine-readable [errorCode] that consuming
 * applications can map to localized user-facing messages:
 * ```kotlin
 * val resId = when (e.errorCode) {
 *     "network_timeout" -> R.string.error_network_timeout
 *     "auth_failed" -> R.string.error_auth_failed
 *     else -> R.string.error_generic
 * }
 * ```
 */
open class SirosException(
    message: String,
    cause: Throwable? = null,
    /** Machine-readable error code for i18n mapping. */
    val errorCode: String = "unknown_error",
) : Exception(message, cause)

/** Raised when a network request fails (timeout, DNS, connection refused). */
class NetworkException(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "network_error",
) : SirosException(message, cause, errorCode)

/** Raised when authentication or authorization fails (401, token expired, WebAuthn error). */
class AuthException @JvmOverloads constructor(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "auth_failed",
    /** HTTP status code when the failure came from an AS/Backend HTTP response. */
    val code: Int? = null,
    /**
     * The server's own user-facing explanation (`message` in the error body),
     * when it sent one - e.g. the text a SID-AUTH-06 `WALLET_SUSPENDED` /
     * `WALLET_REVOKED` refusal carries to tell the two cases apart for the
     * user. [message] stays the developer-facing diagnostic.
     */
    val serverMessage: String? = null,
    /**
     * The `scope` of a SID-AUTH-06 lifecycle refusal (`instance` or `wallet`),
     * when the server sent one. It is the only machine-readable way to tell a
     * revoked wallet instance from a deactivated wallet, because both answer
     * with `WALLET_REVOKED`; see
     * [org.siros.sdk.auth.WalletLifecycleRefusal.fromRefusal]. Null against a
     * backend that does not send it yet, which must be read as the
     * per-instance case.
     */
    val serverScope: String? = null,
) : SirosException(message, cause, errorCode)
// @JvmOverloads keeps every shorter JVM constructor descriptor alive as
// parameters are appended. Kotlin's default arguments alone do not: adding
// serverScope replaced the five-argument constructor outright, and an
// already-compiled consumer of this published module would have met a
// NoSuchMethodError rather than a recompile.

/** Raised when keystore operations fail (locked, corrupt container, decryption error). */
class KeystoreException(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "keystore_error",
) : SirosException(message, cause, errorCode)

/** Raised for wallet-level orchestration errors. */
class WalletException(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "wallet_error",
) : SirosException(message, cause, errorCode)

/** Raised when the backend returns an HTTP error. */
class BackendApiException(
    val code: Int,
    message: String,
    val body: String? = null,
) : SirosException(message, errorCode = "backend_api_$code")
