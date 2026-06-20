// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.credentials

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
class AuthException(
    message: String,
    cause: Throwable? = null,
    errorCode: String = "auth_failed",
) : SirosException(message, cause, errorCode)

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
