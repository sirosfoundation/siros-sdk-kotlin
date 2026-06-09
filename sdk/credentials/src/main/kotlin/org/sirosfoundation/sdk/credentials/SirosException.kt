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
 */
open class SirosException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/** Raised when a network request fails (timeout, DNS, connection refused). */
class NetworkException(
    message: String,
    cause: Throwable? = null,
) : SirosException(message, cause)

/** Raised when authentication or authorization fails (401, token expired, WebAuthn error). */
class AuthException(
    message: String,
    cause: Throwable? = null,
) : SirosException(message, cause)

/** Raised when keystore operations fail (locked, corrupt container, decryption error). */
class KeystoreException(
    message: String,
    cause: Throwable? = null,
) : SirosException(message, cause)

/** Raised for wallet-level orchestration errors. */
class WalletException(
    message: String,
    cause: Throwable? = null,
) : SirosException(message, cause)

/** Raised when the backend returns an HTTP error. */
class BackendApiException(
    val code: Int,
    message: String,
    val body: String? = null,
) : SirosException(message)
