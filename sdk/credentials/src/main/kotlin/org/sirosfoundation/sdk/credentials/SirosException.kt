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
 */
open class SirosException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)
