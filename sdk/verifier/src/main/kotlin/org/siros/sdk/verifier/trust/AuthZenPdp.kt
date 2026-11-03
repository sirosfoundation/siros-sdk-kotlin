// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.trust

import java.io.IOException

/**
 * A remote OpenID AuthZEN policy decision point.
 *
 * Implementations must fail closed: [evaluate] returns only for an explicit
 * permit. Denials, invalid responses, and transport failures are reported as
 * [AuthZenException] subtypes. There is deliberately no local trust fallback.
 */
fun interface AuthZenPdp {
    /**
     * Evaluates the exact AuthZEN request JSON produced by the verifier core.
     *
     * @return `true` for an explicit permit; this method never returns `false`.
     * @throws AuthZenDeniedException for an explicit deny.
     * @throws AuthZenException for every other failure to obtain a permit.
     */
    suspend fun evaluate(requestJson: String): Boolean
}

/** Base type for a failure to obtain an AuthZEN permit. */
sealed class AuthZenException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The PDP returned the JSON boolean decision `false`. */
class AuthZenDeniedException internal constructor() :
    AuthZenException("The policy decision point denied the request")

/** The PDP endpoint returned a non-success HTTP status. */
class AuthZenHttpException internal constructor(val statusCode: Int) :
    AuthZenException("The policy decision point returned HTTP $statusCode")

/** The PDP returned a malformed response or no JSON boolean decision. */
class AuthZenResponseException internal constructor(message: String, cause: Throwable? = null) :
    AuthZenException(message, cause)

/** The PDP could not be reached, or its response could not be read. */
class AuthZenNetworkException internal constructor(cause: IOException) :
    AuthZenException("The policy decision point could not be reached", cause)
