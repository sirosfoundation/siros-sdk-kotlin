package org.siros.sdk.wallet

import org.siros.sdk.credentials.SirosException

/**
 * A trust evaluation that must NOT be softened by a cached positive result.
 *
 * Callers of the trust paths keep a [TrustCache] of recent positive results
 * and fall back to it when an evaluation fails, on the reasoning that a
 * momentarily unreachable backend should not strand a user at a checkpoint.
 * That reasoning holds for exactly one failure - an unreachable backend while
 * the wallet is in [MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK] - and
 * for no other.
 *
 * It does not hold when the backend was REACHABLE and refused the caller: a
 * cached positive would then let an expired token keep a stale "trusted"
 * answer alive, which is the same silent downgrade the refused-versus-
 * unreachable rule exists to prevent, just arriving through the cache instead
 * of the local roots. Nor does it hold under
 * [MdocTrustEvaluationMode.REMOTE_ONLY], where the whole point is that
 * nothing stands in for a current remote answer.
 *
 * So those two cases throw this instead of the underlying exception, and
 * every catch site that consults the cache lets it through untouched.
 */
class TrustEvaluationFailedClosedException(
    message: String,
    cause: Throwable? = null,
) : SirosException(message, cause, errorCode = "trust_evaluation_failed_closed")
