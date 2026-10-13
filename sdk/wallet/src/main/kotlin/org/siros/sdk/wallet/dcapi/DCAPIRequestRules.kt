// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.dcapi

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.siros.sdk.credentials.SirosException

/**
 * How strictly the wallet enforces a signed request's `expected_origins`
 * (OpenID4VP 1.0 Appendix A) for the formats other than `circuit_zk`.
 * `circuit_zk` always requires it and is not affected by this setting.
 */
enum class ExpectedOriginsMode {
    /** Ignore `expected_origins`, as the SDK always has. The default. */
    OFF,

    /** Enforce `expected_origins` on a signed request that has the member; one without it is accepted. */
    IF_PRESENT,

    /** A signed request without a valid `expected_origins` is rejected. */
    REQUIRED,
}

/**
 * Chooses which entry of a request's `requests[]` the wallet answers:
 * [DCAPIRequestParser.parse] evaluates the entries in order and takes the
 * first one this accepts.
 */
fun interface DCAPIEntryPolicy {
    /** Whether [request], one parsed entry, is acceptable. */
    fun accepts(request: DCAPIRequest): Boolean

    companion object {
        /** Accept the first entry: the behaviour of the parser before there was a policy. */
        val FIRST_ENTRY = DCAPIEntryPolicy { true }
    }
}

/**
 * Raised when no entry of `requests[]` is acceptable under the wallet's
 * [DCAPIRequestRules]. The wallet answers it with `access_denied` and no
 * description. The message names only the protocol of the entry that was
 * refused, never any request content.
 */
class DCAPIRequestRefused(val protocol: String) :
    SirosException("DC API request refused (protocol=$protocol)", errorCode = "dcapi_request_refused")

/**
 * The wallet's rules for a DC API request: whether a request must be signed
 * and carry the calling origin in `expected_origins`.
 *
 * - For a request that [requiresSignedRequest] says needs one (by default,
 *   any credential query with `format: "circuit_zk"`), the protocol must be
 *   exactly `openid4vp-v1-signed` (so `openid4vp-v1-multisigned` is
 *   refused), and [origin] must equal, as an exact string, an entry of a
 *   non-empty `expected_origins`. A missing or malformed `expected_origins`
 *   fails. There is no configuration for this.
 * - Any other request follows [mode].
 *
 * [origin] is what the OS reports for the calling page. The wallet compares
 * it; it does not authenticate it.
 */
class DCAPIRequestRules(
    private val origin: String,
    private val mode: ExpectedOriginsMode = ExpectedOriginsMode.OFF,
    private val requiresSignedRequest: (JsonObject?) -> Boolean = DEFAULT_REQUIRES_SIGNED_REQUEST,
) : DCAPIEntryPolicy {

    override fun accepts(request: DCAPIRequest): Boolean {
        if (requiresSignedRequest(request.dcqlQuery)) {
            return request.protocol == SIGNED_PROTOCOL &&
                request.keyMaterial != null &&
                originListed(request)
        }
        if (request.keyMaterial == null) return true
        return when (mode) {
            ExpectedOriginsMode.OFF -> true
            ExpectedOriginsMode.IF_PRESENT -> !request.hasExpectedOrigins || originListed(request)
            ExpectedOriginsMode.REQUIRED -> originListed(request)
        }
    }

    private fun originListed(request: DCAPIRequest): Boolean {
        val listed = request.expectedOrigins
        return listed != null && listed.isNotEmpty() && origin in listed
    }

    companion object {
        /** The only protocol a `circuit_zk` request may use. */
        const val SIGNED_PROTOCOL = "openid4vp-v1-signed"

        /** The default hook: any credential query with `format: "circuit_zk"`. */
        val DEFAULT_REQUIRES_SIGNED_REQUEST: (JsonObject?) -> Boolean = { query ->
            ((query?.get("credentials") as? JsonArray) ?: JsonArray(emptyList())).any {
                (it as? JsonObject)?.get("format")?.jsonPrimitive?.contentOrNull == "circuit_zk"
            }
        }
    }
}
