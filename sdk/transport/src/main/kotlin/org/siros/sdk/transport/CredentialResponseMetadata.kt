package org.siros.sdk.transport

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * One entry of a per-credential `credential_metadata` array that an issuer
 * delivers beside `credential` in an OID4VCI credential response, as the
 * wallet engine relays it on a `CredentialResult`.
 *
 * This is NOT the display-oriented `CredentialMetadata` of the credential
 * store (issuer-published claim and logo metadata): it is a delivered,
 * possibly secret, per-credential value. [value] is kept as the raw JSON
 * element so it can be stored exactly as received; a consumer interprets
 * only the entry types it knows and leaves every other entry untouched.
 *
 * The array is only trustworthy when [CredentialResultMetadata.credentialMetadataEncryptedResponse]
 * is set on the same result: the engine sets that only when the issuer's
 * response was JWE-decrypted, and a secret must not be accepted from a plain
 * JSON response.
 */
@Serializable
data class CredentialResponseMetadataEntry(
    val type: String,
    val value: JsonElement,
)

/**
 * The delivered-metadata members shared by both transports' `CredentialResult`
 * DTOs, so wallet code reads them the same way whichever transport carried
 * the result.
 */
interface CredentialResultMetadata {
    /** `credential_metadata`; null when the issuer delivered none. */
    val credentialMetadata: List<CredentialResponseMetadataEntry>?

    /**
     * `credential_metadata_encrypted_response`: true only when metadata is
     * present AND the issuer's response was JWE-decrypted by the engine.
     * Absent means false; metadata with this false came over plain JSON.
     */
    val credentialMetadataEncryptedResponse: Boolean
}
