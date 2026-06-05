// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.credentials

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * A registered credential issuer from the backend.
 * Returned by `GET /issuer/all` (requires auth + X-Tenant-ID).
 */
@Serializable
data class IssuerEntry(
    val id: Long,
    @SerialName("tenantId") val tenantId: String? = null,
    @SerialName("credentialIssuerIdentifier") val credentialIssuerIdentifier: String,
    @SerialName("clientId") val clientId: String? = null,
    val visible: Boolean = true,
)

/**
 * OpenID4VCI Credential Issuer Metadata — the subset we need for
 * displaying available credentials and starting issuance flows.
 *
 * Fetched from `<issuerUrl>/.well-known/openid-credential-issuer`.
 */
@Serializable
data class IssuerMetadata(
    @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("credential_endpoint") val credentialEndpoint: String? = null,
    @SerialName("authorization_servers") val authorizationServers: List<String>? = null,
    val display: List<IssuerDisplay>? = null,
    @SerialName("credential_configurations_supported")
    val credentialConfigurationsSupported: Map<String, CredentialConfiguration> = emptyMap(),
)

@Serializable
data class IssuerDisplay(
    val name: String? = null,
    val locale: String? = null,
    val logo: LogoInfo? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
)

/**
 * A single credential configuration from the issuer metadata.
 */
@Serializable
data class CredentialConfiguration(
    val format: String,
    val vct: String? = null,
    val doctype: String? = null,
    val scope: String? = null,
    @SerialName("credential_metadata") val credentialMetadata: CredentialDisplayMetadata? = null,
)

/**
 * Display metadata for a credential configuration.
 */
@Serializable
data class CredentialDisplayMetadata(
    val display: List<CredentialDisplayEntry>? = null,
    val claims: List<JsonElement>? = null,
)

@Serializable
data class CredentialDisplayEntry(
    val name: String,
    val description: String? = null,
    val locale: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
    @SerialName("background_image") val backgroundImage: BackgroundImage? = null,
    val logo: LogoInfo? = null,
)

@Serializable
data class BackgroundImage(
    val uri: String? = null,
)

/**
 * A credential configuration ready for display in the UI.
 * Combines issuer info with the credential config display metadata.
 */
data class CredentialOffer(
    val credentialConfigurationId: String,
    val credentialIssuerIdentifier: String,
    val credentialName: String,
    val credentialDescription: String? = null,
    val issuerName: String,
    val backgroundColor: String? = null,
    val textColor: String? = null,
    val logoUri: String? = null,
    val issuerLogoUri: String? = null,
)
