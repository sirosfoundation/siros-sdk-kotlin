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
    /**
     * The signed form of this metadata, per OpenID4VCI 12.2.3. ETSI TS 119 472-3
     * ISS-MDATA-4.2.1-01 requires it, and ISS-MDATA-4.2.1-02 requires the JWS to
     * be signed with the provider's access certificate. Kept so the document can
     * be round-tripped and verified rather than silently dropped on parse.
     */
    @SerialName("signed_metadata") val signedMetadata: String? = null,
    /**
     * Attestations about the issuer, per ETSI TS 119 472-3
     * ISS-MDATA-REG_CERT-4.2.3-01. The element with format "registration_cert"
     * carries the provider's WRPRC, which is what says the provider is
     * registered to issue these credential types.
     *
     * Not to be confused with the wallet engine's own issuer display payload,
     * which travels under a different key precisely so these two do not collide.
     */
    @SerialName("issuer_info") val issuerInfo: List<IssuerInfoEntry>? = null,
)

/**
 * One attestation about the issuer from [IssuerMetadata.issuerInfo]. Mirrors
 * OpenID4VP's verifier_info, which ISS-MDATA-REG_CERT-4.2.3-03 says to reuse.
 */
@Serializable
data class IssuerInfoEntry(
    val format: String,
    val data: kotlinx.serialization.json.JsonElement,
    @SerialName("credential_ids") val credentialIds: List<String>? = null,
)

/**
 * Whether a provider is registered to issue what it is offering, as decided by
 * the wallet backend per ARF section 6.6.2.3.
 *
 * [evaluated] is deliberately separate from [allowed]: a provider that carries
 * no registration certificate is not the same as one that was checked and
 * passed, and treating the two alike would make an unregistered issuer look
 * verified.
 */
@Serializable
data class IssuerEntitlement(
    val allowed: Boolean,
    val mode: String? = null,
    val evaluated: Boolean = false,
    val findings: List<IssuerEntitlementFinding> = emptyList(),
    val entitlements: List<String> = emptyList(),
    val subject: String? = null,
)

/** One reason an entitlement check did not pass. */
@Serializable
data class IssuerEntitlementFinding(
    val code: String,
    val message: String,
    @SerialName("credential_type") val credentialType: String? = null,
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
    // Appended rather than grouped with the OID4VCI fields above: this is a
    // data class, so a property's position is part of the binary API
    // (componentN, copy, the constructor descriptor).
    /**
     * How this Issuer will accept the Holder's key being identified -
     * OID4VCI's `cryptographic_binding_methods_supported`, e.g. `["jwk"]`
     * (HAIP) or `["did:jwk"]` (DIIP).
     *
     * This is the field that lets one wallet serve both ecosystems without a
     * setting: the Issuer declares what it can verify, and the wallet shapes
     * its proof to match. See `HolderBinding.negotiate`.
     */
    @SerialName("cryptographic_binding_methods_supported")
    val cryptographicBindingMethodsSupported: List<String>? = null,
    /**
     * Credential Auxiliary Data v0.1 advertisement (`{"to_wallet": [...], "to_issuer": [...]}`), kept raw so a value that must
     * not be there can be told from a slot list; read by [AuxiliaryDataV01.advertisement]. Appended: binary API of a data class.
     */
    @SerialName("auxiliary_data_supported") val auxiliaryDataSupported: JsonElement? = null,
)

/**
 * Display metadata for a credential configuration.
 */
@Serializable
data class CredentialDisplayMetadata(
    val display: List<CredentialDisplayEntry>? = null,
    val claims: List<JsonElement>? = null,
    /**
     * The PRESENCE of each member of a REMOVED secret-bearing shape in the configuration's public metadata, never its value
     * ([LegacyMemberPresence]): a configuration that publishes any of them is a superseded shape and is not offered
     * ([AuxiliaryDataV01.advertisement]). [carriesLegacyMember] is the test.
     */
    @SerialName("org.siros.secret_seed") @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val legacySecretSeed: LegacyMemberPresence = LegacyMemberPresence.ABSENT,
    @SerialName("org.siros.holder_commitments") @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val legacyOrgHolderCommitments: LegacyMemberPresence = LegacyMemberPresence.ABSENT,
    @SerialName("org.siros.psc") @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val legacyOrgPsc: LegacyMemberPresence = LegacyMemberPresence.ABSENT,
    @SerialName("holder_commitments") @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val legacyHolderCommitments: LegacyMemberPresence = LegacyMemberPresence.ABSENT,
    @SerialName("secret_members") @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val legacySecretMembers: LegacyMemberPresence = LegacyMemberPresence.ABSENT,
    /**
     * The Auxiliary Data v0.1 response member as it appears in PUBLIC metadata, where it is forbidden: kept raw only so its
     * presence can be told ([AuxiliaryDataV01.advertisement] classifies the configuration as malformed). Appended: binary API.
     */
    @SerialName("auxiliary_data") val auxiliaryData: JsonElement? = null,
) {
    /** Whether any member of a removed secret-bearing shape was present. */
    val carriesLegacyMember: Boolean
        get() = listOf(legacySecretSeed, legacyOrgHolderCommitments, legacyOrgPsc, legacyHolderCommitments, legacySecretMembers).any { it == LegacyMemberPresence.PRESENT }
}

@Serializable
data class CredentialDisplayEntry(
    val name: String,
    val description: String? = null,
    val locale: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
    @SerialName("background_image") val backgroundImage: BackgroundImage? = null,
    val logo: LogoInfo? = null,
    /**
     * OID4VCI's optional richer rendering (mirroring `sirosfoundation/vc`'s
     * `MetadataRendering`/`CredentialMetadataDisplay.Rendering`): a `simple.logo`
     * alternative to [logo], or a full SVG card template. Before this was added, a
     * configuration that only advertised [rendering] (no flat [logo]) silently kept
     * ignoreUnknownKeys' default treatment - type parsed fine, [rendering] vanished,
     * and the offer fell back to [backgroundColor]/an initial-letter badge even
     * though the issuer had published a properly designed card (confirmed live for
     * nym_auth: `display[0]` carries both the legacy flat fields AND
     * `rendering.svg_templates`, every refresh, not a stale cache - see
     * [org.siros.sdk.wallet.SirosWallet.buildCredentialOfferFromMetadata], which
     * reads this field down into [org.siros.sdk.credentials.CredentialOffer.logoUri]).
     */
    val rendering: CredentialDisplayRendering? = null,
)

/** See [CredentialDisplayEntry.rendering]; field-for-field mirror of vc's `MetadataRendering`. */
@Serializable
data class CredentialDisplayRendering(
    val simple: CredentialSimpleRendering? = null,
    @SerialName("svg_templates") val svgTemplates: List<CredentialSvgTemplate>? = null,
)

/** mirrors vc's `MetadataSimpleRendering`: a logo alternative to [CredentialDisplayEntry.logo]. */
@Serializable
data class CredentialSimpleRendering(
    val logo: LogoInfo? = null,
)

/** mirrors vc's `MetadataSvgTemplate`: a full SVG card template, same shape [org.siros.sdk.credentials.logo.LogoSanitizer] already rasterizes as a logo. */
@Serializable
data class CredentialSvgTemplate(
    val uri: String,
    val properties: CredentialSvgTemplateProperties? = null,
)

/** mirrors vc's `MetadataSvgTemplateProperties`. */
@Serializable
data class CredentialSvgTemplateProperties(
    val orientation: String? = null,
    @SerialName("color_scheme") val colorScheme: String? = null,
    val contrast: String? = null,
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
    /**
     * OID4VCI credential format (e.g. `"mso_mdoc"`, `"dc+sd-jwt"`) - lets a
     * picker UI distinguish same-named offers from the same issuer, such as
     * an ARF PID issued as either an mdoc or an SD-JWT VC.
     */
    val format: String = "",
    /**
     * The credential type this configuration issues: the `vct` of an SD-JWT VC.
     *
     * Carried on the offer because it is the type the wallet's checks are made
     * about - the issuer's entitlement, and the comparison against what
     * actually arrives - and unlike resolved type metadata it is known whether
     * or not that resolution succeeded.
     */
    val vct: String? = null,
    /** The `doctype` of an mdoc, the counterpart to [vct]. */
    val doctype: String? = null,
    val backgroundColor: String? = null,
    val textColor: String? = null,
    val logoUri: String? = null,
    val issuerLogoUri: String? = null,
    /** Non-null when the offer uses a pre-authorized code grant. */
    val preAuthorizedCode: String? = null,
    /** Optional user PIN / tx_code required with the pre-authorized code. */
    val txCode: String? = null,
    /**
     * The Issuer's advertised `cryptographic_binding_methods_supported` for
     * this configuration, carried from its metadata so the wallet can shape
     * the OID4VCI proof to what this Issuer can verify - see
     * `HolderBinding.negotiate`. Empty when the Issuer said nothing.
     */
    val cryptographicBindingMethodsSupported: List<String> = emptyList(),
)
