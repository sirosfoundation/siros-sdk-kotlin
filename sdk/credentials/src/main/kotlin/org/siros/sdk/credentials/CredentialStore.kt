package org.siros.sdk.credentials

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** Supported verifiable credential formats. */
enum class CredentialFormat(val value: String) {
    SD_JWT_VC("vc+sd-jwt"),
    DC_SD_JWT("dc+sd-jwt"),
    MSO_MDOC("mso_mdoc"),
    JWT_VC_JSON("jwt_vc_json"),

    /**
     * A JSON Web Proof carrying a BBS credential
     * (`draft-bormann-jwp-modular-bbs`).
     *
     * Not a variant of SD-JWT despite both using the SD-JWT VC data model.
     * The container is different - JWP has its own issued and presented
     * forms, and selective disclosure is BBS itself rather than `_sd`
     * digests - so none of the `~`-delimited parsing applies. What is
     * shared is everything above the container: `vct`, the VCTM metadata
     * path, claim display.
     */
    JWP("jwp"),
}

/** A stored verifiable credential with parsed metadata. */
@Serializable
data class StoredCredential(
    /**
     * A randomly-generated uint32-range identifier, matching wallet-frontend's
     * `credentialId: number` (privatedata-spec §6) - not a UUID. Cross-client
     * interop (the same encrypted container read by either client) requires
     * this to be a genuine JSON number on the wire, not a string.
     */
    val id: Long,
    val format: String,
    val raw: String,
    /** Key ID (JWK thumbprint) of the keypair bound to this credential. */
    val kid: String? = null,
    val metadata: CredentialMetadata? = null,
    @SerialName("issued_at") val issuedAt: Long? = null,
    @SerialName("expires_at") val expiresAt: Long? = null,
    /**
     * OID4VCI §10 notification identifier for this credential, if the issuer
     * returned one. Persisted client-side and echoed back when a lifecycle
     * event occurs.
     */
    @SerialName("notification_id") val notificationId: String? = null,
    /**
     * Issuer identifier this credential was obtained from - part of
     * privatedata-spec's normative `S.credentials[]` fields (`WalletSessionEventNewCredential`
     * in wallet-frontend), needed to re-fetch VCTM display metadata after a
     * fresh login (wallet-frontend doesn't persist `metadata` either - it
     * re-fetches/derives display info live rather than snapshotting it into
     * the encrypted container).
     */
    @SerialName("credential_issuer_identifier") val credentialIssuerIdentifier: String? = null,
    /**
     * Credential configuration ID (issuance scope) this credential was
     * requested under - part of privatedata-spec's normative fields, needed
     * (alongside [credentialIssuerIdentifier]) to re-fetch VCTM after login.
     */
    @SerialName("credential_configuration_id") val credentialConfigurationId: String? = null,
    /**
     * Identifier shared by every copy issued in the same OID4VCI response
     * (`batch_credential_issuance`/key-attestation multi-proof issuance) -
     * privatedata-spec's normative `S.credentials[].batchId` (`number`).
     * Mirrors wallet-frontend exactly: ALWAYS assigned a fresh value per
     * issuance response (`useOID4VCIFlow.ts`'s `batchId = Date.now()`), even
     * for a single-credential issuance - there is no "no batch" sentinel on
     * either client, since every issuance response is itself a batch of at
     * least one. Lets the UI show one card per batch instead of one per copy
     * (`CredentialsContextProvider.fetchVcData`/[CredentialUtils.groupForDisplay]).
     */
    @SerialName("batch_id") val batchId: Long,
    /** 0-based position of this copy within its [batchId]. */
    @SerialName("instance_id") val instanceId: Int,
)

@Serializable
data class CredentialMetadata(
    val name: String? = null,
    val description: String? = null,
    val issuer: IssuerInfo? = null,
    val vct: String? = null,
    val doctype: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
    val logo: LogoInfo? = null,
    val claims: List<ClaimMeta>? = null,
    /** VCTM SVG rendering templates, if the issuer's VCTM published any. */
    @SerialName("svg_templates") val svgTemplates: List<SvgTemplateInfo>? = null,
)

/** Metadata about an individual claim within a credential. */
@Serializable
data class ClaimMeta(
    /** JSON path elements selecting this claim in the credential. */
    val path: List<String>,
    /** Human-readable label for display. */
    val label: String? = null,
    /** Human-readable description. */
    val description: String? = null,
    /** Selective disclosure rule: "always", "allowed", or "never". */
    val sd: String? = null,
    /** Whether this claim must be present in a presentation. */
    val mandatory: Boolean = false,
    /** VCTM SVG template placeholder ID this claim fills, if any. */
    @SerialName("svg_id") val svgId: String? = null,
)

/** A VCTM SVG rendering template reference (VCTM section 6, `rendering.svg_templates`). */
@Serializable
data class SvgTemplateInfo(
    val uri: String,
    @SerialName("color_scheme") val colorScheme: String? = null,
    val contrast: String? = null,
    val orientation: String? = null,
)

/** Information about the credential issuer. */
@Serializable
data class IssuerInfo(
    /** Display name of the issuer. */
    val name: String? = null,
    /** URL of the issuer. */
    val url: String? = null,
)

/** Logo image reference for a credential or issuer. */
@Serializable
data class LogoInfo(
    /** URI of the logo image. */
    val uri: String? = null,
    /** Accessible alt-text for the logo. */
    @SerialName("alt_text") val altText: String? = null,
)

/**
 * Local credential store.
 *
 * SDK consumers can implement custom storage backends (e.g. Room, SQLite,
 * encrypted preferences). All methods are suspend to allow I/O-backed
 * implementations.
 *
 * Thread safety: implementations must be safe for concurrent access
 * from multiple coroutines.
 */
interface CredentialStore {
    /** Return all stored credentials. */
    suspend fun getAll(): List<StoredCredential>

    /** Find a credential by its unique [id]. Returns null if not found. */
    suspend fun getById(id: Long): StoredCredential?

    /** Store a new credential. Overwrites any existing credential with the same ID. */
    suspend fun save(credential: StoredCredential)

    /** Update an existing credential's metadata. Equivalent to [save]. */
    suspend fun update(credential: StoredCredential)

    /** Delete a credential by [id]. No-op if not found. */
    suspend fun delete(id: Long)

    /** Remove all stored credentials. */
    suspend fun clear()
}

/**
 * In-memory credential store for development/testing.
 */
class InMemoryCredentialStore : CredentialStore {
    private val store = mutableMapOf<Long, StoredCredential>()

    override suspend fun getAll(): List<StoredCredential> = store.values.toList()
    override suspend fun getById(id: Long): StoredCredential? = store[id]
    override suspend fun save(credential: StoredCredential) { store[credential.id] = credential }
    override suspend fun update(credential: StoredCredential) { store[credential.id] = credential }
    override suspend fun delete(id: Long) { store.remove(id) }
    override suspend fun clear() { store.clear() }
}
