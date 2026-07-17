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
}

/** A stored verifiable credential with parsed metadata. */
@Serializable
data class StoredCredential(
    val id: String,
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
    suspend fun getById(id: String): StoredCredential?

    /** Store a new credential. Overwrites any existing credential with the same ID. */
    suspend fun save(credential: StoredCredential)

    /** Update an existing credential's metadata. Equivalent to [save]. */
    suspend fun update(credential: StoredCredential)

    /** Delete a credential by [id]. No-op if not found. */
    suspend fun delete(id: String)

    /** Remove all stored credentials. */
    suspend fun clear()
}

/**
 * In-memory credential store for development/testing.
 */
class InMemoryCredentialStore : CredentialStore {
    private val store = mutableMapOf<String, StoredCredential>()

    override suspend fun getAll(): List<StoredCredential> = store.values.toList()
    override suspend fun getById(id: String): StoredCredential? = store[id]
    override suspend fun save(credential: StoredCredential) { store[credential.id] = credential }
    override suspend fun update(credential: StoredCredential) { store[credential.id] = credential }
    override suspend fun delete(id: String) { store.remove(id) }
    override suspend fun clear() { store.clear() }
}
