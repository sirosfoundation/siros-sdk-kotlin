package org.sirosfoundation.sdk.credentials

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
    val metadata: CredentialMetadata? = null,
    @SerialName("issued_at") val issuedAt: Long? = null,
    @SerialName("expires_at") val expiresAt: Long? = null,
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

@Serializable
data class ClaimMeta(
    val path: List<String>,
    val label: String? = null,
    val description: String? = null,
    val sd: String? = null,
    val mandatory: Boolean = false,
)

@Serializable
data class IssuerInfo(
    val name: String? = null,
    val url: String? = null,
)

@Serializable
data class LogoInfo(
    val uri: String? = null,
    @SerialName("alt_text") val altText: String? = null,
)

/**
 * Local credential store.
 * SDK consumers can implement custom storage backends.
 */
interface CredentialStore {
    suspend fun getAll(): List<StoredCredential>
    suspend fun getById(id: String): StoredCredential?
    suspend fun save(credential: StoredCredential)
    suspend fun update(credential: StoredCredential)
    suspend fun delete(id: String)
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
