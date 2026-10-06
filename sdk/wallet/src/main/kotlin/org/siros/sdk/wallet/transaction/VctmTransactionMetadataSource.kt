// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.Integrity
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.VctmFetcher
import timber.log.Timber
import java.util.concurrent.TimeUnit

/**
 * The production [TransactionMetadataSource]: type metadata through the
 * SDK's [VctmFetcher] (registry, issuer endpoint, well-known path, with its
 * caches) and referenced documents through a bounded HTTPS GET.
 *
 * The type metadata is only used if it is the document the credential's
 * `vct#integrity` pins (when it pins one) and if it describes the credential's
 * own `vct`. Referenced documents are fetched with no credentials of the
 * wallet attached, over HTTPS only, with a size cap and a hard time limit.
 *
 * Staleness: [VctmFetcher] may answer from its cache (30 minutes in memory,
 * up to 7 days on disk). A pinned `vct#integrity` is always enforced against
 * what it returns; without a pin the metadata is as fresh as that cache.
 *
 * @param allowInsecureHttp only for tests: permits `http://` documents.
 */
internal class VctmTransactionMetadataSource(
    private val vctmFetcher: VctmFetcher,
    private val registryUrl: String,
    private val httpClient: OkHttpClient,
    private val allowInsecureHttp: Boolean = false,
) : TransactionMetadataSource {

    override suspend fun typeMetadata(credential: StoredCredential): JsonObject? {
        val payload = CredentialUtils.parseJwtPayload(credential.raw) ?: return null
        val vct = (payload["vct"] as? JsonPrimitive)?.contentOrNull ?: return null
        val pinned = (payload["vct#integrity"] as? JsonPrimitive)?.contentOrNull
        val document = try {
            vctmFetcher.fetchDocument(
                issuerUrl = credential.credentialIssuerIdentifier.orEmpty(),
                scope = credential.credentialConfigurationId.orEmpty(),
                vct = vct,
                registryUrl = registryUrl,
                expectedIntegrity = pinned,
            )
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Timber.w(e, "Type metadata lookup failed")
            null
        } ?: return null
        if (document.vctm.vct != vct) {
            Timber.w("Type metadata describes '${document.vctm.vct}', not the credential's type")
            return null
        }
        if (pinned != null && !Integrity.matches(document.raw.toByteArray(Charsets.UTF_8), pinned)) return null
        return try {
            Json.parseToJsonElement(document.raw) as? JsonObject
        } catch (_: Exception) {
            null
        }
    }

    override suspend fun document(uri: String): String? = withContext(Dispatchers.IO) {
        val url = uri.toHttpUrlOrNull() ?: return@withContext null
        if (!url.isHttps && !allowInsecureHttp) return@withContext null
        val client = httpClient.newBuilder()
            .callTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .followSslRedirects(false)
            .build()
        try {
            client.newCall(Request.Builder().url(url).get().build()).execute().use { response ->
                if (!response.isSuccessful) return@use null
                val source = response.body?.source() ?: return@use null
                // Read one byte past the cap to tell "exactly at" from "over".
                source.request(MAX_DOCUMENT_BYTES + 1)
                if (source.buffer.size > MAX_DOCUMENT_BYTES) return@use null
                source.readUtf8()
            }
        } catch (e: java.io.IOException) {
            Timber.w(e, "Document fetch failed")
            null
        }
    }

    companion object {
        /** Largest document accepted (a schema or label catalogue is a few KiB). */
        const val MAX_DOCUMENT_BYTES = 256L * 1024

        /** Wall-clock limit for one document fetch. */
        const val TIMEOUT_SECONDS = 10L
    }
}
