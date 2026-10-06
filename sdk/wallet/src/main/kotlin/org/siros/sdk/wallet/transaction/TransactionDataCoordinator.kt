// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet.transaction

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.siros.sdk.credentials.TransactionDataError
import org.siros.sdk.credentials.TransactionDataReason
import org.siros.sdk.keystore.TransactionBinding
import org.siros.sdk.wallet.AuthenticationFactorsProvider
import org.siros.sdk.wallet.SigningOperation
import org.siros.sdk.wallet.TransactionConsentHandler
import org.siros.sdk.wallet.TransactionLogEntry
import org.siros.sdk.wallet.TransactionLogStore
import org.siros.sdk.wallet.TransactionOutcome
import timber.log.Timber

/**
 * What a successful [TransactionDataCoordinator.process] hands to signing:
 * the KB-JWT binding for each DCQL query id an entry is bound to. A query not
 * in it is presented without transaction data.
 */
internal class ScaPresentationPlan(private val bindings: Map<String, TransactionBinding>) {
    fun bindingFor(queryId: String?): TransactionBinding? = queryId?.let { bindings[it] }
}

/**
 * The whole `transaction_data` pipeline for one request (contract section 4):
 * validate, show and obtain consent, establish authentication factors, and
 * log the outcome. Throws a [TransactionDataError] to refuse or decline, with
 * nothing signed; returns the plan to sign with otherwise.
 */
internal class TransactionDataCoordinator(
    private val validator: TransactionDataValidator,
    private val display: TransactionDisplayBuilder,
    private val consentHandler: () -> TransactionConsentHandler?,
    private val factorsProvider: () -> AuthenticationFactorsProvider,
    private val log: () -> TransactionLogStore,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val consentTimeoutMillis: Long = CONSENT_TIMEOUT_MILLIS,
) {
    /** Records [error] as a refusal of [request] and throws it. */
    suspend fun refuse(request: TransactionDataRequest, error: TransactionDataError): Nothing {
        record(request, null, TransactionOutcome.REFUSED, error.reason)
        throw error
    }

    /** Records a refusal of a request whose entries could not even be read (nothing but the verifier is known). */
    suspend fun recordUnreadable(verifier: String?, error: TransactionDataError) {
        record(TransactionDataRequest(emptyList(), null, emptyMap(), verifier = verifier), null, TransactionOutcome.REFUSED, error.reason, unreadable = true)
    }

    suspend fun process(request: TransactionDataRequest): ScaPresentationPlan {
        val validated = try {
            validator.validate(request)
        } catch (e: TransactionDataError) {
            record(request, null, TransactionOutcome.REFUSED, e.reason)
            throw e
        }
        try {
            val consentModel = display.build(validated, request.verifier, request.requestSigned)
            val handler = consentHandler() ?: throw TransactionDataError(
                TransactionDataReason.NO_CONSENT_HANDLER,
                "No consent handler is registered, so the transaction cannot be shown to the user",
            )
            // A handler that throws or does not answer is a decline, never consent.
            val confirmed = try {
                withTimeoutOrNull(consentTimeoutMillis) { handler.confirm(consentModel) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.w(e, "The transaction consent handler failed; treating it as declined")
                null
            }
            if (confirmed != true) {
                throw TransactionDataError(TransactionDataReason.DECLINED, "The user did not confirm the transaction")
            }
            val bindings = LinkedHashMap<String, TransactionBinding>()
            for (queryId in validated.boundQueryIds()) {
                val credential = request.credentials.getValue(queryId).first()
                // A provider that fails has established nothing.
                val factors = try {
                    factorsProvider().factorsFor(SigningOperation(credential))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Timber.w(e, "The authentication factors provider failed")
                    emptyList()
                }
                bindings[queryId] = validated.bindingFor(queryId, factors)!!
            }
            record(request, validated, TransactionOutcome.CONSENTED, null)
            return ScaPresentationPlan(bindings)
        } catch (e: TransactionDataError) {
            record(
                request, validated,
                if (e.reason == TransactionDataReason.DECLINED) TransactionOutcome.DECLINED else TransactionOutcome.REFUSED,
                e.reason,
            )
            throw e
        }
    }

    private suspend fun record(
        request: TransactionDataRequest,
        validated: ValidatedTransactionData?,
        outcome: TransactionOutcome,
        reason: TransactionDataReason?,
        unreadable: Boolean = false,
    ) {
        val now = nowMillis()
        val credentialName = validated?.entries?.firstOrNull()?.contexts?.firstOrNull()?.let { it.credential.metadata?.name ?: (it.metadata["name"] as? JsonPrimitive)?.contentOrNull }
            ?: request.credentials.values.firstOrNull()?.firstOrNull()?.metadata?.name
        // Refused before validation finished: read what can be read, for the record only.
        val items: List<Pair<String?, JsonObject?>> = validated?.entries?.map { it.type to it.payload }
            ?: if (unreadable) listOf(null to null) else request.entries.map { e ->
                runCatching { TransactionDataDecoder.decode(e) }.getOrNull()?.let { it.type to it.payload } ?: (null to null)
            }
        for ((type, payload) in items) {
            try {
                log().append(
                    TransactionLogEntry(
                        transactionId = (payload?.get("transaction_id") as? JsonPrimitive)?.contentOrNull,
                        transactionType = type,
                        typeName = type?.let { TypeNames.builtIn(it) },
                        entities = if (type != null && payload != null) entityNames(type, payload) else emptyMap(),
                        verifier = request.verifier,
                        credential = credentialName,
                        timestampMillis = now,
                        outcome = outcome,
                        reason = reason?.code,
                    ),
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Timber.e(e, "Could not record the transaction in the log")
            }
        }
    }

    companion object {
        /** How long the user has to answer; the backend's own interaction timeout is five minutes. */
        const val CONSENT_TIMEOUT_MILLIS = 5L * 60 * 1000

        /** The entity names EC TS12 5.3 asks for, by built-in type; nothing else is copied out of the payload. */
        fun entityNames(type: String, payload: JsonObject): Map<String, String> {
            fun name(o: JsonElement?, member: String): String? =
                ((o as? JsonObject)?.get(member) as? JsonPrimitive)?.contentOrNull
            val out = linkedMapOf<String, String>()
            fun put(key: String, value: String?) { if (!value.isNullOrEmpty()) out[key] = value }
            when (type) {
                "urn:eudi:sca:payment:1" -> {
                    put("payee", name(payload["payee"], "name"))
                    put("pisp", name(payload["pisp"], "legal_name"))
                }
                "urn:eudi:sca:login_risk_transaction:1" -> put("service", (payload["service"] as? JsonPrimitive)?.contentOrNull)
                "urn:eudi:sca:account_access:1" -> put("aisp", name(payload["aisp"], "legal_name"))
                "urn:eudi:sca:emandate:1" -> {
                    val pp = payload["payment_payload"]
                    put("payee", name((pp as? JsonObject)?.get("payee"), "name"))
                    put("pisp", name((pp as? JsonObject)?.get("pisp"), "legal_name"))
                }
            }
            return out
        }
    }
}
