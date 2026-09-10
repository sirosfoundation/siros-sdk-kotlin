// GENERATED from spec/bridge-capabilities.json by tools/gen_bridge_capabilities.py - do not edit.
// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

package org.siros.sdk.transport.bridge

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** Versions of the vocabulary and of the descriptor schema this SDK was generated from. */
public object BridgeVocabulary {
    public const val VERSION: Int = 1
    public const val DESCRIPTOR_VERSION: Int = 1
}

/** Capability ids. Stable once published; retired ids stay here with a [DEPRECATED] note. */
public object BridgeCapabilityId {
    /** Native WebAuthn create()/get() in place of the WebView's, so security keys reach the page over the SDK's own CTAP2 transports and platform passkeys carry the PRF extension. */
    public const val WEBAUTHN: String = "webauthn"
    /** The host is a W3C Digital Credentials API provider on this device and mirrors the page's credential list into the platform registry; presentation responses are returned through the host. */
    public const val DC_API: String = "dc_api"
    /** Physical identity document scanning and face match, started from the page and returned as an identity-verification result. */
    public const val IDV_PHYSICAL_ID: String = "idv.physical_id"
    /** Host-mediated OpenID Connect login: the authorization request opens in a system browser tab and the response is handed back to the page. */
    public const val OIDC: String = "oidc"
    /** Raw Bluetooth LE byte pipe (client and server) with the ISO 18013-5 session layer implemented by the page. */
    public const val PROXIMITY_BYTE_PIPE: String = "proximity.byte_pipe"
    /** ISO 18013-5 proximity presentation run natively as a session: device engagement, transport, session encryption and reader authentication in the host; the page supplies credentials, consent and device signatures through callbacks. */
    public const val PROXIMITY_SESSION: String = "proximity.session"
    /** Zero-knowledge presentation proofs generated natively. The page decides a proof is needed and supplies credential bytes and transcript; the host resolves the circuit, proves, and calls back for the witness signature. */
    public const val ZK: String = "zk"
    /** Key operations performed natively on a container the page imports and exports around each session: generate, sign, attest, over the SDK's key manager and its WSCD plugins. */
    public const val KEYS: String = "keys"
    /** Credential matching (DCQL) and presentation assembly performed natively over the imported container. */
    public const val CREDENTIALS: String = "credentials"
    /** Authentication and PRF-derived container ownership held natively; the page no longer derives the unwrap key. */
    public const val AUTH: String = "auth"
    /** A native Wallet Messaging Protocol engine. Reserved so that, if it ever exists, it is one more advertised capability rather than a new detection mechanism. */
    public const val ENGINE: String = "engine"

    public val ALL: List<String> = listOf(WEBAUTHN, DC_API, IDV_PHYSICAL_ID, OIDC, PROXIMITY_BYTE_PIPE, PROXIMITY_SESSION, ZK, KEYS, CREDENTIALS, AUTH, ENGINE)
    /** Deprecated ids and why. */
    public val DEPRECATED: Map<String, String> = mapOf(
        PROXIMITY_BYTE_PIPE to "Superseded by proximity.session; removed once every shipped wrapper advertises the session capability.",
    )
}

/**
 * Native WebAuthn create()/get() in place of the WebView's, so security keys
 * reach the page over the SDK's own CTAP2 transports and platform passkeys
 * carry the PRF extension.
 *
 * Stage: reached.
 */
@Serializable
public data class WebauthnCapability(
    /** Assertions can return the WebAuthn PRF extension output. */
    val prf: Boolean? = null,
    /** CTAP2 transports available to the page: `usb`, `nfc`, `ble`, `hybrid`. */
    @SerialName("security_key_transports") val securityKeyTransports: List<String>? = null,
)

/**
 * The host is a W3C Digital Credentials API provider on this device and
 * mirrors the page's credential list into the platform registry; presentation
 * responses are returned through the host.
 *
 * Stage: reached.
 */
@Serializable
public data class DcApiCapability(
    /** Version of the siros-dc-matcher the host registers. */
    @SerialName("matcher_version") val matcherVersion: String? = null,
    /** Credential formats the registry accepts: `mso_mdoc`, `dc+sd-jwt`. */
    val formats: List<String>? = null,
)

/**
 * Physical identity document scanning and face match, started from the page
 * and returned as an identity-verification result.
 *
 * Stage: reached.
 */
@Serializable
public data class IdvPhysicalIdCapability(
    /** Vendor of the capture SDK, e.g. `facetec`. */
    val provider: String? = null,
)

/**
 * Host-mediated OpenID Connect login: the authorization request opens in a
 * system browser tab and the response is handed back to the page.
 *
 * Stage: reached.
 */
@Serializable
public class OidcCapability

/**
 * Raw Bluetooth LE byte pipe (client and server) with the ISO 18013-5 session
 * layer implemented by the page.
 *
 * Stage: reached. DEPRECATED: Superseded by proximity.session; removed once every shipped wrapper advertises the session capability.
 */
@Serializable
public data class ProximityBytePipeCapability(
    /** `client`, `server`. */
    val roles: List<String>? = null,
)

/**
 * ISO 18013-5 proximity presentation run natively as a session: device
 * engagement, transport, session encryption and reader authentication in the
 * host; the page supplies credentials, consent and device signatures through
 * callbacks.
 *
 * Stage: A.
 */
@Serializable
public data class ProximitySessionCapability(
    /** `ble_central`, `ble_peripheral`, `nfc`. */
    val transports: List<String>? = null,
    /** NFC static handover to BLE is available. */
    @SerialName("nfc_static_handover") val nfcStaticHandover: Boolean? = null,
    /** Reader authentication against the configured trust lists is evaluated natively. */
    @SerialName("reader_auth") val readerAuth: Boolean? = null,
)

/**
 * Zero-knowledge presentation proofs generated natively. The page decides a
 * proof is needed and supplies credential bytes and transcript; the host
 * resolves the circuit, proves, and calls back for the witness signature.
 *
 * Stage: A.
 */
@Serializable
public data class ZkCapability(
    /** Proof system ids the host can prove for, e.g. `longfellow-libzk-v1`, `vega-mdoc-v1`. From the SDK's ZkMdocPresentation.systemIds(). */
    val systems: List<String>? = null,
    /** Circuits are cached on disk across launches. */
    @SerialName("circuit_cache") val circuitCache: Boolean? = null,
)

/**
 * Key operations performed natively on a container the page imports and
 * exports around each session: generate, sign, attest, over the SDK's key
 * manager and its WSCD plugins.
 *
 * Stage: B.
 */
@Serializable
public data class KeysCapability(
    /** Registered WSCD plugin ids. */
    @SerialName("wscd_plugins") val wscdPlugins: List<String>? = null,
)

/**
 * Credential matching (DCQL) and presentation assembly performed natively over
 * the imported container.
 *
 * Stage: C.
 */
@Serializable
public data class CredentialsCapability(
    /** `mso_mdoc`, `dc+sd-jwt`. */
    val formats: List<String>? = null,
)

/**
 * Authentication and PRF-derived container ownership held natively; the page
 * no longer derives the unwrap key.
 *
 * Stage: D.
 */
@Serializable
public class AuthCapability

/**
 * A native Wallet Messaging Protocol engine. Reserved so that, if it ever
 * exists, it is one more advertised capability rather than a new detection
 * mechanism.
 *
 * Stage: never.
 */
@Serializable
public data class EngineCapability(
    /** WMP capability names, as WmpRegistry.allCapabilities() reports them: `oid4vci`, `oid4vp`, ... */
    @SerialName("wmp_capabilities") val wmpCapabilities: List<String>? = null,
)

/** The host application advertising the bridge. */
@Serializable
public data class BridgeHost(
    /** Host application id (Android applicationId / iOS bundle id). */
    val name: String,
    /** Host application version string. */
    val version: String,
    /** SIROS SDK version the host links. */
    @SerialName("sdk_version") val sdkVersion: String,
)

@Serializable
public data class BridgeMeta(val version: Int = BridgeVocabulary.DESCRIPTOR_VERSION)

/**
 * What a host advertises to the page. `bridge` is the descriptor schema
 * itself; `vocabulary` says which version of this file the ids come from, so a
 * page can tell 'unknown id' from 'older host'.
 *
 * Build one with [BridgeDescriptorBuilder]; the page consumes the JSON form.
 */
@Serializable
public data class BridgeDescriptor(
    val bridge: BridgeMeta = BridgeMeta(),
    val vocabulary: Int = BridgeVocabulary.VERSION,
    /** `android` or `ios`. */
    val platform: String,
    val host: BridgeHost,
    /** Capability id to its parameters. Present means offered. */
    val capabilities: JsonObject,
)

/** Typed, one method per capability; the descriptor's capability map is built from what was offered. */
public class BridgeDescriptorBuilder(private val platform: String, private val host: BridgeHost) {
    private val offered = LinkedHashMap<String, kotlinx.serialization.json.JsonElement>()
    // Defaults on (bridge/vocabulary versions must always appear), nulls off (unset parameters are omitted).
    private val json = kotlinx.serialization.json.Json { encodeDefaults = true; explicitNulls = false }

    public fun webauthn(params: WebauthnCapability = WebauthnCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.WEBAUTHN] = json.encodeToJsonElement(WebauthnCapability.serializer(), params)
    }
    public fun dcApi(params: DcApiCapability = DcApiCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.DC_API] = json.encodeToJsonElement(DcApiCapability.serializer(), params)
    }
    public fun idvPhysicalId(params: IdvPhysicalIdCapability = IdvPhysicalIdCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.IDV_PHYSICAL_ID] = json.encodeToJsonElement(IdvPhysicalIdCapability.serializer(), params)
    }
    public fun oidc(params: OidcCapability = OidcCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.OIDC] = json.encodeToJsonElement(OidcCapability.serializer(), params)
    }
    public fun proximityBytePipe(params: ProximityBytePipeCapability = ProximityBytePipeCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.PROXIMITY_BYTE_PIPE] = json.encodeToJsonElement(ProximityBytePipeCapability.serializer(), params)
    }
    public fun proximitySession(params: ProximitySessionCapability = ProximitySessionCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.PROXIMITY_SESSION] = json.encodeToJsonElement(ProximitySessionCapability.serializer(), params)
    }
    public fun zk(params: ZkCapability = ZkCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.ZK] = json.encodeToJsonElement(ZkCapability.serializer(), params)
    }
    public fun keys(params: KeysCapability = KeysCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.KEYS] = json.encodeToJsonElement(KeysCapability.serializer(), params)
    }
    public fun credentials(params: CredentialsCapability = CredentialsCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.CREDENTIALS] = json.encodeToJsonElement(CredentialsCapability.serializer(), params)
    }
    public fun auth(params: AuthCapability = AuthCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.AUTH] = json.encodeToJsonElement(AuthCapability.serializer(), params)
    }
    public fun engine(params: EngineCapability = EngineCapability()): BridgeDescriptorBuilder = apply {
        offered[BridgeCapabilityId.ENGINE] = json.encodeToJsonElement(EngineCapability.serializer(), params)
    }

    public fun build(): BridgeDescriptor = BridgeDescriptor(platform = platform, host = host, capabilities = JsonObject(offered))

    /** The JSON the page receives. */
    public fun encode(): String = json.encodeToString(BridgeDescriptor.serializer(), build())
}
