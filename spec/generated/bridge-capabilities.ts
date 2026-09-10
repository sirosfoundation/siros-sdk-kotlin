// GENERATED from spec/bridge-capabilities.json by tools/gen_bridge_capabilities.py - do not edit.
// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

/** Version of the vocabulary these types were generated from. */
export const BRIDGE_VOCABULARY_VERSION = 1 as const;
/** Version of the descriptor schema. */
export const BRIDGE_DESCRIPTOR_VERSION = 1 as const;

/** Capability ids. Stable once published; retired ids stay here and appear in DEPRECATED_CAPABILITIES. */
export const BRIDGE_CAPABILITY_IDS = [
  'webauthn',
  'dc_api',
  'idv.physical_id',
  'oidc',
  'proximity.byte_pipe',
  'proximity.session',
  'zk',
  'keys',
  'credentials',
  'auth',
  'engine',
] as const;
export type BridgeCapabilityId = (typeof BRIDGE_CAPABILITY_IDS)[number];

/** Deprecated ids and why. */
export const DEPRECATED_CAPABILITIES: Partial<Record<BridgeCapabilityId, string>> = {
  'proximity.byte_pipe': "Superseded by proximity.session; removed once every shipped wrapper advertises the session capability.",
};

/**
 * Native WebAuthn create()/get() in place of the WebView's, so security keys
 * reach the page over the SDK's own CTAP2 transports and platform passkeys
 * carry the PRF extension.
 *
 * Stage: reached.
 */
export interface WebauthnCapability {
  /** Assertions can return the WebAuthn PRF extension output. */
  prf?: boolean;
  /** CTAP2 transports available to the page: `usb`, `nfc`, `ble`, `hybrid`. */
  security_key_transports?: string[];
}

/**
 * The host is a W3C Digital Credentials API provider on this device and
 * mirrors the page's credential list into the platform registry; presentation
 * responses are returned through the host.
 *
 * Stage: reached.
 */
export interface DcApiCapability {
  /** Version of the siros-dc-matcher the host registers. */
  matcher_version?: string;
  /** Credential formats the registry accepts: `mso_mdoc`, `dc+sd-jwt`. */
  formats?: string[];
}

/**
 * Physical identity document scanning and face match, started from the page
 * and returned as an identity-verification result.
 *
 * Stage: reached.
 */
export interface IdvPhysicalIdCapability {
  /** Vendor of the capture SDK, e.g. `facetec`. */
  provider?: string;
}

/**
 * Host-mediated OpenID Connect login: the authorization request opens in a
 * system browser tab and the response is handed back to the page.
 *
 * Stage: reached.
 */
export interface OidcCapability {
}

/**
 * Raw Bluetooth LE byte pipe (client and server) with the ISO 18013-5 session
 * layer implemented by the page.
 *
 * Stage: reached. DEPRECATED: Superseded by proximity.session; removed once every shipped wrapper advertises the session capability.
 */
export interface ProximityBytePipeCapability {
  /** `client`, `server`. */
  roles?: string[];
}

/**
 * ISO 18013-5 proximity presentation run natively as a session: device
 * engagement, transport, session encryption and reader authentication in the
 * host; the page supplies credentials, consent and device signatures through
 * callbacks.
 *
 * Stage: A.
 */
export interface ProximitySessionCapability {
  /** `ble_central`, `ble_peripheral`, `nfc`. */
  transports?: string[];
  /** NFC static handover to BLE is available. */
  nfc_static_handover?: boolean;
  /** Reader authentication against the configured trust lists is evaluated natively. */
  reader_auth?: boolean;
}

/**
 * Zero-knowledge presentation proofs generated natively. The page decides a
 * proof is needed and supplies credential bytes and transcript; the host
 * resolves the circuit, proves, and calls back for the witness signature.
 *
 * Stage: A.
 */
export interface ZkCapability {
  /** Proof system ids the host can prove for, e.g. `longfellow-libzk-v1`, `vega-mdoc-v1`. From the SDK's ZkMdocPresentation.systemIds(). */
  systems?: string[];
  /** Circuits are cached on disk across launches. */
  circuit_cache?: boolean;
}

/**
 * Key operations performed natively on a container the page imports and
 * exports around each session: generate, sign, attest, over the SDK's key
 * manager and its WSCD plugins.
 *
 * Stage: B.
 */
export interface KeysCapability {
  /** Registered WSCD plugin ids. */
  wscd_plugins?: string[];
}

/**
 * Credential matching (DCQL) and presentation assembly performed natively over
 * the imported container.
 *
 * Stage: C.
 */
export interface CredentialsCapability {
  /** `mso_mdoc`, `dc+sd-jwt`. */
  formats?: string[];
}

/**
 * Authentication and PRF-derived container ownership held natively; the page
 * no longer derives the unwrap key.
 *
 * Stage: D.
 */
export interface AuthCapability {
}

/**
 * A native Wallet Messaging Protocol engine. Reserved so that, if it ever
 * exists, it is one more advertised capability rather than a new detection
 * mechanism.
 *
 * Stage: never.
 */
export interface EngineCapability {
  /** WMP capability names, as WmpRegistry.allCapabilities() reports them: `oid4vci`, `oid4vp`, ... */
  wmp_capabilities?: string[];
}

/** Capability id to its parameters. Present means offered. */
export interface BridgeCapabilities {
  webauthn?: WebauthnCapability;
  dc_api?: DcApiCapability;
  'idv.physical_id'?: IdvPhysicalIdCapability;
  oidc?: OidcCapability;
  'proximity.byte_pipe'?: ProximityBytePipeCapability;
  'proximity.session'?: ProximitySessionCapability;
  zk?: ZkCapability;
  keys?: KeysCapability;
  credentials?: CredentialsCapability;
  auth?: AuthCapability;
  engine?: EngineCapability;
}

/** The host application advertising the bridge. */
export interface BridgeHost {
  /** Host application id (Android applicationId / iOS bundle id). */
  name: string;
  /** Host application version string. */
  version: string;
  /** SIROS SDK version the host links. */
  sdk_version: string;
}

/**
 * What a host advertises to the page. `bridge` is the descriptor schema
 * itself; `vocabulary` says which version of this file the ids come from, so a
 * page can tell 'unknown id' from 'older host'.
 */
export interface BridgeDescriptor {
  bridge: { version: number };
  /** The vocabulary_version this host was built against. */
  vocabulary: number;
  platform: 'android' | 'ios';
  host: BridgeHost;
  capabilities: BridgeCapabilities;
}

/** True when the descriptor offers `id`. Unknown ids are simply not offered. */
export function offers<K extends BridgeCapabilityId>(descriptor: BridgeDescriptor, id: K): descriptor is BridgeDescriptor & { capabilities: Required<Pick<BridgeCapabilities, K>> } {
  return Object.prototype.hasOwnProperty.call(descriptor.capabilities, id);
}
