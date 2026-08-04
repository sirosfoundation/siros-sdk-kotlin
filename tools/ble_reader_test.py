#!/usr/bin/env python3
"""Bare ISO 18013-5 BLE "mdoc central client" test reader.

Drives siros-sdk-kotlin's BlePeripheralServer (sample-app, "mdoc peripheral
server mode") through a real device-retrieval round trip using nothing but
the host machine's own Bluetooth adapter - no phone, Waydroid, Flutter, or
reader app needed on this side. Useful for validating the BLE GATT wire
protocol (UUIDs, chunking, session encryption) in isolation before involving
a full conformance-grade reader like siros-verifier-app or Google's multipaz.

This is a TEST TOOL, not a conformant mdoc reader: it does no mdoc reader
authentication (no ReaderAuth), no certificate/trust chain validation of the
returned DeviceResponse, and assumes device engagement happened via QR (i.e.
Handover = null in the SessionTranscript) - see --nfc if engagement instead
happened via NFC static handover.

Requires:
    pip install bleak cbor2 cryptography

Usage:
    1. Open the SIROS sample app and tap the contactless icon in the header
       (left of the QR icon) to open "Proximity Engagement". It shows a QR
       code and starts advertising over BLE.
    2. Get the `mdoc:...` URI encoded in that QR code onto this machine, e.g.
       by scanning it with a phone's camera app and AirDropping/messaging
       the text to yourself, or decoding a screenshot with zbarimg:
           zbarimg screenshot.png
    3. Run this script on a machine with a real Bluetooth adapter, within
       BLE range of the phone:
           python3 ble_reader_test.py 'mdoc:AAAA...' --doc-type org.iso.18013.5.1.mDL \\
               --namespace org.iso.18013.5.1 --claims given_name,family_name

The script prints the decrypted DeviceResponse's docType and disclosed
namespaces/elements on success.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import struct
import sys
import uuid

import cbor2
from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Fixed characteristic UUIDs, ISO/IEC 18013-5 Table 5 ("mdoc service").
STATE_UUID = "00000001-a123-48ce-896b-4c76973373e6"
CLIENT2SERVER_UUID = "00000002-a123-48ce-896b-4c76973373e6"
SERVER2CLIENT_UUID = "00000003-a123-48ce-896b-4c76973373e6"

STATE_START = b"\x01"
STATE_END = b"\x02"

READER_IDENTIFIER = bytes(8)
MDOC_IDENTIFIER = bytes(7) + b"\x01"


def parse_device_engagement(mdoc_uri: str) -> tuple[bytes, ec.EllipticCurvePublicKey, uuid.UUID]:
    """Decode a `mdoc:` URI into (raw DeviceEngagement CBOR bytes, EDeviceKey.Pub,
    peripheralServerModeUuid) - mirrors DeviceEngagement.kt's own structure exactly."""
    if not mdoc_uri.startswith("mdoc:"):
        raise ValueError("expected a URI starting with 'mdoc:'")
    encoded = mdoc_uri.removeprefix("mdoc:")
    padded = encoded + "=" * (-len(encoded) % 4)
    de_bytes = base64.urlsafe_b64decode(padded)
    de = cbor2.loads(de_bytes)

    security = de[1]  # [cipherSuite, EDeviceKeyBytes]
    e_device_key_tag = security[1]
    cose_key = cbor2.loads(e_device_key_tag.value)
    x = cose_key[-2]
    y = cose_key[-3]
    e_device_pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    ).public_key()

    retrieval_methods = de[2]  # [[type, version, BleOptions], ...]
    ble_options = next(m[2] for m in retrieval_methods if m[0] == 2)
    peripheral_uuid_bytes = ble_options.get(10)
    if peripheral_uuid_bytes is None:
        raise ValueError("engagement does not offer peripheral server mode (no key 10 in BleOptions)")
    peripheral_uuid = uuid.UUID(bytes=peripheral_uuid_bytes)

    return de_bytes, e_device_pub, peripheral_uuid


def cose_key_tag(pub: ec.EllipticCurvePublicKey) -> cbor2.CBORTag:
    """Tag-24-wrapped COSE_Key (as a CBORTag *object*, not pre-encoded bytes) for
    an uncompressed P-256 public point - matches DeviceEngagement.kt's coseKey().
    Kept as an object (not bytes) so it can be embedded directly wherever it's
    needed (SessionEstablishment's "eReaderKey" field, the SessionTranscript
    array) without ever double-wrapping it in another tag 24."""
    numbers = pub.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    cose_key = {1: 2, -1: 1, -2: x, -3: y}  # kty=EC2, crv=P-256
    return cbor2.CBORTag(24, cbor2.dumps(cose_key))


def build_session_transcript(device_engagement_bytes: bytes, e_reader_key_tag: cbor2.CBORTag, nfc_handover_select: bytes | None) -> bytes:
    """Bare (untagged) SessionTranscript array bytes - matches ProximitySessionTranscript.build()'s return shape."""
    handover = None if nfc_handover_select is None else [nfc_handover_select, None]
    transcript = [
        cbor2.CBORTag(24, device_engagement_bytes),
        e_reader_key_tag,
        handover,
    ]
    return cbor2.dumps(transcript)


def derive_session_keys(zab: bytes, session_transcript: bytes) -> tuple[bytes, bytes]:
    """ECKA-DH -> HKDF-SHA256(SKReader/SKDevice), salt = SHA-256(tag-24-wrapped SessionTranscriptBytes) - §12.2.5."""
    session_transcript_bytes = cbor2.dumps(cbor2.CBORTag(24, session_transcript))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(session_transcript_bytes)
    salt = digest.finalize()

    sk_reader = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SKReader").derive(zab)
    sk_device = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SKDevice").derive(zab)
    return sk_reader, sk_device


def gcm_iv(identifier: bytes, counter: int) -> bytes:
    return identifier + struct.pack(">I", counter)


def chunk_message(message: bytes, max_chunk_size: int) -> list[bytes]:
    """§11.1.3.4 BLE chunking: each part prefixed 0x01 (more) or 0x00 (last).

    max_chunk_size is the TOTAL wire size (prefix + payload) allowed per
    part, so each payload slice is at most max_chunk_size - 1 bytes -
    matches BleMessageChunker.chunk's corrected contract (an earlier
    version of both implementations added the prefix ON TOP of
    max_chunk_size payload bytes, silently producing chunks one byte over
    the limit)."""
    if max_chunk_size <= 1:
        raise ValueError(f"max_chunk_size must allow at least 1 payload byte alongside the prefix, was {max_chunk_size}")
    payload_size = max_chunk_size - 1
    if not message:
        return [b"\x00"]
    chunks = []
    offset = 0
    while offset < len(message):
        end = min(offset + payload_size, len(message))
        is_last = end == len(message)
        chunks.append((b"\x00" if is_last else b"\x01") + message[offset:end])
        offset = end
    return chunks


class Reassembler:
    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> bytes | None:
        is_last = chunk[0] == 0x00
        self._buffer.extend(chunk[1:])
        if not is_last:
            return None
        result = bytes(self._buffer)
        self._buffer.clear()
        return result


async def run(args: argparse.Namespace) -> None:
    device_engagement_bytes, e_device_pub, peripheral_uuid = parse_device_engagement(args.mdoc_uri)
    print(f"Parsed engagement: peripheral service UUID = {peripheral_uuid}")

    nfc_handover_select = bytes.fromhex(args.nfc_handover_hex) if args.nfc_handover_hex else None

    e_reader_priv = ec.generate_private_key(ec.SECP256R1())
    e_reader_pub = e_reader_priv.public_key()
    e_reader_key_tag = cose_key_tag(e_reader_pub)

    session_transcript = build_session_transcript(device_engagement_bytes, e_reader_key_tag, nfc_handover_select)
    zab = e_reader_priv.exchange(ec.ECDH(), e_device_pub)
    sk_reader, sk_device = derive_session_keys(zab, session_transcript)

    print(f"Scanning for service {peripheral_uuid} ...")
    device = await BleakScanner.find_device_by_filter(
        lambda d, adv: str(peripheral_uuid).lower() in [str(u).lower() for u in (adv.service_uuids or [])],
        timeout=args.scan_timeout,
    )
    if device is None:
        print("Device not found - is the sample app's Proximity Engagement screen open?", file=sys.stderr)
        sys.exit(1)
    print(f"Found {device.address}, connecting...")

    reassembler = Reassembler()
    response_future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def on_server2client(_char, data: bytearray) -> None:
        message = reassembler.feed(bytes(data))
        if message is not None and not response_future.done():
            response_future.set_result(message)

    async with BleakClient(device) as client:
        print(f"Connected. Negotiated MTU: {client.mtu_size}")
        await client.start_notify(SERVER2CLIENT_UUID, on_server2client)
        await client.write_gatt_char(STATE_UUID, STATE_START, response=False)

        item_map = {claim: True for claim in args.claims.split(",")}
        items_request = {"docType": args.doc_type, "nameSpaces": {args.namespace: item_map}}
        doc_request = {"itemsRequest": cbor2.CBORTag(24, cbor2.dumps(items_request))}
        device_request = cbor2.dumps({"version": "1.0", "docRequests": [doc_request]})

        aad = b""
        ciphertext = AESGCM(sk_reader).encrypt(gcm_iv(READER_IDENTIFIER, 1), device_request, aad)
        session_establishment = cbor2.dumps({"eReaderKey": e_reader_key_tag, "data": ciphertext})

        # §11.1.3.4: chunk size must respect both MTU-3 and the Bluetooth
        # Core Specification's absolute 512-byte max attribute value length.
        max_chunk_size = min(max(client.mtu_size - 3, 20), 512)
        print(f"Sending SessionEstablishment ({len(session_establishment)} bytes, {max_chunk_size}-byte chunks)...")
        for chunk in chunk_message(session_establishment, max_chunk_size):
            await client.write_gatt_char(CLIENT2SERVER_UUID, chunk, response=False)

        print("Waiting for SessionData response...")
        session_data_bytes = await asyncio.wait_for(response_future, timeout=args.response_timeout)

        await client.write_gatt_char(STATE_UUID, STATE_END, response=False)

    session_data = cbor2.loads(session_data_bytes)
    if "status" in session_data and "data" not in session_data:
        print(f"mdoc returned status {session_data['status']} with no data (see Table 15)", file=sys.stderr)
        sys.exit(1)

    plaintext = AESGCM(sk_device).decrypt(gcm_iv(MDOC_IDENTIFIER, 1), session_data["data"], b"")
    device_response = cbor2.loads(plaintext)

    print("\n--- DeviceResponse ---")
    print(f"version: {device_response.get('version')}")
    for doc in device_response.get("documents", []):
        print(f"docType: {doc['docType']}")
        issuer_signed = doc.get("issuerSigned", {})
        name_spaces = issuer_signed.get("nameSpaces", {})
        for ns, items in name_spaces.items():
            print(f"  namespace {ns}:")
            for tagged_item in items:
                item = cbor2.loads(tagged_item.value)
                print(f"    {item['elementIdentifier']} = {item['elementValue']!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mdoc_uri", help="The 'mdoc:...' URI encoded in the engagement QR code")
    parser.add_argument("--doc-type", default="org.iso.18013.5.1.mDL", help="Requested docType")
    parser.add_argument("--namespace", default="org.iso.18013.5.1", help="Namespace for the requested claims")
    parser.add_argument("--claims", default="given_name,family_name", help="Comma-separated element identifiers to request")
    parser.add_argument(
        "--nfc-handover-hex",
        default=None,
        help="Hex-encoded Handover Select NDEF message, if engagement happened via NFC static handover instead of QR",
    )
    parser.add_argument("--scan-timeout", type=float, default=10.0)
    parser.add_argument("--response-timeout", type=float, default=15.0)
    args = parser.parse_args()

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
