// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

/**
 * A connected ISO 18013-5 message transport.
 *
 * Implementations own radio framing, chunking, reassembly, backpressure, and
 * timeouts. Messages crossing this interface are always complete CBOR
 * SessionEstablishment or SessionData values, never BLE fragments or APDUs.
 * A transport belongs to exactly one elected reader session.
 */
interface MdocMessageTransport {
    suspend fun send(message: ByteArray)

    suspend fun receive(): ByteArray

    suspend fun close()
}
