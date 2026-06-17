package org.sirosfoundation.sdk.keystore

/**
 * Interface for providing a CTAP2 transport channel to external authenticators.
 *
 * Implementations bridge platform-specific BLE or NFC communication
 * to the WSCD's CTAP2 transport requirements. The wallet application
 * provides a concrete implementation that handles device discovery,
 * pairing, and CBOR message framing over the chosen transport.
 *
 * Usage with WSCD:
 * ```kotlin
 * class BleTransport(private val context: Context) : Ctap2TransportProvider {
 *     override suspend fun send(command: ByteArray): ByteArray {
 *         // BLE GATT write/notify cycle
 *     }
 *     override suspend fun isAvailable(): Boolean {
 *         return context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)
 *     }
 * }
 * ```
 */
interface Ctap2TransportProvider {
    /**
     * Send a CTAP2 command (CBOR-encoded) and return the response.
     *
     * The implementation handles framing (e.g. BLE fragmentation)
     * and waits for the authenticator response.
     *
     * @param command CBOR-encoded CTAP2 command bytes.
     * @return CBOR-encoded CTAP2 response bytes.
     */
    suspend fun send(command: ByteArray): ByteArray

    /** Whether the transport is currently available and connected. */
    suspend fun isAvailable(): Boolean

    /**
     * Attempt to discover and connect to an authenticator.
     *
     * For BLE: starts scanning for FIDO2 service UUID.
     * For NFC: initiates tag polling session.
     */
    suspend fun connect()

    /** Disconnect from the current authenticator. */
    suspend fun disconnect()
}

/** Errors specific to CTAP2 transport operations. */
sealed class Ctap2TransportException(message: String) : Exception(message) {
    class NotAvailable : Ctap2TransportException("CTAP2 transport not available")
    class ConnectionFailed(detail: String) : Ctap2TransportException("Connection failed: $detail")
    class Timeout : Ctap2TransportException("CTAP2 transport timeout")
    class DeviceDisconnected : Ctap2TransportException("Authenticator disconnected")
    class InvalidResponse(detail: String) : Ctap2TransportException("Invalid CTAP2 response: $detail")
}
