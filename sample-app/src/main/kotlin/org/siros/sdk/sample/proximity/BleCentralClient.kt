// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.proximity

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.mdoc.BleMessageChunker
import org.siros.sdk.keystore.mdoc.DeviceEngagement
import org.siros.sdk.keystore.mdoc.MdocProximitySession
import org.siros.sdk.keystore.mdoc.ProximitySessionCrypto
import org.siros.sdk.keystore.mdoc.RequestProximityConsent
import timber.log.Timber
import java.util.UUID

/**
 * ISO 18013-5 §8.3.3.1.1/§11.1.3 "mdoc central client mode": the mdoc acts
 * as the BLE GATT CLIENT, scanning for and connecting to a reader that
 * advertises [DeviceEngagement.Engagement.centralClientModeUuid] as its own
 * GATT service UUID (per §11.1.3.1 - the reader is the peripheral/advertiser
 * in this mode, the mirror image of [BlePeripheralServer]). Discovers the
 * reader's "mdoc reader service" (Table 6: `State`, `Client2Server`,
 * `Server2Client`, `Ident`), verifies the reader's identity via the `Ident`
 * characteristic, then runs the same session-establishment/session-data
 * protocol as [BlePeripheralServer] (via the shared [MdocProximitySession])
 * with the GATT roles reversed: this mdoc WRITES to `Client2Server` and
 * receives via `Server2Client` notify (§11.1.3.4: "Client2Server" always
 * carries GATT-client-to-server traffic and "Server2Client" always carries
 * the reverse, regardless of which side - mdoc or reader - holds the GATT
 * client/server role for a given transaction).
 *
 * UNVERIFIED ON REAL HARDWARE beyond compiling - there is no second BLE
 * GATT-server test tool available yet (siros-verifier-cli's `siros-verify read`,
 * https://github.com/sirosfoundation/siros-verifier-cli, uses `bleak`, which is
 * central/client-only on every platform, the same role this class plays - it
 * cannot stand in as a peripheral to test against).
 * Needs testing against either a real ISO 18013-5 reader or a purpose-built
 * BlueZ-peripheral test script before relying on it.
 */
class BleCentralClient(
    private val context: Context,
    private val engagement: DeviceEngagement.Engagement,
    /** Mirrors `SirosWallet.getCredentials` - see [BlePeripheralServer]'s matching parameter doc comment. */
    getCredentials: suspend () -> List<StoredCredential>,
    /** Mirrors `SirosWallet.signMdocPresentationForProximity`. */
    signPresentation: suspend (credentialId: Long, disclosedClaims: List<String>?, sessionTranscriptBytes: ByteArray) -> ByteArray,
    /** See [RequestProximityConsent]'s doc comment. */
    requestConsent: RequestProximityConsent,
    /** See [BlePeripheralServer]'s matching parameter doc comment. */
    filterEligible: (List<StoredCredential>) -> List<StoredCredential>,
    /** Reports a canonical step token (see `FlowStepCatalog.proximitySteps`) for driving the same progress-bar UI the issuance/presentation flows use. */
    private val onStep: (String) -> Unit,
    private val onComplete: (success: Boolean) -> Unit,
) {
    companion object {
        // Table 6 - mdoc reader service characteristics (present when the reader is the GATT server).
        private val STATE_UUID = UUID.fromString("00000005-A123-48CE-896B-4C76973373E6")
        private val CLIENT2SERVER_UUID = UUID.fromString("00000006-A123-48CE-896B-4C76973373E6")
        private val SERVER2CLIENT_UUID = UUID.fromString("00000007-A123-48CE-896B-4C76973373E6")
        private val IDENT_UUID = UUID.fromString("00000008-A123-48CE-896B-4C76973373E6")
        private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        private const val STATE_START: Byte = 0x01
        private const val STATE_END: Byte = 0x02

        private const val DEFAULT_MTU = 23
        private const val REQUESTED_MTU = 517
    }

    private val scope = CoroutineScope(Dispatchers.IO)
    private val reassembler = BleMessageChunker.Reassembler()
    private val session = MdocProximitySession(
        engagement = engagement,
        getHandoverSelectBytes = { ActiveEngagement.handoverSelectBytes },
        getCredentials = getCredentials,
        signPresentation = signPresentation,
        requestConsent = requestConsent,
        filterEligible = filterEligible,
        onStep = onStep,
        logTag = "BleCentralClient",
    )
    private var negotiatedMtu = DEFAULT_MTU
    private var gatt: BluetoothGatt? = null
    private var client2ServerCharacteristic: BluetoothGattCharacteristic? = null
    private var stateCharacteristic: BluetoothGattCharacteristic? = null
    private var scanning = false

    @SuppressLint("MissingPermission")
    fun start() {
        val serviceUuid = engagement.centralClientModeUuid
            ?: throw IllegalStateException("engagement does not offer central client mode")
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val adapter = bluetoothManager.adapter
        if (adapter == null || !adapter.isEnabled) {
            Timber.w("BleCentralClient: Bluetooth is not available/enabled")
            onComplete(false)
            return
        }
        val scanner = adapter.bluetoothLeScanner
        if (scanner == null) {
            Timber.w("BleCentralClient: this device cannot scan for BLE (no BluetoothLeScanner)")
            onComplete(false)
            return
        }

        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(serviceUuid)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanning = true
        onStep("waiting_for_reader")
        scanner.startScan(listOf(filter), settings, scanCallback)
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        if (scanning) {
            val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            bluetoothManager?.adapter?.bluetoothLeScanner?.stopScan(scanCallback)
            scanning = false
        }
        gatt?.disconnect()
        gatt?.close()
        gatt = null
    }

    private val scanCallback = object : ScanCallback() {
        @SuppressLint("MissingPermission")
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            bluetoothManager.adapter.bluetoothLeScanner?.stopScan(this)
            scanning = false
            gatt = result.device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
        }

        override fun onScanFailed(errorCode: Int) {
            Timber.w("BleCentralClient: BLE scan failed to start (error $errorCode)")
            onComplete(false)
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothGatt.STATE_CONNECTED -> {
                    onStep("reader_connected")
                    gatt.requestMtu(REQUESTED_MTU)
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            negotiatedMtu = mtu
            gatt.discoverServices()
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val serviceUuid = engagement.centralClientModeUuid!!
            val service = gatt.getService(serviceUuid)
            if (service == null) {
                Timber.w("BleCentralClient: reader has no service matching $serviceUuid")
                onComplete(false)
                gatt.disconnect()
                return
            }
            client2ServerCharacteristic = service.getCharacteristic(CLIENT2SERVER_UUID)
            stateCharacteristic = service.getCharacteristic(STATE_UUID)
            val identChar = service.getCharacteristic(IDENT_UUID)
            if (client2ServerCharacteristic == null || identChar == null ||
                stateCharacteristic == null || service.getCharacteristic(SERVER2CLIENT_UUID) == null
            ) {
                Timber.w("BleCentralClient: reader's mdoc reader service is missing required characteristics")
                onComplete(false)
                gatt.disconnect()
                return
            }
            gatt.readCharacteristic(identChar)
        }

        // The 4-arg onCharacteristicRead(gatt, characteristic, value, status)
        // overload only exists (and is only ever invoked) on API 33+; this
        // repo's minSdk is 28, so overriding ONLY that one would silently
        // never fire on most real devices. Override the deprecated 3-arg
        // form (reading characteristic.value) for broad compatibility.
        @Suppress("DEPRECATION")
        @SuppressLint("MissingPermission")
        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            if (characteristic.uuid != IDENT_UUID) return
            val value = characteristic.value ?: return
            val expected = ProximitySessionCrypto.computeIdent(engagement.eDeviceKeyBytes)
            if (!value.contentEquals(expected)) {
                Timber.w("BleCentralClient: Ident characteristic mismatch - not the reader this engagement was intended for, terminating")
                onComplete(false)
                gatt.disconnect()
                return
            }
            enableNotifications(gatt, characteristic.service.getCharacteristic(STATE_UUID))
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            when (descriptor.characteristic.uuid) {
                STATE_UUID -> enableNotifications(gatt, descriptor.characteristic.service.getCharacteristic(SERVER2CLIENT_UUID))
                SERVER2CLIENT_UUID -> {
                    val stateChar = descriptor.characteristic.service.getCharacteristic(STATE_UUID)
                    writeNoResponse(gatt, stateChar, byteArrayOf(STATE_START))
                }
            }
        }

        // Same API-33-vs-minSdk-28 reasoning as onCharacteristicRead above:
        // override the deprecated 2-arg form, not the newer 3-arg one.
        @Suppress("DEPRECATION")
        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            if (characteristic.uuid != SERVER2CLIENT_UUID) return
            val value = characteristic.value ?: return
            // This callback runs on the system's Binder thread, not inside
            // the scope.launch below - an uncaught exception here (e.g. the
            // reassembler's max-size guard tripping) would crash the whole
            // process instead of just this presentation attempt.
            val message = try {
                reassembler.feed(value) ?: return
            } catch (e: IllegalStateException) {
                Timber.w(e, "BleCentralClient: reassembly aborted")
                onComplete(false)
                return
            }
            scope.launch {
                try {
                    if (session.established) {
                        Timber.w("BleCentralClient: additional SessionData messages after the first request are not yet handled")
                        return@launch
                    }
                    when (val result = session.handleSessionEstablishment(message)) {
                        is MdocProximitySession.Result.Response -> {
                            if (!sendData(result.sessionData)) {
                                Timber.w("BleCentralClient: a write failed to queue - reader will not receive the full response")
                                onComplete(false)
                                return@launch
                            }
                            onComplete(true)
                        }
                        MdocProximitySession.Result.Denied -> onComplete(false)
                        is MdocProximitySession.Result.Failed -> onComplete(false)
                    }
                } catch (e: Exception) {
                    Timber.e(e, "Proximity presentation failed")
                    onComplete(false)
                }
            }
        }
    }

    @Suppress("DEPRECATION")
    @SuppressLint("MissingPermission")
    private fun enableNotifications(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic?) {
        if (characteristic == null) return
        gatt.setCharacteristicNotification(characteristic, true)
        val cccd = characteristic.getDescriptor(CCCD_UUID) ?: return
        // The 2-arg writeDescriptor(descriptor, value) overload requires API
        // 33 - this repo's minSdk is 28, so the deprecated
        // value-then-write pattern is what's actually compatible.
        cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        gatt.writeDescriptor(cccd)
    }

    /** @return false if [characteristic] is null or the write couldn't be initiated/queued. */
    @Suppress("DEPRECATION")
    @SuppressLint("MissingPermission")
    private fun writeNoResponse(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic?, value: ByteArray): Boolean {
        if (characteristic == null) return false
        // Same API-33-vs-minSdk-28 reasoning as enableNotifications above.
        characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        characteristic.value = value
        return gatt.writeCharacteristic(characteristic)
    }

    /** @return false if any chunk's write failed to queue - the reader will not have received a complete response. */
    private fun sendData(message: ByteArray): Boolean {
        val characteristic = client2ServerCharacteristic ?: return false
        val currentGatt = gatt ?: return false
        // Floor at the default MTU-3 (20 bytes): BleMessageChunker.chunk
        // requires maxChunkSize > 1, and an unexpected/invalid negotiated
        // MTU should never be allowed to produce a smaller (or negative)
        // value that would crash chunking outright.
        val maxChunkSize = minOf(negotiatedMtu - 3, 512).coerceAtLeast(DEFAULT_MTU - 3)
        for (chunk in BleMessageChunker.chunk(message, maxChunkSize)) {
            if (!writeNoResponse(currentGatt, characteristic, chunk)) return false
        }
        // §11.1.3.1: signal the end of this side's transaction once the
        // response has been fully written - without this, a reader
        // following the state machine strictly may keep waiting/hold the
        // transaction open unnecessarily.
        writeNoResponse(currentGatt, stateCharacteristic, byteArrayOf(STATE_END))
        return true
    }
}
