// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.keystore.mdoc

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.siros.sdk.credentials.StoredCredential
import timber.log.Timber
import java.util.UUID

/**
 * ISO 18013-5 §8.3.3.1.1/§11.1.3 "mdoc peripheral server mode": the mdoc
 * acts as the BLE GATT server, advertising [DeviceEngagement.Engagement.peripheralServerModeUuid]
 * and exposing the "mdoc service" characteristics (Table 5: `State`,
 * `Client2Server`, `Server2Client`). The reader connects as GATT client,
 * writes the `SessionEstablishment` message (chunked) to `Client2Server`, and
 * [MdocProximitySession] decrypts the mdoc request, matches a stored
 * credential by `docType`, signs a `DeviceResponse` over the ISO 18013-5
 * proximity session transcript, and this class notifies the encrypted
 * `SessionData` response back via `Server2Client`.
 *
 * Real hardware-verified end to end (see the proximity plan's Phase 3.1-3.3
 * completion notes and `project_kotlin_sdk_ble_proximity_verified` memory) -
 * a real Android device running this class completed a full presentation
 * against siros-verifier-cli's `siros-verify read` command
 * (https://github.com/sirosfoundation/siros-verifier-cli) on a Linux host's
 * Bluetooth adapter.
 * This class now only handles the BLE/GATT transport; the proximity
 * protocol itself lives in [MdocProximitySession] (SDK-level, shared with
 * [BleCentralClient]).
 */
class BlePeripheralServer(
    private val context: Context,
    private val engagement: DeviceEngagement.Engagement,
    /**
     * NFC static-handover bytes for the currently-active engagement, if any -
     * see [BleCentralClient]'s matching parameter doc comment.
     */
    getHandoverSelectBytes: () -> ByteArray?,
    /** Mirrors `SirosWallet.getCredentials` - injected rather than taking a `SirosWallet` directly, keeping this BLE/GATT glue class independent of the wallet facade. */
    getCredentials: suspend () -> List<StoredCredential>,
    /** Mirrors `SirosWallet.signMdocPresentationForProximity`. */
    signPresentation: suspend (credentialId: Long, disclosedClaims: List<String>?, sessionTranscriptBytes: ByteArray) -> ByteArray,
    /** See [RequestProximityConsent]'s doc comment. */
    requestConsent: RequestProximityConsent,
    /**
     * Mirrors `CredentialUtils.eligibleInstances` bound to the caller's
     * current `SirosWallet.credentialConsumptionPolicy`/`presentationHistory` -
     * excludes instances the active consumption policy considers already
     * used up, so a family the user approves can't sign with an exhausted
     * instance even if [requestConsent]'s UI failed to grey it out.
     */
    filterEligible: (List<StoredCredential>) -> List<StoredCredential>,
    /** Reports a canonical step token (see `FlowStepCatalog.proximitySteps`) for driving the same progress-bar UI the issuance/presentation flows use. */
    private val onStep: (String) -> Unit,
    private val onComplete: (success: Boolean) -> Unit,
) {
    companion object {
        private val STATE_UUID = UUID.fromString("00000001-A123-48CE-896B-4C76973373E6")
        private val CLIENT2SERVER_UUID = UUID.fromString("00000002-A123-48CE-896B-4C76973373E6")
        private val SERVER2CLIENT_UUID = UUID.fromString("00000003-A123-48CE-896B-4C76973373E6")
        private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        private const val STATE_START: Byte = 0x01
        private const val STATE_END: Byte = 0x02

        /** Default BLE ATT MTU before negotiation (23 bytes, per the Bluetooth Core Spec) - yields a 20-byte max chunk payload (MTU-3). */
        private const val DEFAULT_MTU = 23

        // Android's GATT stack only allows one in-flight notification per
        // connection - notifyCharacteristicChanged() for a LATER chunk can
        // silently fail/queue-drop if issued before onNotificationSent fires
        // for the PRIOR one. This bounds how long a single chunk's ack is
        // awaited before giving up (e.g. the reader dropped the connection
        // mid-transfer) rather than hanging forever.
        private const val NOTIFY_ACK_TIMEOUT_MS = 5000L
    }

    private val scope = CoroutineScope(Dispatchers.IO)
    private val reassembler = BleMessageChunker.Reassembler()
    private val session = MdocProximitySession(
        engagement = engagement,
        getHandoverSelectBytes = getHandoverSelectBytes,
        getCredentials = getCredentials,
        signPresentation = signPresentation,
        requestConsent = requestConsent,
        filterEligible = filterEligible,
        onStep = onStep,
        logTag = "BlePeripheralServer",
    )
    private var gattServer: BluetoothGattServer? = null
    private var connectedDevice: BluetoothDevice? = null
    private var negotiatedMtu = DEFAULT_MTU
    private var server2ClientCharacteristic: BluetoothGattCharacteristic? = null
    private var completed = false
    // Distinct from session.established: the session's cipher is created
    // right after session-key derivation, well before a response is
    // actually signed and notified back - if the reader sends STATE_END
    // early (e.g. mid-consent, or after a timeout), session.established
    // would already be true and incorrectly report success. Only set once
    // sendNotification actually runs.
    private var responseSent = false
    // Set immediately before each notifyCharacteristicChanged() call and
    // completed from onNotificationSent - see NOTIFY_ACK_TIMEOUT_MS's doc
    // comment on why notifications must be paced rather than issued
    // back-to-back.
    private var pendingNotifyAck: CompletableDeferred<Boolean>? = null

    /** Reports the presentation's outcome exactly once - a signed response being sent and the reader's STATE_END write both resolve to "complete" and would otherwise double-report. */
    private fun completeOnce(success: Boolean) {
        if (completed) return
        completed = true
        onComplete(success)
    }

    @SuppressLint("MissingPermission")
    fun start() {
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val adapter = bluetoothManager.adapter
        if (adapter == null || !adapter.isEnabled) {
            Timber.w("BlePeripheralServer: Bluetooth is not available/enabled")
            completeOnce(false)
            return
        }
        // §11.1.3.1: "The Peripheral device shall broadcast the service with
        // the UUID as received or sent during device engagement" - the GATT
        // service itself must be identified by this per-transaction UUID (not
        // a fixed constant), since that's what the reader scans for and then
        // does GATT service discovery against after connecting.
        val serviceUuid = engagement.peripheralServerModeUuid
            ?: throw IllegalStateException("engagement does not offer peripheral server mode")

        val server = bluetoothManager.openGattServer(context, gattServerCallback)
        if (server == null) {
            Timber.w("BlePeripheralServer: openGattServer returned null (Bluetooth stack unavailable)")
            completeOnce(false)
            return
        }
        gattServer = server

        val state = BluetoothGattCharacteristic(
            STATE_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        ).apply { addDescriptor(cccd()) }
        val client2Server = BluetoothGattCharacteristic(
            CLIENT2SERVER_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val server2Client = BluetoothGattCharacteristic(
            SERVER2CLIENT_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            0,
        ).apply { addDescriptor(cccd()) }
        server2ClientCharacteristic = server2Client

        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY).apply {
            addCharacteristic(state)
            addCharacteristic(client2Server)
            addCharacteristic(server2Client)
        }
        server.addService(service)

        val advertiser = adapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            Timber.w("BlePeripheralServer: this device cannot advertise BLE (no BluetoothLeAdvertiser)")
            stop()
            completeOnce(false)
            return
        }
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        val advertiseData = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(serviceUuid))
            .setIncludeDeviceName(false)
            .build()
        advertiser.startAdvertising(settings, advertiseData, advertiseCallback)
        onStep("waiting_for_reader")
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        bluetoothManager?.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
        connectedDevice?.let { gattServer?.cancelConnection(it) }
        gattServer?.close()
        gattServer = null
    }

    private fun cccd() = BluetoothGattDescriptor(
        CCCD_UUID,
        BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
    )

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            Timber.w("BlePeripheralServer: BLE advertise failed to start (error $errorCode)")
            stop()
            completeOnce(false)
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothGatt.STATE_CONNECTED) {
                connectedDevice = device
                onStep("reader_connected")
            } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                if (device == connectedDevice) connectedDevice = null
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            negotiatedMtu = mtu
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, android.bluetooth.BluetoothGatt.GATT_SUCCESS, offset, null)
            }
            when (characteristic.uuid) {
                STATE_UUID -> handleStateWrite(value)
                CLIENT2SERVER_UUID -> handleDataWrite(value)
            }
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            // Some GATT clients read the CCCD back afterwards to confirm
            // notifications were actually enabled - store the value rather
            // than just acking the write.
            @Suppress("DEPRECATION")
            descriptor.value = value
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, android.bluetooth.BluetoothGatt.GATT_SUCCESS, offset, null)
            }
        }

        // Completes the notify paced by sendNotification below - see
        // NOTIFY_ACK_TIMEOUT_MS's doc comment for why this pacing exists.
        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            pendingNotifyAck?.complete(status == android.bluetooth.BluetoothGatt.GATT_SUCCESS)
        }
    }

    private fun handleStateWrite(value: ByteArray) {
        if (value.isEmpty()) return
        when (value[0]) {
            STATE_END -> {
                stop()
                completeOnce(responseSent)
            }
        }
    }

    private fun handleDataWrite(chunk: ByteArray) {
        // This is invoked directly from the system's GattServerCallback, not
        // inside the scope.launch below - an uncaught exception here (e.g.
        // the reassembler's max-size guard tripping) would crash the whole
        // process instead of just this presentation attempt.
        val message = try {
            reassembler.feed(chunk) ?: return
        } catch (e: IllegalStateException) {
            Timber.w(e, "BlePeripheralServer: reassembly aborted")
            completeOnce(false)
            return
        }
        scope.launch {
            try {
                if (session.established) {
                    Timber.w("BlePeripheralServer: additional SessionData messages after the first request are not yet handled")
                    return@launch
                }
                when (val result = session.handleSessionEstablishment(message)) {
                    is MdocProximitySession.Result.Response -> {
                        if (!sendNotification(result.sessionData)) {
                            Timber.w("BlePeripheralServer: a notify failed to queue - reader will not receive the full response")
                            completeOnce(false)
                            return@launch
                        }
                        responseSent = true
                        completeOnce(true)
                    }
                    MdocProximitySession.Result.Denied -> completeOnce(false)
                    is MdocProximitySession.Result.Failed -> completeOnce(false)
                }
            } catch (e: Exception) {
                Timber.e(e, "Proximity presentation failed")
                completeOnce(false)
            }
        }
    }

    /**
     * @return false if any chunk's notify failed to queue/ack - the reader
     *   will not have received a complete response.
     */
    @SuppressLint("MissingPermission")
    private suspend fun sendNotification(message: ByteArray): Boolean {
        val characteristic = server2ClientCharacteristic ?: return false
        val device = connectedDevice ?: return false
        val server = gattServer ?: return false
        // §11.1.3.4: chunk size must respect BOTH limits - MTU-3 AND the
        // Bluetooth Core Specification's absolute 512-byte max attribute
        // value length. A negotiated MTU above 515 (observed: BlueZ
        // negotiating 517 without this being visible at the client's own
        // API layer) makes MTU-3 alone exceed 512, which
        // notifyCharacteristicChanged rejects outright ("Notification
        // should not be longer than max length of an attribute value") -
        // found via a real BLE central connecting to this server.
        // Also floor at the default MTU-3 (20 bytes): BleMessageChunker.chunk
        // requires maxChunkSize > 1, and an unexpected/invalid negotiated
        // MTU should never be allowed to produce a smaller (or negative)
        // value that would crash chunking outright.
        val maxChunkSize = minOf(negotiatedMtu - 3, 512).coerceAtLeast(DEFAULT_MTU - 3)
        for (chunk in BleMessageChunker.chunk(message, maxChunkSize)) {
            characteristic.value = chunk
            val ack = CompletableDeferred<Boolean>()
            pendingNotifyAck = ack
            if (!server.notifyCharacteristicChanged(device, characteristic, false)) {
                pendingNotifyAck = null
                return false
            }
            val result = withTimeoutOrNull(NOTIFY_ACK_TIMEOUT_MS) { ack.await() }
            pendingNotifyAck = null
            if (result != true) return false
        }
        return true
    }
}
