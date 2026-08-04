// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample.proximity

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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.siros.sdk.credentials.CredentialUtils
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.keystore.mdoc.BleMessageChunker
import org.siros.sdk.keystore.mdoc.DeviceEngagement
import org.siros.sdk.keystore.mdoc.DeviceRequestParser
import org.siros.sdk.keystore.mdoc.ProximitySessionCrypto
import org.siros.sdk.keystore.mdoc.ProximitySessionMessages
import org.siros.sdk.keystore.mdoc.ProximitySessionTranscript
import timber.log.Timber
import java.util.UUID

/**
 * ISO 18013-5 §8.3.3.1.1/§11.1.3 "mdoc peripheral server mode": the mdoc
 * acts as the BLE GATT server, advertising [DeviceEngagement.Engagement.peripheralServerModeUuid]
 * and exposing the "mdoc service" characteristics (Table 5: `State`,
 * `Client2Server`, `Server2Client`). The reader connects as GATT client,
 * writes the `SessionEstablishment` message (chunked) to `Client2Server`,
 * and this class decrypts the mdoc request, matches a stored credential by
 * `docType`, signs a `DeviceResponse` over the ISO 18013-5 proximity
 * session transcript, and notifies the encrypted `SessionData` response back
 * via `Server2Client`.
 *
 * Real hardware-verified end to end (see the proximity plan's Phase 3.1-3.3
 * completion notes and `project_kotlin_sdk_ble_proximity_verified` memory) -
 * a real Android device running this class completed a full presentation
 * against `tools/ble_reader_test.py` on a Linux host's Bluetooth adapter.
 *
 * Every matching credential is offered to the user via [requestConsent]
 * before signing - no auto-selection.
 */
class BlePeripheralServer(
    private val context: Context,
    private val engagement: DeviceEngagement.Engagement,
    /** Mirrors `SirosWallet.getCredentials` - injected rather than taking a `SirosWallet` directly, keeping this BLE/GATT glue class independent of the wallet facade. */
    private val getCredentials: suspend () -> List<StoredCredential>,
    /** Mirrors `SirosWallet.signMdocPresentationForProximity`. */
    private val signPresentation: suspend (credentialId: Long, disclosedClaims: List<String>?, sessionTranscriptBytes: ByteArray) -> ByteArray,
    /** See [RequestProximityConsent]'s doc comment. */
    private val requestConsent: RequestProximityConsent,
    /** Reports a canonical step token (see `FlowProgress.kt`'s `PROXIMITY_STEPS`) for driving the same progress-bar UI the issuance/presentation flows use. */
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
    }

    private val scope = CoroutineScope(Dispatchers.IO)
    private val reassembler = BleMessageChunker.Reassembler()
    private var gattServer: BluetoothGattServer? = null
    private var connectedDevice: BluetoothDevice? = null
    private var negotiatedMtu = DEFAULT_MTU
    private var deviceCipher: ProximitySessionCrypto.SessionCipher? = null
    private var server2ClientCharacteristic: BluetoothGattCharacteristic? = null

    @SuppressLint("MissingPermission")
    fun start() {
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val adapter = bluetoothManager.adapter
        if (adapter == null || !adapter.isEnabled) {
            Timber.w("BlePeripheralServer: Bluetooth is not available/enabled")
            onComplete(false)
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
            onComplete(false)
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
            onComplete(false)
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
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, android.bluetooth.BluetoothGatt.GATT_SUCCESS, offset, null)
            }
        }
    }

    private fun handleStateWrite(value: ByteArray) {
        if (value.isEmpty()) return
        when (value[0]) {
            STATE_END -> {
                stop()
                onComplete(deviceCipher != null)
            }
        }
    }

    private fun handleDataWrite(chunk: ByteArray) {
        val message = reassembler.feed(chunk) ?: return
        scope.launch {
            try {
                if (deviceCipher == null) {
                    handleSessionEstablishment(message)
                } else {
                    Timber.w("BlePeripheralServer: additional SessionData messages after the first request are not yet handled")
                }
            } catch (e: Exception) {
                Timber.e(e, "Proximity presentation failed")
                onComplete(false)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun handleSessionEstablishment(message: ByteArray) {
        onStep("parsing_request")
        val established = ProximitySessionMessages.parseSessionEstablishment(message)
        val eReaderPublicKey = ProximitySessionCrypto.parseEReaderKeyPublic(established.eReaderKeyBytes)
        val sessionTranscript = ProximitySessionTranscript.build(
            deviceEngagementBytes = engagement.deviceEngagementBytes,
            eReaderKeyBytes = established.eReaderKeyBytes,
            handoverSelectMessageBytes = null,
        )
        val keys = ProximitySessionCrypto.deriveSessionKeys(engagement.privateKey, eReaderPublicKey, sessionTranscript)
        val requestBytes = ProximitySessionCrypto.readerCipher(keys.skReader).decrypt(established.encryptedData)
        deviceCipher = ProximitySessionCrypto.deviceCipher(keys.skDevice)

        val docRequests = DeviceRequestParser.parse(requestBytes)
        val docRequest = docRequests.firstOrNull()
        if (docRequest == null) {
            Timber.w("BlePeripheralServer: request contained no documents")
            onComplete(false)
            return
        }

        onStep("match_credentials")
        val matches = getCredentials().filter { cred ->
            cred.format == "mso_mdoc" && CredentialUtils.parseMdocDocument(cred)?.docType == docRequest.docType
        }
        if (matches.isEmpty()) {
            Timber.w("BlePeripheralServer: no stored credential matches requested docType '${docRequest.docType}'")
            onComplete(false)
            return
        }
        val families = groupIntoFamilies(matches)
        onStep("awaiting_consent")
        val consent = requestConsent(docRequest.docType, docRequest.disclosedClaims(), families)
        val family = when (consent) {
            is ProximityConsentResult.Approved -> consent.family
            ProximityConsentResult.Denied -> {
                onComplete(false)
                return
            }
        }
        // Pick a random instance from the batch rather than always the same
        // one - each instance is bound to its own device key specifically so
        // repeated presentations of "the same" credential can't be
        // correlated by a verifier via a reused public key. Always picking
        // instance 0 would quietly throw that unlinkability away.
        val credential = family.instances.random()

        onStep("submitting_response")
        val response = signPresentation(credential.id, docRequest.disclosedClaims(), sessionTranscript)
        val encrypted = deviceCipher!!.encrypt(response)
        val sessionData = ProximitySessionMessages.buildSessionData(encryptedData = encrypted)
        sendNotification(sessionData)
        onComplete(true)
    }

    @SuppressLint("MissingPermission")
    private fun sendNotification(message: ByteArray) {
        val characteristic = server2ClientCharacteristic ?: return
        val device = connectedDevice ?: return
        val server = gattServer ?: return
        // §11.1.3.4: chunk size must respect BOTH limits - MTU-3 AND the
        // Bluetooth Core Specification's absolute 512-byte max attribute
        // value length. A negotiated MTU above 515 (observed: BlueZ
        // negotiating 517 without this being visible at the client's own
        // API layer) makes MTU-3 alone exceed 512, which
        // notifyCharacteristicChanged rejects outright ("Notification
        // should not be longer than max length of an attribute value") -
        // found via a real BLE central connecting to this server.
        val maxChunkSize = minOf(negotiatedMtu - 3, 512)
        for (chunk in BleMessageChunker.chunk(message, maxChunkSize)) {
            characteristic.value = chunk
            server.notifyCharacteristicChanged(device, characteristic, false)
        }
    }
}
