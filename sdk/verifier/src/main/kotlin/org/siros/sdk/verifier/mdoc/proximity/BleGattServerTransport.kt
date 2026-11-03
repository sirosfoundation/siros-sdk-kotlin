// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

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
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Reader as GATT server for mdoc central-client mode. The mdoc reads Ident and
 * writes STATE_START before this transport is eligible for election.
 */
@SuppressLint("MissingPermission")
@Suppress("DEPRECATION")
internal class BleGattServerTransport(
    private val context: Context,
    private val serviceUuid: UUID,
    eDeviceKeyBytes: ByteArray,
    onReady: (MdocBleCandidate) -> Unit,
    onFailure: (MdocBleCandidate, Throwable) -> Unit,
) : AbstractMdocBleTransport("mdoc central-client mode", onReady, onFailure) {
    private val ident = MdocBleProtocol.computeIdent(eDeviceKeyBytes)
    private val handshake = MdocBleServerHandshake()
    private val advertising = AtomicBoolean(false)

    private var advertiser: BluetoothLeAdvertiser? = null
    private var gattServer: BluetoothGattServer? = null
    private var connectedDevice: BluetoothDevice? = null
    private var server2ClientCharacteristic: BluetoothGattCharacteristic? = null

    @Volatile
    private var negotiatedMtu = MdocBleProtocol.DEFAULT_MTU

    @Volatile
    private var pendingNotifyAck: CompletableDeferred<Boolean>? = null

    override fun startRadio() {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            ?: throw MdocBleTransportException("BluetoothManager is unavailable")
        val adapter = manager.adapter
        if (adapter == null || !adapter.isEnabled) {
            throw MdocBleTransportException("Bluetooth is unavailable or disabled")
        }
        advertiser = adapter.bluetoothLeAdvertiser
            ?: throw MdocBleTransportException("This device has no BLE advertiser")
        val server = manager.openGattServer(context, gattServerCallback)
            ?: throw MdocBleTransportException("openGattServer returned null")
        gattServer = server

        val state = BluetoothGattCharacteristic(
            MdocBleProtocol.READER_STATE_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        ).apply { addDescriptor(cccd()) }
        val client2Server = BluetoothGattCharacteristic(
            MdocBleProtocol.READER_CLIENT2SERVER_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val server2Client = BluetoothGattCharacteristic(
            MdocBleProtocol.READER_SERVER2CLIENT_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            0,
        ).apply { addDescriptor(cccd()) }
        val identCharacteristic = BluetoothGattCharacteristic(
            MdocBleProtocol.READER_IDENT_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        ).apply { value = ident }
        server2ClientCharacteristic = server2Client

        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY).apply {
            addCharacteristic(state)
            addCharacteristic(client2Server)
            addCharacteristic(server2Client)
            addCharacteristic(identCharacteristic)
        }
        if (!server.addService(service)) {
            throw MdocBleTransportException("Could not add the mdoc reader GATT service")
        }
    }

    override fun closeRadio() {
        stopAdvertising()
        pendingNotifyAck?.complete(false)
        pendingNotifyAck = null
        connectedDevice?.let { device -> runCatching { gattServer?.cancelConnection(device) } }
        connectedDevice = null
        runCatching { gattServer?.close() }
        gattServer = null
    }

    override fun currentMaxChunkSize(): Int = MdocBleProtocol.maxChunkSize(negotiatedMtu)

    override suspend fun sendChunk(chunk: ByteArray) {
        if (!handshake.ready) throw MdocBleTransportException("Server2Client notifications are not enabled")
        val server = gattServer ?: throw MdocBleTransportException("GATT server is closed")
        val device = connectedDevice ?: throw MdocBleTransportException("mdoc is disconnected")
        val characteristic = server2ClientCharacteristic
            ?: throw MdocBleTransportException("Server2Client characteristic is unavailable")
        characteristic.value = chunk
        val ack = CompletableDeferred<Boolean>()
        pendingNotifyAck = ack
        val queued = try {
            server.notifyCharacteristicChanged(device, characteristic, false)
        } catch (_: Exception) {
            false
        }
        if (!queued) {
            pendingNotifyAck = null
            throw MdocBleTransportException("Server2Client notification could not be queued")
        }
        val result = withTimeoutOrNull(NOTIFY_ACK_TIMEOUT_MS) { ack.await() }
        pendingNotifyAck = null
        if (result != true || !isActive) {
            throw MdocBleTransportException("Server2Client notification failed or was not acknowledged")
        }
    }

    private fun cccd() = BluetoothGattDescriptor(
        MdocBleProtocol.CCCD_UUID,
        BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
    )

    private fun stopAdvertising() {
        val currentAdvertiser = advertiser
        if (currentAdvertiser != null && advertising.compareAndSet(true, false)) {
            runCatching { currentAdvertiser.stopAdvertising(advertiseCallback) }
        }
        advertiser = null
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            advertising.set(false)
            fail("BLE advertising failed with code $errorCode")
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            if (!isActive || service.uuid != serviceUuid) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("adding the mdoc reader service failed with status $status")
                return
            }
            val currentAdvertiser = advertiser
            if (currentAdvertiser == null) {
                fail("BLE advertiser is unavailable")
                return
            }
            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setConnectable(true)
                .setTimeout(0)
                .build()
            val data = AdvertiseData.Builder()
                .addServiceUuid(ParcelUuid(serviceUuid))
                .setIncludeDeviceName(false)
                .build()
            try {
                advertising.set(true)
                currentAdvertiser.startAdvertising(settings, data, advertiseCallback)
            } catch (e: Exception) {
                advertising.set(false)
                fail("BLE advertising could not start", e)
            }
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (!isActive) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                if (device == connectedDevice || newState == BluetoothGatt.STATE_DISCONNECTED) {
                    fail("GATT server connection failed with status $status")
                }
                return
            }
            when (newState) {
                BluetoothGatt.STATE_CONNECTED -> {
                    val current = connectedDevice
                    if (current != null && current != device) {
                        runCatching { gattServer?.cancelConnection(device) }
                        fail("a second GATT client attempted to join the one-session transport")
                        return
                    }
                    connectedDevice = device
                    negotiatedMtu = MdocBleProtocol.DEFAULT_MTU
                    stopAdvertising()
                }
                BluetoothGatt.STATE_DISCONNECTED -> {
                    if (device == connectedDevice) fail("mdoc disconnected")
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            if (device == connectedDevice) {
                negotiatedMtu = if (mtu >= MdocBleProtocol.DEFAULT_MTU) mtu else MdocBleProtocol.DEFAULT_MTU
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic,
        ) {
            val server = gattServer ?: return
            if (device != connectedDevice || characteristic.uuid != MdocBleProtocol.READER_IDENT_UUID || offset !in 0..ident.size) {
                server.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                return
            }
            server.sendResponse(
                device,
                requestId,
                BluetoothGatt.GATT_SUCCESS,
                offset,
                ident.copyOfRange(offset, ident.size),
            )
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            val server = gattServer ?: return
            if (device != connectedDevice || preparedWrite) {
                if (responseNeeded) server.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                return
            }
            when (characteristic.uuid) {
                MdocBleProtocol.READER_STATE_UUID -> {
                    val event = try {
                        handshake.onState(value)
                    } catch (e: Exception) {
                        if (responseNeeded) server.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        fail("malformed State write", e)
                        return
                    }
                    if (responseNeeded) server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
                    when (event) {
                        MdocBleStateEvent.START -> if (handshake.ready) markReady()
                        MdocBleStateEvent.END -> fail("mdoc sent STATE_END")
                    }
                }
                MdocBleProtocol.READER_CLIENT2SERVER_UUID -> {
                    if (!handshake.started) {
                        if (responseNeeded) server.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        fail("Client2Server data arrived before STATE_START")
                        return
                    }
                    if (responseNeeded) server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
                    onIncomingChunk(value)
                }
                else -> if (responseNeeded) {
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            val server = gattServer ?: return
            if (device != connectedDevice || preparedWrite || descriptor.uuid != MdocBleProtocol.CCCD_UUID) {
                if (responseNeeded) server.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                return
            }
            descriptor.value = value
            if (responseNeeded) server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
            if (descriptor.characteristic.uuid == MdocBleProtocol.READER_SERVER2CLIENT_UUID) {
                val enabled = value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                handshake.onServer2ClientNotifications(enabled)
                if (!enabled && handshake.started) {
                    fail("mdoc disabled Server2Client notifications during the session")
                } else if (handshake.ready) {
                    markReady()
                }
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            if (device == connectedDevice) pendingNotifyAck?.complete(status == BluetoothGatt.GATT_SUCCESS)
        }
    }

    private companion object {
        const val NOTIFY_ACK_TIMEOUT_MS = 5_000L
    }
}
