// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.verifier.mdoc.proximity

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Reader as GATT client for mdoc peripheral-server mode. A successful startup means
 * STATE_START was acknowledged; only then may the elected transport send SessionEstablishment.
 */
@SuppressLint("MissingPermission")
@Suppress("DEPRECATION")
internal class BleGattClientTransport(
    private val context: Context,
    private val serviceUuid: UUID,
    onReady: (MdocBleCandidate) -> Unit,
    onFailure: (MdocBleCandidate, Throwable) -> Unit,
) : AbstractMdocBleTransport("mdoc peripheral-server mode", onReady, onFailure) {
    private val handshake = MdocBleClientHandshake()
    private val scanning = AtomicBoolean(false)
    private val connecting = AtomicBoolean(false)
    private val awaitingMtu = AtomicBoolean(false)
    private val serviceDiscoveryStarted = AtomicBoolean(false)

    private var scanner: BluetoothLeScanner? = null

    @Volatile
    private var gatt: BluetoothGatt? = null

    @Volatile
    private var negotiatedMtu = MdocBleProtocol.DEFAULT_MTU

    private var client2ServerCharacteristic: BluetoothGattCharacteristic? = null
    private var stateCharacteristic: BluetoothGattCharacteristic? = null

    @Volatile
    private var pendingWriteAck: CompletableDeferred<Boolean>? = null

    override fun startRadio() {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            ?: throw MdocBleTransportException("BluetoothManager is unavailable")
        val adapter = manager.adapter
        if (adapter == null || !adapter.isEnabled) {
            throw MdocBleTransportException("Bluetooth is unavailable or disabled")
        }
        scanner = adapter.bluetoothLeScanner
            ?: throw MdocBleTransportException("This device has no BLE scanner")
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(serviceUuid)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanning.set(true)
        try {
            scanner?.startScan(listOf(filter), settings, scanCallback)
        } catch (e: Exception) {
            scanning.set(false)
            throw e
        }
    }

    override fun closeRadio() {
        stopScanning()
        pendingWriteAck?.complete(false)
        pendingWriteAck = null
        gatt?.let {
            runCatching { it.disconnect() }
            runCatching { it.close() }
        }
        gatt = null
    }

    override fun currentMaxChunkSize(): Int = MdocBleProtocol.maxChunkSize(negotiatedMtu)

    override suspend fun sendChunk(chunk: ByteArray) {
        val currentGatt = gatt ?: throw MdocBleTransportException("GATT client is disconnected")
        val characteristic = client2ServerCharacteristic
            ?: throw MdocBleTransportException("Client2Server characteristic is unavailable")
        if (!writeNoResponse(currentGatt, characteristic, chunk)) {
            throw MdocBleTransportException("Client2Server chunk write failed or was not acknowledged")
        }
    }

    private fun stopScanning() {
        if (scanning.compareAndSet(true, false)) {
            runCatching { scanner?.stopScan(scanCallback) }
        }
        scanner = null
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            if (!isActive || !connecting.compareAndSet(false, true)) return
            stopScanning()
            try {
                val connected = result.device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
                if (connected == null) {
                    fail("connectGatt returned null")
                } else if (!isActive) {
                    connected.disconnect()
                    connected.close()
                } else {
                    gatt = connected
                }
            } catch (e: Exception) {
                fail("could not connect to the mdoc", e)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            scanning.set(false)
            fail("BLE scan failed with code $errorCode")
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (!isActive) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("GATT connection failed with status $status")
                return
            }
            when (newState) {
                BluetoothGatt.STATE_CONNECTED -> negotiateMtu(gatt)
                BluetoothGatt.STATE_DISCONNECTED -> fail("mdoc disconnected")
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            if (!isActive) return
            negotiatedMtu = if (status == BluetoothGatt.GATT_SUCCESS && mtu >= MdocBleProtocol.DEFAULT_MTU) {
                mtu
            } else {
                MdocBleProtocol.DEFAULT_MTU
            }
            awaitingMtu.set(false)
            discoverServices(gatt)
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (!isActive) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("GATT service discovery failed with status $status")
                return
            }
            val service = gatt.getService(serviceUuid)
            if (service == null) {
                fail("mdoc does not expose the engaged service $serviceUuid")
                return
            }
            val state = service.getCharacteristic(MdocBleProtocol.MDOC_STATE_UUID)
            val client2Server = service.getCharacteristic(MdocBleProtocol.MDOC_CLIENT2SERVER_UUID)
            val server2Client = service.getCharacteristic(MdocBleProtocol.MDOC_SERVER2CLIENT_UUID)
            if (state == null || client2Server == null || server2Client == null) {
                fail("mdoc service is missing State, Client2Server, or Server2Client")
                return
            }
            stateCharacteristic = state
            client2ServerCharacteristic = client2Server
            enableNotifications(gatt, state)
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            if (!isActive) return
            if (status != BluetoothGatt.GATT_SUCCESS) {
                fail("enabling ${descriptor.characteristic.uuid} notifications failed with status $status")
                return
            }
            when (descriptor.characteristic.uuid) {
                MdocBleProtocol.MDOC_STATE_UUID -> {
                    handshake.onNotifications(MdocBleNotificationCharacteristic.STATE, true)
                    val server2Client = descriptor.characteristic.service
                        .getCharacteristic(MdocBleProtocol.MDOC_SERVER2CLIENT_UUID)
                    enableNotifications(gatt, server2Client)
                }
                MdocBleProtocol.MDOC_SERVER2CLIENT_UUID -> {
                    handshake.onNotifications(MdocBleNotificationCharacteristic.SERVER_TO_CLIENT, true)
                    val state = stateCharacteristic
                    if (state == null) {
                        fail("State characteristic disappeared during startup")
                        return
                    }
                    scope.launch {
                        if (!writeNoResponse(gatt, state, byteArrayOf(MdocBleProtocol.STATE_START))) {
                            fail("STATE_START write failed or was not acknowledged")
                        } else {
                            handshake.onStateStartWritten()
                            if (handshake.ready) markReady()
                        }
                    }
                }
            }
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            pendingWriteAck?.complete(status == BluetoothGatt.GATT_SUCCESS)
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            if (!isActive) return
            when (characteristic.uuid) {
                MdocBleProtocol.MDOC_SERVER2CLIENT_UUID -> onIncomingChunk(characteristic.value ?: return)
                MdocBleProtocol.MDOC_STATE_UUID -> handleStateNotification(characteristic.value ?: return)
            }
        }
    }

    private fun negotiateMtu(gatt: BluetoothGatt) {
        awaitingMtu.set(true)
        val requested = try {
            gatt.requestMtu(REQUESTED_MTU)
        } catch (e: Exception) {
            awaitingMtu.set(false)
            fail("MTU negotiation could not start", e)
            return
        }
        if (!requested) {
            awaitingMtu.set(false)
            discoverServices(gatt)
            return
        }
        scope.launch {
            delay(MTU_TIMEOUT_MS)
            if (awaitingMtu.compareAndSet(true, false)) discoverServices(gatt)
        }
    }

    private fun discoverServices(gatt: BluetoothGatt) {
        if (!isActive || !serviceDiscoveryStarted.compareAndSet(false, true)) return
        val started = try {
            gatt.discoverServices()
        } catch (e: Exception) {
            fail("GATT service discovery could not start", e)
            return
        }
        if (!started) fail("GATT service discovery could not start")
    }

    private fun enableNotifications(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic?) {
        if (characteristic == null) {
            fail("cannot enable notifications on a missing characteristic")
            return
        }
        try {
            if (!gatt.setCharacteristicNotification(characteristic, true)) {
                fail("setCharacteristicNotification failed for ${characteristic.uuid}")
                return
            }
            val descriptor = characteristic.getDescriptor(MdocBleProtocol.CCCD_UUID)
            if (descriptor == null) {
                fail("${characteristic.uuid} has no CCCD")
                return
            }
            descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            if (!gatt.writeDescriptor(descriptor)) {
                fail("CCCD write could not start for ${characteristic.uuid}")
            }
        } catch (e: Exception) {
            fail("could not enable ${characteristic.uuid} notifications", e)
        }
    }

    private fun handleStateNotification(value: ByteArray) {
        try {
            if (MdocBleState.parse(value) == MdocBleStateEvent.END) fail("mdoc sent STATE_END")
        } catch (e: Exception) {
            fail("malformed State notification", e)
        }
    }

    /** Android permits only one outstanding GATT operation; every chunk waits for its write callback. */
    private suspend fun writeNoResponse(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
    ): Boolean {
        if (!isActive) return false
        val ack = CompletableDeferred<Boolean>()
        pendingWriteAck = ack
        characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        characteristic.value = value
        val queued = try {
            gatt.writeCharacteristic(characteristic)
        } catch (_: Exception) {
            false
        }
        if (!queued) {
            pendingWriteAck = null
            return false
        }
        val result = withTimeoutOrNull(WRITE_ACK_TIMEOUT_MS) { ack.await() }
        pendingWriteAck = null
        return result == true && isActive
    }

    private companion object {
        const val REQUESTED_MTU = 517
        const val MTU_TIMEOUT_MS = 5_000L
        const val WRITE_ACK_TIMEOUT_MS = 5_000L
    }
}
