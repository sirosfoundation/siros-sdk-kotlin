# tools

The BLE mdoc-reader test script that used to live here
(`ble_reader_test.py`) has moved to its own repo and grown into a real
commandline verifier:

**[siros-verifier-cli](https://github.com/sirosfoundation/siros-verifier-cli)**

It still drives the same "mdoc central client" role against this SDK's
`BlePeripheralServer`, but now supports multi-document/namespace requests,
IssuerAuth/DeviceAuth/digest verification, JSON output, QR image/webcam
input, and offline `DeviceEngagement` inspection.
