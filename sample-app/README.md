# SIROS Kotlin sample: wallet and standalone verifier

The sample contains both a holder wallet and an ISO 18013-5 verifier. **The verifier does not require registration or login.** On the logged-out screen, choose **Verify nearby mdoc (no account required)**. A logged-in user can use the **Verify** action in the bottom bar.

## Configure go-trust

Start a local AuthZEN PDP, for example the allow-all development instance from `siros-conformance`:

```sh
docker compose -f compose/go-trust.yml up -d
```

It listens on port `9095`. In the verifier screen, enter the complete evaluation URL and tenant ID:

- Android emulator: `http://10.0.2.2:9095/v1/evaluate`
- Local device/waydroid setup: `http://127.0.0.1:9095/v1/evaluate`
- Physical device: use the development host's reachable LAN address

The allow-all instance is only a demonstration fixture. Use a configured go-trust tenant for meaningful issuer policy. The sample never uses a local trust fallback and displays claims only after an explicit permit.

## Two-device demonstration

1. On the holder device, log in and open **Proximity** to display its `mdoc:` QR engagement.
2. On the verifier device, open **Verify nearby mdoc** without signing in.
3. Grant camera and Bluetooth permissions and choose **Scan wallet QR**.
4. The verifier requests `given_name` and `family_name` from one mDL with no retention, elects one BLE role, verifies the response, evaluates the issuer through go-trust, and only then displays the claims.

**Tap wallet (NFC)** reads NFC static handover from a Type 4 Tag and continues over BLE. It does not implement NFC SessionData transport. NFC handover requires a second NFC-capable holder device.

QR/BLE and NFC tests on a JVM do not establish radio interoperability. Run both BLE roles and NFC static handover on physical devices before release.
