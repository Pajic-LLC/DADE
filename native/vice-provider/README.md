# DADE VICE provider

This is the first native DADE provider for VICE.

VICE loads this library before protected game code starts. VICE gives it an asset ID, platform, and project root. The provider checks the local DADE ownership chain and returns one decision.

VICE never receives the owner anchor private key, controller private key, or device private key.

## Build

```sh
cargo build --release --manifest-path native/vice-provider/Cargo.toml
python native/vice-provider/package.py native/vice-provider/dist
```

The packaging helper gives the library the filename VICE expects:

- macOS: `dade_provider.dylib`
- Windows: `dade_provider.dll`
- Linux reference builds: `dade_provider.so`

The packaged library belongs in the VICE runtime `modules` directory.

## Local DADE store

Set `DADE_HOME` to override the default local store location.

The current reference store looks like this:

```text
DADE_HOME/
  assets/
    com.pajic.vice/
      issuer-id.hex
      deed.hex
      signing-credential.hex

  trust/
    issuers/
      <issuer-id>/
        root.pem
        snapshot.hex              optional

  owners/
    <owner-id>/
      anchor.pem
      controller.hex
      device-authorization.hex
      snapshot.hex                optional

  devices/
    <device-id>.pem

  state/
    issuers/
      <issuer-id>.seq
    owners/
      <owner-id>.seq
```

The sequence files are written by the provider after it accepts newer signed trust state. They are used to reject signed rollback attempts later.

## Launch verification

For a permanent local deed the provider does this without a network request:

1. Find the deed for the requested asset.
2. Load the issuer root from the local trust store.
3. Verify the root-signed signing credential.
4. Verify the deed signature and rights.
5. Apply the newest cached issuer trust snapshot.
6. Verify the owner anchor.
7. Apply the newest cached owner trust snapshot.
8. Verify the controller credential.
9. Verify the device authorization.
10. Load a device signer behind the provider boundary.
11. Create a fresh 32-byte launch challenge.
12. Ask the device signer to sign the proof input.
13. Verify the fresh device proof against the authorized device key.
14. Return `owned` only if every required check passes.

## Device signer boundary

Device proof creation now goes through a small signer interface. The provider asks that interface for the device public key and for an ES256 signature. The ownership verification path does not need direct access to a private key object anymore.

The first backend still reads a PKCS#8 P-256 key from `devices/<device-id>.pem`. That keeps existing fixtures and cross-language tests working while the hardware-backed backends are built.

The next retail step is to add platform implementations behind the same interface:

- Secure Enclave on supported Apple hardware
- TPM-backed signing on supported Windows hardware
- an explicit development fallback where secure hardware is unavailable

Those backends must return the same P-256 public key and raw 64-byte ES256 signature shape. They do not require a VICE ABI change or a DADE wire-format change.

## Cross-language tests

`reference/python/generate_vice_fixture.py` creates DADE homes from the same deterministic credentials used by the Python reference tests.

The Rust tests read the Python-generated expectations and must return the same decision codes for:

- valid ownership
- missing deed
- wrong asset
- invalid deed signature
- wrong issuer root
- revoked controller
- compromised issuer signing key
- owner trust rollback
- issuer trust rollback
- platform not granted
- wrong device key

The Python path remains the conformance oracle for DADE 1 while the native implementation is young.

## Packaging status

VICE staged builds no longer use `dade.asset` as the runtime enforcement switch. VICE now stamps staged executables with package metadata that records the DADE requirement and asset ID, validates that metadata before game code loads, and fails closed if it is missing or changed.

`dade.asset` remains authoring input for development builds. Retail builds still need normal platform code signing after the VICE package stamp is written so an attacker cannot simply rewrite the executable and its metadata together.
