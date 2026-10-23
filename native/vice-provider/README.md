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
10. Create a fresh 32-byte launch challenge.
11. Sign the challenge with the local device key.
12. Verify the fresh device proof against the authorized device key.
13. Return `owned` only if every required check passes.

## Device key status

This Stage I provider keeps the device private key behind the provider boundary, so VICE cannot access it.

The current reference store still uses a PKCS#8 PEM file for that device key. That is good enough for conformance and product integration work, but it is not the final retail key-storage design.

A production provider should replace the file-backed signer with platform-backed key storage such as Secure Enclave on Apple platforms and TPM-backed keys on supported Windows systems. The verifier and VICE ABI do not need to change when that signer backend changes.

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

## Packaging limit

VICE currently uses a loose `dade.asset` file to mark a protected project.

That is not enough for final retail enforcement. The DADE asset ID still needs to be bound into signed or integrity-protected game package metadata so deleting one file cannot turn ownership checks off.
