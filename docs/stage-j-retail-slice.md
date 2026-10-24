# Stage J retail slice

This is the current DADE 1 hardening path for a retail-style VICE test title.

It is not a DADE 1 conformance procedure. The goal is to exercise the real local ownership path with secrets separated from the installed game and with a hardware-backed personal device key where the platform supports it.

## 1. Build the native provider and device tool

```sh
cargo build --release --manifest-path native/vice-provider/Cargo.toml
python native/vice-provider/package.py native/vice-provider/dist
```

The packaged provider belongs in the VICE runtime `modules` directory.

## 2. Enroll a hardware device

The hardware key is created before the DADE device authorization exists. Game launch never creates a replacement key.

### macOS

```sh
cargo run --manifest-path native/vice-provider/Cargo.toml --bin dade-device -- enroll-macos
```

Keep the returned:

- `device_id`
- `application_label`
- `public_key_sec1`

### Windows

```powershell
cargo run --manifest-path native/vice-provider/Cargo.toml --bin dade-device -- enroll-windows
```

Keep the returned:

- `device_id`
- `key_name`
- `public_key_sec1`

The private device key is not printed by either command.

## 3. Issue the Stage J test ownership chain

Use the hardware public key from the previous step:

```sh
python reference/python/generate_retail_slice.py .stage-j \
  --asset-id com.pajic.dade.stagej \
  --platform macos \
  --device-public-key-sec1 <public-key-sec1-hex>
```

For Windows, use `--platform windows`. Repeat `--platform` if the deed should grant both platforms.

The generator creates three separate areas:

```text
.stage-j/
  install/dade-home/   locally installed proof material
  secrets/             test issuer and owner private material
  trust-updates/       signed Stage J update scenarios
```

Hardware mode does not put a device private key in `install/dade-home` or `secrets`.

For CI or development without hardware-backed signing, use the explicit development mode instead:

```sh
python reference/python/generate_retail_slice.py .stage-j \
  --development-file-signer
```

That mode intentionally installs an exportable development device key and must not be treated as the retail key-storage path.

## 4. Activate the authorized hardware key

Point `DADE_HOME` at the generated install root first. The generated owner state already contains the controller-signed device authorization for the public key supplied to the generator.

### macOS

```sh
export DADE_HOME="$PWD/.stage-j/install/dade-home"
cargo run --manifest-path native/vice-provider/Cargo.toml --bin dade-device -- \
  activate-macos <device-id> <application-label>
```

### Windows PowerShell

```powershell
$env:DADE_HOME = "$PWD\.stage-j\install\dade-home"
cargo run --manifest-path native/vice-provider/Cargo.toml --bin dade-device -- `
  activate-windows <device-id> <key-name>
```

Activation reloads the exact platform key, derives its DADE device ID again, and refuses to install the signer descriptor if the key does not match the authorized device.

## 5. Stage the VICE title

The VICE project authoring metadata must use the exact same asset ID as the deed:

```text
com.pajic.dade.stagej
```

Stage the project through the normal VICE build flow. Staged VICE executables carry the DADE requirement and asset ID in the package metadata stamped into the executable. The loose `dade.asset` authoring file is not the staged runtime enforcement switch.

Until VICE stages the DADE provider automatically, install the already packaged provider with the repeatable helper:

```sh
python reference/python/stage_vice_provider.py \
  native/vice-provider/dist \
  <vice-game-output>
```

The helper copies the one packaged `dade_provider` library into the staged runtime `modules` directory and refuses to replace an existing provider unless `--force` is passed. Automatic VICE-side staging is tracked separately so this helper can go away once the editor owns that step.

For a retail-style artifact, apply the normal platform code signature only after VICE has written its package metadata and the DADE provider has been staged. The package stamp detects missing or changed DADE metadata; platform signing is the outer integrity boundary for the final executable.

## 6. Run offline

After setup is complete, disconnect network access and launch the staged title.

A valid permanent deed must reach `owned` without a live Pajic service, DADE service, or original store service.

Keep `DADE_HOME` outside the staged game package. The game package should not contain issuer signing keys, owner anchor private keys, controller private keys, or the personal device private key.

## 7. Reinstall test

Keep the same `DADE_HOME` and hardware key, remove the staged application, then reinstall the archived staged package.

The reinstalled title should still reach `owned` offline because ownership is represented by the retained deed, trust material, owner/device authorization, and the same local hardware device identity.

## 8. Controller revocation test

The fixture includes:

```text
trust-updates/owner-sequence-1.hex
trust-updates/owner-controller-revoked-sequence-2.hex
```

Install sequence 1 as the owner snapshot and launch once. Then replace it with sequence 2 and launch again. The second launch must deny the revoked controller.

After sequence 2 has been remembered, replacing the snapshot with sequence 1 must be rejected as `trust_state_rollback`.

## 9. Issuer compromise test

The fixture also includes:

```text
trust-updates/issuer-sequence-1.hex
trust-updates/issuer-signing-key-compromised-sequence-2.hex
```

Install sequence 1 and launch once. Then install sequence 2. The Stage J deed was issued at the compromise cutoff, so the later launch must be denied as `issuer_key_revoked`.

After sequence 2 has been remembered, restoring sequence 1 must be rejected as `trust_state_rollback`.

## 10. What remains manual

CI can verify the reference chain, native builds, descriptor parsing, platform API compilation, generated retail ownership state, and the packaged provider against that generated state. It cannot prove that a hosted runner has a usable personal Secure Enclave or TPM for the exact retail flow.

Before Stage J hardware work is called complete, run this procedure on:

- a real Apple Silicon Mac with Secure Enclave available
- a Windows machine with a usable TPM through the Microsoft Platform Crypto Provider

Record the device enrollment, restart, activation, offline launch, reinstall, revocation, and rollback results.
