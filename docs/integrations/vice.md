# VICE integration

VICE uses DADE as an ownership decision provider before protected game code starts.

VICE does not parse deeds itself. It does not receive owner private keys or device private keys. The DADE provider verifies ownership and returns one decision.

The first VICE integration lives behind a small dynamic provider ABI so DADE can keep evolving without copying protocol internals into the engine.

## Request

VICE gives the provider:

- the DADE asset ID
- the current platform
- the project root

The provider is responsible for finding the local DADE material it needs and producing a fresh ownership proof where required.

## Result codes

The application decision codes are fixed to these numeric values for the first VICE provider ABI:

```text
0  owned
1  not_owned
2  wrong_asset
3  invalid_deed
4  untrusted_issuer
5  owner_proof_failed
6  device_not_authorized
7  device_proof_failed
8  controller_revoked
9  issuer_key_revoked
10 trust_state_rollback
11 right_not_granted
12 provider_error
```

Codes 0 through 11 map directly to the Python `DecisionCode` values through `dade_vice.py`.

`provider_error` belongs to the native boundary. It means the provider itself could not complete the request. It must never be treated as ownership.

Only `owned` allows launch.

## Native provider

The first native provider lives in `native/vice-provider`.

It is a Rust dynamic library with the `vice_dade_verify` entrypoint expected by VICE. It does not need a Python runtime when used by VICE.

The provider reads the local DADE store, verifies the full ownership chain, creates a fresh launch challenge, signs that challenge with the authorized local device key, verifies the resulting device proof, and returns one decision.

The provider does not trust issuer roots supplied by a game package. Issuer roots are looked up by issuer ID from the local DADE trust store.

For a normal permanent deed the native path is:

```text
trusted issuer root
  -> signing credential
  -> digital deed
  -> cached issuer trust state
  -> owner anchor
  -> cached owner trust state
  -> controller credential
  -> device authorization
  -> fresh device proof
  -> rights check
  -> owned
```

Any required check that fails returns a denial code instead of falling back to an online activation service.

## Local store

The reference provider uses a local `DADE_HOME` store. `DADE_HOME` can be set explicitly for tests and development. Without it, the provider uses the normal per-user application-data location for the current platform.

The current layout is documented in `native/vice-provider/README.md`.

The game package does not contain owner or device private keys.

The current Stage I device signer uses a PKCS#8 private-key file inside the DADE store. This keeps the key behind the provider boundary and is enough for integration and conformance work. It is not the final retail key-storage design. A later signer backend should use platform-backed key storage without changing this VICE ABI.

## Verification rules

The native provider must produce the same decision as `dade_app.can_use` for the same DADE artifacts, asset, platform, challenge, and remembered trust state.

The Python implementation remains the conformance oracle until the native verifier has enough independent review and test coverage to stand on its own.

Cross-language test vectors cover:

- valid permanent ownership
- missing deed
- wrong asset
- invalid deed signature
- wrong issuer root
- controller revocation
- issuer signing-key compromise cutoff
- bad device proof or key
- platform not granted
- owner trust rollback
- issuer trust rollback

## Private keys

VICE must not receive the owner anchor private key.

VICE must not receive the controller private key.

VICE must not receive the personal device private key.

Device signing belongs inside DADE or a dedicated local ownership component. VICE should only receive the final decision and diagnostics.

## Offline use

A permanent offline-capable deed must still be verifiable without a live Pajic service.

The provider may use cached signed trust updates. It must not turn a permanent deed into periodic online activation.

## Packaging

VICE currently uses `dade.asset` as the first integration marker for a protected project.

That file is not a final retail anti-tamper boundary. Before shipping enforcement, the DADE asset ID must be bound into signed or integrity-protected package metadata so removing one loose file cannot disable the ownership requirement.

Build the provider with:

```sh
cargo build --release --manifest-path native/vice-provider/Cargo.toml
python native/vice-provider/package.py native/vice-provider/dist
```

The packaging helper removes the normal Unix `lib` prefix so the output filename matches the module name VICE already loads.
