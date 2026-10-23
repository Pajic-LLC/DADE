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

## Verification rules

The native provider must produce the same decision as `dade_app.can_use` for the same DADE artifacts, asset, platform, challenge, and remembered trust state.

The Python implementation remains the conformance oracle until the native verifier has enough independent review and test coverage to stand on its own.

Cross-language test vectors should cover at least:

- valid permanent ownership
- missing deed
- wrong asset
- invalid deed signature
- wrong issuer root
- controller revocation
- issuer signing-key compromise cutoff
- bad device proof
- platform not granted
- trust-state rollback

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
