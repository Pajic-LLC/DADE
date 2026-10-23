# Application verification

A game or application should not need to understand the full DADE protocol just to decide whether an asset can be used.

This document defines the first DADE 1 application-facing verification contract.

It is still a draft. The Python implementation is a reference harness, not a production SDK.

## The question

For normal local launch checks, an application should be able to ask one question:

```text
can this device use this asset?
```

The reference API expresses that as:

```text
can_use(asset_id, artifacts, challenge, ...)
```

The application supplies locally available DADE material. The verifier handles the protocol layers underneath.

## Inputs

The first reference path accepts:

- digital deed
- trusted issuer root public key
- issuer signing credential
- owner anchor public key
- controller credential
- personal device authorization
- fresh device proof
- optional owner trust snapshot
- optional issuer trust snapshot
- remembered trust sequence numbers when rollback protection is available
- the fresh challenge created for this verification attempt
- optional platform name
- optional local evaluation time for fixed-time rights

No network request is required for this decision.

## Result

The verifier returns a structured result instead of making the application parse cryptographic exceptions.

Current result codes are:

```text
owned
not_owned
wrong_asset
invalid_deed
untrusted_issuer
owner_proof_failed
device_not_authorized
device_proof_failed
controller_revoked
issuer_key_revoked
trust_state_rollback
right_not_granted
```

`owned` is the only result that allows use.

Every other result fails closed.

Development tools also receive a short diagnostic detail. Applications should make decisions from the stable result code, not from matching diagnostic text.

## What `owned` means

For the first local use path, `owned` means all of the following were proven:

1. the deed is structurally valid and correctly signed
2. the signing key was authorized by the trusted issuer root
3. the deed belongs to the requested asset
4. the deed was issued inside the signing key's allowed window
5. known issuer trust state does not reject that signing key for the deed's issuance time
6. the deed grants the required local use right
7. the deed owner matches the supplied owner anchor
8. the controller credential was issued by that owner anchor
9. known owner trust state does not revoke that controller
10. the device authorization was issued by that controller
11. the device has permission to use owned assets
12. the device signed the fresh challenge for the requested asset

The application does not need to repeat those checks itself.

## Rights behavior

The first `can_use` path supports permanent use directly.

Fixed-time use can be checked when the caller supplies a local evaluation time.

Subscription state is not yet defined by the local DADE 1 reference path. The reference API fails closed instead of pretending that a signed deed proves an active subscription.

If the deed limits platforms, the requested platform must be included.

Use on a personal device also requires the deed to allow personal-device use.

## Trust snapshots

Trust snapshots are optional because a completely offline device may not have received one yet.

If a valid snapshot is available, the application path applies it.

If the platform remembers that it previously accepted sequence 12, a signed sequence 11 snapshot is rejected as rollback.

This does not create periodic activation. A device can keep using the newest valid trust state it actually has.

## Privacy

The application-facing verifier does not require a real name, email address, Pajic account, or store account.

The ownership check uses cryptographic identifiers and locally available credentials.

## Private keys

Application code must not receive the owner anchor private key or device private key.

The device proof should be produced by the platform or secure key holder and passed into the verifier as signed proof.

The Python reference tests generate private keys only to create repeatable protocol test material.

## What this does not solve

This application path does not define:

- ownership transfer
- gifting
- resale invalidation
- lending
- inheritance
- active subscription proof
- the final production SDK API

Those remain separate work.
