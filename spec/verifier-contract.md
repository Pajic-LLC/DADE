# Local verifier contract

The DADE verifier should give applications a small, boring interface.

A game or application should not need to understand the entire DADE protocol just to decide whether an owned product can be used.

This document defines the first logical verifier contract. It does not freeze an SDK API or programming language.

## Main question

For normal use, an application should be able to ask:

```text
Can this DADE identity exercise this right for this asset on this device?
```

For example:

```text
Can the current owner use VICE on this device?
```

The verifier checks the local ownership material and returns a result.

## Inputs

The verifier may need:

- the digital deed
- the expected asset ID
- the requested right
- proof that the owner controls the DADE identity
- the current device authorization when device authorization is required
- trusted issuer verification material
- the current DADE protocol rules

For a permanently owned offline-capable asset that has already been set up, these inputs must be available locally.

## No network requirement for ordinary offline verification

The verifier must not require a live Pajic, DADE, store, or issuer API call just to validate normal use of a properly set up permanent offline-capable product.

An application can still choose to use online services for updates, multiplayer, cloud saves, storefront features, or other unrelated functions.

Those are not the ownership proof itself.

## Minimum checks

A local verifier should be able to check at least the following.

### Deed structure

Is the deed well formed for the DADE version it claims to use?

### Issuer authenticity

Was the deed signed by an issuer trusted for this asset?

### Integrity

Were the signed deed fields changed after issuance?

### Asset match

Does the deed cover the asset that is asking for verification?

A deed for one game must not unlock another game just because they share an issuer.

### Owner control

Can the current user prove control of the DADE identity named as owner?

The final proof mechanism is not fixed yet.

### Right check

Does the deed include the right being requested?

Examples:

- permanent use
- offline use
- use on a personal device
- access to a platform-specific build

### Device authorization

If the requested use requires an authorized personal device, is this device validly authorized by the owner?

The final device authorization protocol is not fixed yet.

### Service dependency

Does the requested feature depend on a live service?

A verifier should be able to distinguish ownership failure from service unavailability.

## Result model

The verifier should return a machine-readable result and a short human-readable reason.

The first result set should stay small.

Possible results:

- `valid`
- `invalid_deed`
- `untrusted_issuer`
- `wrong_asset`
- `owner_proof_required`
- `owner_proof_failed`
- `device_not_authorized`
- `right_not_granted`
- `service_required`
- `unsupported_dade_version`

These names are draft names, not frozen protocol constants.

## Ownership failure is not service failure

Applications must not turn unrelated outages into ownership errors.

Bad:

```text
Could not contact multiplayer server.
Your license is invalid.
```

Good:

```text
Ownership verified.
Multiplayer service is unavailable.
```

That difference matters.

## Verification should reveal as little as possible

A game checking ownership should not automatically receive the owner's email address, legal name, phone number, full purchase history, or unrelated deeds.

The verifier should return only what the application needs for the requested asset and right.

## Verification should fail closed

If a signature is malformed, the issuer cannot be trusted, the asset does not match, or the ownership proof is invalid, the verifier should not guess.

It should return a clear failure result.

At the same time, an unavailable network must not be treated as a failure when the deed is designed for permanent offline verification.

## Example

An application asks:

```text
asset: example.publisher/vice
right: use
mode: offline
```

The verifier might return:

```json
{
  "result": "valid",
  "asset": "example.publisher/vice",
  "right": "use",
  "offline": true
}
```

This is an illustration only. It is not the final API or wire format.

## What this document does not define

This document does not define:

- the signature suite
- the key hierarchy
- the device pairing protocol
- transfer invalidation
- lending state
- recovery
- network synchronization
- the final SDK API

Those decisions come later.
