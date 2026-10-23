# Device proof

A device authorization says that an owner approved a device key.

A device proof shows that the device currently presenting the authorization can use that private key.

## Format

A DADE 1 device proof is a tagged COSE_Sign1 object signed by the authorized device key.

The payload is a deterministic CBOR map.

| Label | Name | Type | Required |
| --- | --- | --- | --- |
| 1 | version | uint | yes |
| 2 | challenge | 32-byte bstr | yes |
| 3 | asset_id | text string | yes |
| 4 | requested_right | uint | yes |
| 5 | owner_id | 16-byte bstr | yes |
| 6 | device_id | 16-byte bstr | yes |

For this draft, `version` is `1`.

## Requested rights

The first proof right is:

```text
1 use
```

More rights can be added later without changing what right `1` means.

## Challenge

The verifier creates 32 cryptographically random bytes for each proof request.

The challenge must not be reused deliberately.

The device signs the challenge together with the asset ID, requested right, owner ID, and device ID.

This prevents a valid response for one launch request from becoming a generic signature that can be replayed for another asset or right.

## Verification

A verifier checks:

1. the COSE signature is valid for the device public key in the device authorization
2. the proof key ID matches that device public key
3. the challenge is the challenge the verifier just issued
4. the asset ID matches the asset being opened
5. the requested right matches the action being requested
6. the owner ID matches the deed and device authorization
7. the device ID matches the authorized device key

A valid device proof does not replace deed verification.

Both are required.

## Offline use

The challenge is generated locally.

No server is required to create or verify it.

That means an already authorized device can prove possession of its device key while completely offline.

## Local authentication

A platform may require local user authentication before allowing the device key to sign.

For example, the OS may require Face ID, Touch ID, Windows Hello, a passcode, or no prompt depending on the owner's settings and the product's security policy.

DADE does not put biometric data into the proof.
