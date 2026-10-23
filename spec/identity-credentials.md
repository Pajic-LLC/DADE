# Identity credential formats

This document proposes the first DADE 1 wire shapes for owner identity, controller credentials, and personal device authorization.

It is a draft.

## Public key format

DADE 1 should represent P-256 public keys as public COSE_Key maps.

For the first profile:

```text
1   kty = 2, EC2
-1  crv = 1, P-256
-2  x coordinate, 32 bytes
-3  y coordinate, 32 bytes
```

Private key material is never included in a DADE public credential.

## Key IDs

When a COSE signature needs a `kid`, DADE 1 derives it from the canonical public COSE_Key:

```text
kid = first 8 bytes of SHA-256(canonical public COSE_Key)
```

The key ID is a lookup hint. It is not the owner ID.

## Owner ID

The owner ID is derived from the identity anchor public key.

The exact DADE 1 construction is:

```text
owner_id = first 16 bytes of SHA-256(
  h'44414445312d4f574e455200' || canonical public anchor COSE_Key
)
```

The prefix is ASCII `DADE1-OWNER` followed by a zero byte.

The domain prefix prevents the same key hash construction from being reused accidentally for another DADE identifier type.

## Controller ID

A controller ID is derived from the controller public key:

```text
controller_id = first 16 bytes of SHA-256(
  h'44414445312d434f4e54524f4c4c455200' || canonical public controller COSE_Key
)
```

The prefix is ASCII `DADE1-CONTROLLER` followed by a zero byte.

## Device ID

A device ID is derived from the device public key:

```text
device_id = first 16 bytes of SHA-256(
  h'44414445312d44455649434500' || canonical public device COSE_Key
)
```

The prefix is ASCII `DADE1-DEVICE` followed by a zero byte.

## Controller credential

A controller credential is a tagged COSE_Sign1 object signed by the identity anchor key.

Its payload is a deterministic CBOR map.

| Label | Name | Type | Required |
| --- | --- | --- | --- |
| 1 | version | uint | yes |
| 2 | credential_id | 16-byte bstr | yes |
| 3 | owner_id | 16-byte bstr | yes |
| 4 | controller_id | 16-byte bstr | yes |
| 5 | controller_key | COSE_Key map | yes |
| 6 | scopes | array of uint | yes |
| 7 | issued_at | uint | yes |
| 8 | expires_at | uint | no |

For this draft, `version` is `1`.

### Controller scopes

```text
1 authorize_devices
2 prove_owner
```

A verifier must reject a controller action when the controller credential does not include the required scope.

No transfer or recovery scope is defined in this public draft.

## Device authorization

A device authorization is a tagged COSE_Sign1 object signed by a controller key that has the `authorize_devices` scope.

Its payload is a deterministic CBOR map.

| Label | Name | Type | Required |
| --- | --- | --- | --- |
| 1 | version | uint | yes |
| 2 | authorization_id | 16-byte bstr | yes |
| 3 | owner_id | 16-byte bstr | yes |
| 4 | controller_id | 16-byte bstr | yes |
| 5 | device_id | 16-byte bstr | yes |
| 6 | device_key | COSE_Key map | yes |
| 7 | scopes | array of uint | yes |
| 8 | issued_at | uint | yes |
| 9 | expires_at | uint | no |

### Device scopes

```text
1 use_owned_assets
```

The first DADE 1 draft deliberately gives an ordinary device very little authority.

A use device cannot authorize another device.

## Verification chain

A local verifier can validate an authorized personal device without contacting Pajic.

The chain is:

```text
issuer signature on deed
          |
          v
owner_id in deed
          |
          v
anchor public key derives same owner_id
          |
          v
anchor signature on controller credential
          |
          v
controller public key derives controller_id
          |
          v
controller signature on device authorization
          |
          v
device public key derives device_id
          |
          v
fresh challenge signed by device private key
```

If every step is valid, the verifier has evidence that:

1. the issuer issued the deed to this DADE identity
2. the identity authorized this controller
3. the controller authorized this device
4. the current device controls the authorized device key

The deed rights still decide whether the requested use is allowed.

## Fresh device proof

A verifier should challenge the device with at least 32 bytes of cryptographically random data.

The device signs a structured proof that includes:

- DADE proof version
- the random challenge
- the asset ID being requested
- the requested right

Binding the asset and requested right into the signed proof prevents the same response from being reused as a generic signature for another request.

The exact proof encoding will be defined with the verifier implementation.

## Local user confirmation

A controller implementation should ask for local user confirmation before signing a new device authorization.

That can use Face ID, Touch ID, Windows Hello, a device passcode, or another platform authentication method.

DADE does not send biometric data to the new device or put biometric data in the credential.

## Expiry

Permanent personal devices do not need an expiry just to keep working offline.

An expiry can still be used for a temporary controller or temporary device authorization when the owner chooses that behavior.

Lending is not represented by pretending a borrower's machine is a permanent personal device. Lending gets its own protocol later.

## Revocation and state changes

These credentials define authorization, not the final remote revocation system.

A completely offline machine cannot learn about a later state change somewhere else.

The transfer and invalidation design remains separate and is not published here pending the legal and IP review gate.
