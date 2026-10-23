# Issuer signing credential

This document defines the first DADE 1 signing credential used between an issuer root and a deed signing key.

It uses the same deterministic CBOR and COSE_Sign1 profile as the rest of the DADE 1 draft.

## Signed payload

The signing credential payload is a deterministic CBOR map.

| Label | Name | Type | Required |
| --- | --- | --- | --- |
| 1 | version | uint | yes |
| 2 | credential_id | bstr, 16 bytes | yes |
| 3 | issuer_id | bstr, 16 bytes | yes |
| 4 | signing_key_id | bstr, 8 bytes | yes |
| 5 | signing_key | public COSE_Key | yes |
| 6 | valid_from | uint | yes |
| 7 | valid_until | uint | yes |

No other fields are accepted by the first draft.

## Version

The first value is `1`.

## Credential ID

The credential ID identifies this authorization statement.

It does not identify the issuer or signing key by itself.

## Issuer ID

The issuer ID must match the issuer ID derived from the trusted issuer root.

The first DADE 1 issuer ID is:

```text
first_16_bytes(
    SHA-256("DADE1-ISSUER\0" || canonical_public_cose_key(root))
)
```

## Signing key ID

The signing key ID must match the normal DADE key ID for the public signing key in the same credential.

```text
first_8_bytes(
    SHA-256(canonical_public_cose_key(signing_key))
)
```

## Signing key

The signing key is stored as a public P-256 COSE_Key.

Private key material is never included.

## Validity window

`valid_from` and `valid_until` describe when the signing key is allowed to issue deeds.

Both are integer Unix timestamps in UTC.

A deed is valid under the credential only when:

```text
valid_from <= deed.issued_at <= valid_until
```

Credential expiration does not make a previously valid permanent deed expire.

It only limits the time in which this signing key may issue deeds.

## Signature

The whole credential payload is wrapped in tagged COSE_Sign1 and signed by the issuer root.

The protected header contains:

- `alg = -7` for ES256
- `kid` equal to the DADE key ID of the issuer root

## Verification order

A verifier should:

1. load the locally trusted issuer root
2. derive the issuer ID from that root
3. verify the credential signature with the root
4. verify the issuer ID inside the credential
5. verify the signing key ID against the included signing key
6. verify the deed signature with the included signing key
7. verify the issuer ID inside the deed
8. verify the deed issuance time falls inside the credential window

If any step fails, issuer trust fails.

## Rotation

Two signing credentials from the same issuer root may authorize different signing keys for different time windows.

Both can remain useful for historical verification.

A verifier must not reject an old deed only because a newer signing credential exists.