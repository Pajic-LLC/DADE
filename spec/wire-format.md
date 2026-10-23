# DADE 1 deed wire format

This is the first concrete wire-format draft for a DADE digital deed.

It is not a production release yet.

## Container

A portable deed is a tagged COSE_Sign1 object.

The COSE payload is a deterministic CBOR map containing the deed fields.

For this draft:

```text
COSE tag       18, COSE_Sign1
COSE algorithm ES256, value -7
Curve          P-256
Hash           SHA-256
Payload        deterministic CBOR
```

The protected COSE header must contain:

- `alg`
- `kid`

The `kid` value selects the issuer signing key. It does not replace the issuer ID inside the signed deed payload.

## Core deed fields

The payload uses small integer labels.

| Label | Name | Type | Required |
| --- | --- | --- | --- |
| 1 | version | unsigned integer | yes |
| 2 | deed_id | 16-byte byte string | yes |
| 3 | asset_id | text string | yes |
| 4 | issuer_id | 16-byte byte string | yes |
| 5 | owner_id | 16-byte byte string | yes |
| 6 | rights | map | yes |
| 7 | issued_at | unsigned integer | yes |
| 8 | terms_sha256 | 32-byte byte string | yes |
| 9 | terms_uri | text string | no |
| 10 | edition | text string | no |
| 11 | critical | array of unsigned integers | no |

`version` is `1` for this draft.

`issued_at` is the number of whole seconds since 1970-01-01T00:00:00Z.

`asset_id` must be stable for the owned product and must not change for an ordinary software update.

`issuer_id` and `owner_id` are opaque identifiers. Their key and trust bindings are defined by separate DADE profiles.

## Why IDs are not names

The wire format does not put a person's email address, legal name, username, or device name into the ownership identity fields.

The same rule applies to issuers. A company can change its display name without needing to rewrite every deed it ever issued.

## Rights map

The rights map uses these labels.

| Label | Name | Type | Required |
| --- | --- | --- | --- |
| 1 | use | unsigned integer | yes |
| 2 | offline | unsigned integer | yes |
| 3 | personal_devices | boolean | yes |
| 4 | gift | boolean | yes |
| 5 | resale | boolean | yes |
| 6 | lend | boolean | yes |
| 7 | platforms | array of text strings | no |
| 8 | use_until | unsigned integer | conditional |
| 9 | service_dependencies | array of text strings | no |

### Use values

```text
0 permanent
1 until a fixed time
2 subscription or service term
```

If `use` is `1`, `use_until` is required.

If `use` is `0`, `use_until` must not be present.

A later profile can define more detail for subscriptions without changing what `permanent` means.

### Offline values

```text
0 no offline core use
1 full offline core use after valid setup
2 partial offline use
```

If `offline` is `2`, `service_dependencies` should explain the important online dependencies.

## Critical fields

The optional `critical` array lists payload labels that a verifier must understand before accepting the deed.

If a verifier sees a critical label it does not understand, verification fails.

Unknown non-critical fields may be ignored if their encoding is otherwise valid.

This rule lets DADE extend deeds without making old verifiers guess about fields that change ownership meaning.

## Terms binding

`terms_sha256` is the SHA-256 digest of the exact ownership terms bound to the deed at issuance.

The terms document is separate from the deed payload so the deed stays small.

If `terms_uri` is present, it is a location where the terms may be retrieved. The URI is a convenience. The digest is the signed binding.

A verifier must not assume that content later downloaded from `terms_uri` is authentic unless its SHA-256 digest matches `terms_sha256`.

The terms should be archived with permanent products when practical.

## Asset IDs

This draft keeps `asset_id` as a bounded text string instead of creating a central DADE product registry.

The final naming rules are still open.

A reverse-domain style value is a reasonable example:

```text
com.pajic.vice
```

The exact syntax will be frozen before DADE 1 conformance testing.

## Limits

The first parser profile should enforce conservative limits.

Proposed limits:

```text
COSE object                 64 KiB max
CBOR nesting                8 levels max
asset_id                    255 UTF-8 bytes max
terms_uri                   2048 UTF-8 bytes max
edition                     128 UTF-8 bytes max
platform entry              32 UTF-8 bytes max
service dependency entry    128 UTF-8 bytes max
platform entries            32 max
service dependency entries  32 max
critical labels             32 max
```

These limits are there to make parsing predictable and reduce denial-of-service risk.

## Deterministic encoding

The payload must follow the core deterministic encoding requirements in RFC 8949.

DADE 1 additionally forbids floating-point numbers in the core deed payload.

Encoders must use definite-length maps and arrays.

Duplicate map keys are invalid.

## Exported file

The proposed portable deed file extension is:

```text
.ddc
```

`ddc` stands for Digital Deed Certificate.

The file contains the binary tagged COSE_Sign1 object. It is not JSON and it is not a ZIP archive.

This extension is still draft until the first format release.

## Example decoded payload

This is a diagnostic view, not the bytes stored in a `.ddc` file.

```text
{
  1: 1,
  2: h'00112233445566778899aabbccddeeff',
  3: "com.pajic.vice",
  4: h'10000000000000000000000000000001',
  5: h'20000000000000000000000000000001',
  6: {
    1: 0,
    2: 1,
    3: true,
    4: true,
    5: true,
    6: true,
    7: ["windows", "macos"]
  },
  7: 1792782000,
  8: h'0000000000000000000000000000000000000000000000000000000000000000',
  9: "https://example.invalid/terms/vice-1",
  10: "standard"
}
```

The zero terms digest in this example is a placeholder and must never appear in a real test vector.

## Not defined here

This document does not define:

- how owner IDs bind to owner keys
- how device authorization works
- how ownership transfer invalidates the old state
- how lending works
- how recovery works
- how issuer trust anchors are distributed

Those are separate protocol layers.
