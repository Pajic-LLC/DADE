# Digital deed model

This document defines the first logical shape of a DADE digital deed.

It does not define the final wire format, file extension, signature suite, transfer protocol, or recovery protocol.

The goal is to make the ownership object clear enough that we can build a local verifier next.

## What a deed is

A digital deed is a signed ownership record for one digital asset.

It answers four basic questions:

1. What is the asset?
2. Who issued the deed?
3. Which DADE identity owns it?
4. What rights came with it?

A deed is not a store receipt. A receipt can help prove how the purchase happened, but the receipt is not the ownership object.

A deed is also not a device license. Devices can receive authority to use an owned asset, but the device does not become the owner.

## Required information

A DADE 1 deed should contain the following logical fields.

### Protocol version

Identifies which DADE rules a verifier must use.

Example:

```text
DADE 1 draft
```

The final version syntax is not fixed yet.

### Deed ID

A unique identifier for this deed.

The identifier must not contain a person's name, email address, store username, or other personal information.

### Asset ID

A stable identifier for the product covered by the deed.

The asset ID should not change when the product receives an update.

Different editions or separately owned add-ons can have their own asset IDs when the publisher needs them to represent different ownership rights.

### Issuer ID

Identifies the party that issued the deed.

A verifier must be able to connect this identifier to trusted public verification material.

### Owner ID

Identifies the DADE identity that owns the deed.

This should be an opaque cryptographic identity reference. It should not require a legal name or store account.

### Rights

States what the owner received.

The first DADE 1 rights model is defined in [rights.md](rights.md).

### Issued at

Records when the deed was issued.

This is useful for audit, support, migration, and resolving which version of a policy applied at issuance.

### Terms reference

Binds the deed to the ownership terms that were sold with it.

A publisher should not be able to silently replace those terms later.

The final design may store a digest of the terms, a signed policy identifier, or another stable reference. The exact mechanism is not fixed yet.

### Issuer signature

Proves that the deed was created by the issuer and that the signed fields were not changed afterward.

The final signature format and algorithms are not fixed yet.

## Information that should not be required

A normal deed should not need to contain:

- legal name
- email address
- phone number
- billing address
- store username
- payment card information
- purchase price
- public purchase history

A store or issuer may keep some of that information for its own legal, payment, or support needs. DADE ownership should not depend on putting it inside the deed.

## Useful optional information

Some assets may need more detail.

Possible optional fields include:

- edition
- region rules
- supported platforms
- content bundle identifiers
- publisher metadata
- original store reference
- receipt reference
- service dependencies

Optional fields must not quietly weaken the rights expressed elsewhere in the deed.

## Immutability

The signed deed issued at purchase should be treated as immutable evidence of what was issued.

If ownership later changes, DADE should not rewrite the original issuance record and pretend the earlier state never existed.

The public transfer mechanism is not defined in this document. That work remains behind the legal and IP review gate.

## One asset, one deed, one owner

For the first DADE 1 model, a deed represents one current ownership title for one asset.

That title can authorize more than one personal device without creating more than one owner.

Conceptually:

```text
DADE identity
    |
    v
Digital deed
    |
    +-- personal device
    +-- personal device
    +-- personal device
```

The device authorizations are derived use rights. They are not separate deeds.

## Example logical deed

This example is for discussion only. It is not the DADE wire format.

```json
{
  "protocol": "dade/1-draft",
  "deed_id": "example-deed-001",
  "asset": {
    "id": "example.publisher/game.standard",
    "edition": "standard"
  },
  "issuer": "example-issuer-id",
  "owner": "example-dade-identity",
  "rights": {
    "use": "permanent",
    "offline": true,
    "personal_devices": true,
    "gift": true,
    "resale": true,
    "lend": true,
    "platforms": ["windows", "macos"]
  },
  "issued_at": "2026-10-23T19:00:00Z",
  "terms": "example-terms-reference",
  "signature": "not-a-real-signature"
}
```

Real deeds must use a canonical signed representation. Ordinary JSON is shown here only because it is easy to read.

## Design checks

Before a field becomes part of the final deed format, ask:

- Does a verifier actually need it?
- Does it expose personal information for no good reason?
- Could it change over time even though the deed should remain stable?
- Does putting it in the deed create a dependency on one store or provider?
- Can a verifier understand it years later?

If a field fails those checks, it probably belongs somewhere else.
