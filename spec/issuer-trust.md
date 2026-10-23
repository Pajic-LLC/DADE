# Issuer trust

DADE needs to answer one more question before a deed can be trusted offline:

> Does this signing key actually belong to the issuer named in the deed?

A valid signature alone is not enough. Anyone can create a key and sign a file.

DADE separates a stable issuer identity from the signing keys used day to day.

## The trust chain

The first DADE 1 issuer model uses this chain:

```text
Issuer root
    |
    | signs
    v
Signing credential
    |
    | authorizes
    v
Signing key
    |
    | signs
    v
Digital deed
```

The issuer root identifies the issuer.

The signing key does the routine deed signing.

That lets an issuer replace a signing key without changing its identity or rewriting old deeds.

## Issuer root

An issuer root is a long-lived P-256 public key.

DADE derives the issuer ID from the canonical public COSE_Key for that root:

```text
SHA-256("DADE1-ISSUER\0" || canonical_cose_key)
```

The first 16 bytes are the issuer ID used by DADE 1.

The root private key should not be used for routine deed issuance.

A production issuer should keep the root private key offline or in strongly protected signing hardware. DADE does not require one vendor or one HSM product.

## Signing credential

A signing credential is a root-signed statement authorizing one signing key for one issuer.

It contains:

- credential version
- credential ID
- issuer ID
- signing key ID
- signing public key
- valid-from time
- valid-until time

The credential is signed by the issuer root with COSE_Sign1.

A deed verifier checks that:

1. the locally trusted root derives to the issuer ID in the deed
2. the root signed the signing credential
3. the credential names the same issuer
4. the credential contains the signing key that signed the deed
5. the deed was issued while that signing credential was valid
6. the deed signature is valid

## Rotation

Signing keys are expected to rotate.

Rotation does not change the issuer ID.

The issuer creates a new signing key and signs a new signing credential with the same root.

Old deeds remain verifiable with the old credential and key.

New deeds use the new credential and key.

A verifier does not treat the newest key as the only valid historical key.

## Expiration

Signing credential expiration limits when a key may issue new deeds.

It does not automatically make every deed signed by that key stop working after the credential expires.

For an existing deed, the important question is whether its signed `issued_at` value falls inside the signing credential's allowed issuance window.

This keeps a permanent deed usable years after the publisher has rotated away from the original signing key.

## Compromise

Offline systems cannot learn new facts by magic.

If a signing key is compromised today, a computer that has been permanently disconnected since yesterday cannot know that until it receives updated trust information.

DADE must not pretend otherwise.

A future trust-update object can carry compromise or revocation information. Once that update reaches a verifier, it can reject deeds issued after a declared compromise point while preserving earlier deeds when policy allows it.

The first Stage E implementation proves root trust and key rotation. A full signed revocation format is separate work.

## Root rotation

Changing the issuer root is much more serious than changing a signing key because the issuer ID is derived from the root.

DADE 1 does not silently replace an issuer root.

A future root migration format must explicitly link the old trusted identity to the new root and define what happens if the old root is unavailable or compromised.

Until that format exists, changing the root creates a new issuer identity.

## Offline trust material

An offline verifier needs enough local material to verify the chain.

For the first model that means:

- the issuer root public key, or a trusted bundle containing it
- the root-signed signing credential used by the deed
- the deed itself

No live Pajic API is required for normal verification.

Applications can ship trusted issuer roots with the product, import them from a DADE trust bundle, or receive them through another authenticated update path.

How a general-purpose DADE trust bundle is distributed is separate from the cryptographic issuer model.

## Display names

`Pajic Studios` is a display name.

It is not the issuer's cryptographic identity.

A display name can change while the issuer ID stays the same.

User interfaces may show a friendly publisher name next to a verified issuer ID, but security decisions must use the cryptographic issuer identity.

## Current limits

This draft does not yet define:

- the final trust-bundle format
- signing-key revocation objects
- issuer root migration
- public certification policy
- commercial DADE certification
- transfer, lending, or owner recovery

Those are separate layers.