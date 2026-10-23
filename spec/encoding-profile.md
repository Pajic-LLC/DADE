# Encoding and signature profile

This document proposes the first technical encoding profile for DADE 1.

It is a draft. It can still change before the first conformance release.

## Goals

The first DADE encoding should be:

- compact
- deterministic
- easy to sign
- easy to verify offline
- supported by mature libraries
- suitable for desktop, mobile, console, and embedded use
- independent from Pajic infrastructure

DADE should not invent its own cryptography or binary serialization format.

## Deed payload: deterministic CBOR

The first DADE 1 deed payload should use CBOR as defined by RFC 8949.

DADE should require deterministic encoding for signed payloads.

For the first profile:

- use preferred serialization
- use definite-length arrays and maps
- reject duplicate map keys
- sort map keys according to the deterministic encoding rules
- do not use floating-point values in the core deed format
- reject values outside the limits defined by the DADE schema

Using deterministic CBOR gives the same logical deed one predictable signed byte representation.

## Signature wrapper: COSE_Sign1

A deed issued by one issuer should use COSE_Sign1 as defined by RFC 9052.

The COSE payload contains the deterministic CBOR deed.

The protected header should carry the signature algorithm and key identifier.

The initial profile should use the tagged COSE_Sign1 form so the object identifies itself as signed COSE data.

## First signature algorithm: ES256

The first DADE 1 signature profile should use ECDSA with the NIST P-256 curve and SHA-256, commonly identified as ES256 in COSE.

The reason is practical compatibility.

P-256 is widely implemented, works with common HSMs, is available through Apple Secure Enclave, and is supported by Windows cryptography and TPM-backed key storage.

This does not mean DADE is permanently tied to one algorithm.

The protocol must support algorithm agility so a later DADE version or profile can add another signature algorithm without redefining the deed model.

## What is signed

The issuer signature must cover every field that changes the meaning of the deed.

That includes at least:

- DADE version
- deed ID
- asset ID
- issuer ID
- owner reference
- rights
- issuance time
- terms reference

Unsigned metadata must never be allowed to override or weaken signed ownership data.

## Key identifiers

The COSE protected header should carry a key identifier that lets a verifier select the correct trusted issuer public key.

The key identifier is not the issuer identity by itself.

An issuer can rotate signing keys while keeping the same issuer identity.

The trust and rotation model will be defined separately.

## Owner proof is separate

The issuer signature proves that the deed is genuine.

It does not by itself prove that the person presenting the deed controls the owner identity named in it.

Owner proof is a separate part of DADE and will be defined with the identity and device model.

Keeping these jobs separate makes the verifier easier to reason about:

```text
Issuer signature
= Is this a real deed?

Owner proof
= Does this person control the owner identity?
```

## Parsing rules

A DADE parser should reject:

- malformed CBOR
- duplicate map keys
- indefinite-length values in the signed deed payload
- unsupported protocol versions
- unsupported signature algorithms
- missing required fields
- fields with the wrong type
- values larger than the limits defined by the schema
- unknown critical fields
- invalid COSE structures

Parsers should not try to repair malformed ownership data silently.

## Extensibility

DADE needs room to grow without making old verifiers unsafe.

The wire format should distinguish between:

- optional fields an older verifier may ignore
- critical fields an older verifier must understand

If an unknown field is marked critical, verification must fail instead of guessing.

The exact extension mechanism will be defined with the field registry.

## Exported deed files

DADE may define a portable exported deed file for backup, import, or inspection.

The file extension is not frozen yet.

If a custom extension is used, it will be exactly three characters.

The file should contain the signed COSE object rather than an unsigned JSON representation.

Human-readable tools can decode the file for inspection.

## Why not JSON as the signed format

JSON is useful for examples and debugging, but DADE should not use ordinary JSON as its canonical signed representation.

Equivalent JSON can be serialized in different ways. That creates unnecessary canonicalization rules around whitespace, number formatting, escaping, and key order.

CBOR already has deterministic encoding rules designed for protocols that need predictable byte representations.

## Why not custom crypto

DADE should never define a home-grown signature algorithm, hash function, random number generator, or key agreement scheme.

If the standards we depend on stop being suitable, DADE should move to another reviewed standard.

## Current profile summary

```text
Payload          Deterministic CBOR
Signature object COSE_Sign1
Signature        ECDSA P-256 with SHA-256
Hash             SHA-256 where a standalone digest is needed
Network required No, not for local deed signature verification
```

This profile covers deed encoding and issuer signatures only.

It does not yet define owner identity, device authorization, transfer, lending, recovery, or the final issuer trust store.

## References

- RFC 8949, Concise Binary Object Representation
- RFC 9052, CBOR Object Signing and Encryption structures
- RFC 9053, COSE algorithms
