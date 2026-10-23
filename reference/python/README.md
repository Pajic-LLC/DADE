# Python reference verifier

This is an early DADE 1 conformance harness.

It exists to prove the draft formats and test vectors. It is not the production DADE SDK.

## Deed verification

From this directory:

```text
python -m pip install -r requirements.txt
python dade_verify.py ../../test-vectors/valid-deed.hex ../../test-vectors/issuer-public-key.pem --asset com.pajic.vice
```

Expected output:

```text
valid: com.pajic.vice
```

The tampered vector must fail:

```text
python dade_verify.py ../../test-vectors/invalid-tampered-asset.hex ../../test-vectors/issuer-public-key.pem
```

## Issuer trust

`dade_issuer.py` adds the issuer layer above deed signature verification.

The issuer test chain covers:

```text
trusted issuer root
        |
        v
root-signed signing credential
        |
        v
authorized deed signing key
        |
        v
signed digital deed
```

Signing-key rotation keeps the same issuer identity because the issuer ID is derived from the long-lived root, not the routine signing key.

An old deed remains valid after rotation when it was issued inside the old signing credential's allowed issuance window.

## Identity and device chain

`dade_identity.py` verifies the owner and personal device layers after the deed itself has been verified.

The identity test chain covers:

```text
publisher-signed deed
        |
        v
owner anchor
        |
        v
controller credential
        |
        v
device authorization
        |
        v
fresh device proof
```

Every step can be checked from local files and public keys.

No Pajic API or other network request is used by the tests.

## Tests

```text
python -m unittest discover -v -p "test_*.py"
```

The tests cover:

- valid deed verification
- signed deed tampering
- asset mismatch
- old deed verification after signing-key rotation
- new signing key under the same issuer identity
- wrong issuer root
- deed issuance outside a signing credential window
- valid owner and device chain
- wrong identity anchor
- wrong launch challenge

## Scope

The reference verifier currently checks:

- tagged COSE_Sign1 structure
- protected ES256 algorithm headers
- P-256 public keys
- key IDs
- COSE signatures
- deterministic CBOR payloads
- required deed fields
- field sizes and types
- core rights values
- critical field handling
- expected asset matching
- issuer ID derivation from a trusted issuer root
- root-signed signing credentials
- signing-key validity windows
- signing-key rotation under one issuer identity
- owner ID derivation from the identity anchor
- anchor-signed controller credentials
- controller scope
- controller ID derivation
- controller-signed device authorization
- device scope
- device ID derivation
- fresh device proof signatures
- challenge, asset, right, owner, and device binding

It does not yet check:

- issuer revocation updates
- issuer root migration
- transfer state
- lending state
- recovery state

Those are separate layers of DADE.
