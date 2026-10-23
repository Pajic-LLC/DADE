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

No Pajic API or other network request is used by the test.

## Tests

```text
python -m unittest discover -v -p "test_*.py"
```

The tests cover:

- valid deed verification
- signed deed tampering
- asset mismatch
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

- issuer trust chains
- transfer state
- lending state
- recovery state

Those are separate layers of DADE.
