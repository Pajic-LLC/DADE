# Python reference verifier

This is an early DADE 1 conformance harness.

It exists to prove the draft deed format and test vectors. It is not the production DADE SDK.

## Run it

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

## Tests

```text
python -m unittest -v test_dade_verify.py
```

## Scope

The verifier currently checks:

- tagged COSE_Sign1 structure
- protected ES256 algorithm header
- issuer key ID
- P-256 issuer public key
- COSE signature
- deterministic CBOR payload
- required deed fields
- field sizes and types
- core rights values
- critical field handling
- expected asset matching

It does not yet check:

- owner proof
- device authorization
- issuer trust chains
- transfer state
- lending state
- recovery state

Those are separate layers of DADE.
