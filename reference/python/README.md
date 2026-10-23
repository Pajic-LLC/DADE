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

## Recovery

`dade_recovery.py` implements the first recovery profile.

It creates an encrypted recovery bundle using AES-256-GCM and a separate random 32-byte recovery secret.

A valid recovery restores the exact same owner anchor. That means the derived owner ID stays unchanged and existing deeds do not need to be reissued.

The tests also prove that the recovered anchor can issue a fresh controller credential for the same owner identity.

A wrong recovery secret or a tampered recovery bundle must fail authentication.

Recovery does not claim that an old controller can be remotely erased while it is offline.

## Trust updates

`dade_trust.py` verifies signed trust snapshots after recovery or a later compromise event.

Owner trust snapshots are signed by the owner anchor. They carry a sequence number and a list of revoked controller IDs.

Issuer trust snapshots are signed by the issuer root. They carry a sequence number and signing-key compromise cutoffs.

The verifier can reject an older snapshot once it securely remembers a newer sequence number.

A compromise cutoff preserves deeds issued before the cutoff and rejects deeds issued by that key at or after the cutoff.

The verifier still does not pretend that a permanently offline machine can know about a snapshot it has never received.

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
- recovery of the same owner identity
- controller authorization after recovery
- wrong recovery secrets
- tampered recovery bundles
- tampered recovery owner IDs
- controller revocation snapshots
- owner trust rollback rejection
- issuer compromise cutoffs
- issuer trust rollback rejection
- wrong trust-snapshot signing authorities

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
- encrypted owner-anchor recovery bundles
- recovery owner-ID continuity
- recovery bundle authentication
- owner trust snapshot signatures
- issuer trust snapshot signatures
- trust snapshot sequence rollback checks
- controller revocation state
- signing-key compromise cutoffs

It does not yet check:

- issuer root migration
- transfer state
- lending state
- inheritance
- managed or social recovery policy

Those are separate layers of DADE.
