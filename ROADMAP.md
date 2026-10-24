# DADE 1 roadmap

This roadmap matches the work that has actually shipped in the repository. DADE 1 is still a draft and the order can change as testing exposes problems.

## Stage A: ownership model

Status: complete as a draft.

Goal: define what DADE means by ownership before freezing protocol details.

Completed work includes:

- DADE identity and owner roles
- digital deed meaning
- minimum rights model
- separation of owner, issuer, store, and device roles
- permanent offline ownership rules
- documented technical limits

## Stage B: legal and IP review

Status: open release gate.

Goal: protect the work before publishing sensitive transfer and invalidation details or offering production licensing.

Still required:

- DADE trademark review
- patent review before sensitive disclosure
- commercial licensing terms
- evaluation and research terms
- contribution terms
- future certification mark rules

Stage B can run beside engineering work, but transfer and gifting details remain behind this gate.

## Stage C: deed wire format

Status: complete as a draft.

Goal: define a portable signed deed format and prove it with test vectors.

Completed work includes:

- deterministic CBOR payloads
- COSE_Sign1 signatures
- ES256 with P-256
- identifiers and field rules
- rights representation
- parser limits and critical-field handling
- `.ddc` as the draft portable deed extension
- valid and tampered test vectors
- Python reference verification

## Stage D: owner control and personal devices

Status: complete as a reference implementation.

Goal: prove that the deed owner controls the DADE identity and can authorize personal devices without copying the owner key into application code.

Completed work includes:

- owner anchor identity
- controller credentials
- personal device authorizations
- fresh device launch proofs
- offline owner and device verification
- negative tests for wrong owners and challenges

## Stage E: issuer trust and signing-key rotation

Status: complete as a reference implementation.

Goal: separate stable issuer identity from routine deed signing keys.

Completed work includes:

- issuer root identity
- root-signed signing credentials
- signing-key validity windows
- normal key rotation without changing issuer identity
- offline issuer-chain verification
- preservation of old valid deeds after routine rotation

## Stage F: recovery

Status: complete as a reference implementation.

Goal: recover the same owner identity without creating a replacement owner.

Completed work includes:

- encrypted recovery bundles
- a separate recovery secret
- owner continuity checks
- restoration of the same owner anchor
- fresh controller issuance after recovery
- wrong-secret and tamper tests
- `.drb` as the draft recovery bundle extension

## Stage G: signed trust updates

Status: complete as a reference implementation.

Goal: let verifiers learn about later controller revocations and issuer key compromise without requiring periodic online activation.

Completed work includes:

- signed owner trust snapshots
- signed issuer trust snapshots
- monotonic trust sequence numbers
- rollback rejection when newer state is remembered
- controller revocation
- issuer signing-key compromise cutoffs
- preservation of deeds issued before a known compromise cutoff

## Stage H: application verification API

Status: complete as a reference implementation.

Goal: give applications one small local ownership decision instead of exposing protocol internals.

Completed work includes:

- a `can_use` reference path
- stable application decision codes
- issuer, deed, owner, controller, device, rights, and trust-state checks in one path
- fail-closed behavior for unsupported proof material
- end-to-end decision tests

## Stage I: native VICE provider

Status: complete.

Goal: back the VICE launch gate with a native DADE implementation.

Completed work includes:

- Rust `cdylib` provider
- stable VICE provider ABI
- native deterministic CBOR, COSE_Sign1, and P-256 verification
- issuer, deed, owner, controller, device, rights, and trust-state verification
- fresh launch challenges
- provider-owned device signing boundary
- Python-generated cross-language conformance fixtures
- macOS ARM64 and Windows x64 CI
- VICE packaging helper

The current reference device signer still uses a PKCS#8 key in the local DADE store. The VICE integration also still relies on a loose `dade.asset` marker. Those are development boundaries, not final retail protection.

## Stage J: retail VICE vertical slice

Status: active. See [issue #24](https://github.com/Pajic-LLC/DADE/issues/24).

Goal: prove DADE in a retail-style packaged VICE title instead of only through reference fixtures.

Current work:

- bind the DADE asset ID to signed or integrity-protected shipping metadata
- remove the loose sidecar as the sole retail enforcement point
- add hardware-backed device signing where supported
- use Secure Enclave on macOS and TPM-backed signing on Windows without changing the VICE ABI
- issue a real test deed for one VICE asset
- package the native provider with the test title
- test offline launch and archived reinstall
- test a second authorized personal device
- test controller revocation and trust rollback
- keep macOS ARM64 and Windows x64 coverage

## Stage K: transfer and gifting

Status: blocked by Stage B before sensitive design is published.

Goal: move ownership from one DADE identity to another without leaving two legitimate owners.

Planned work includes:

- transfer authorization
- old-owner relinquishment
- new-owner acceptance
- replay protection
- rollback resistance
- offline-device behavior
- audit history

## Stage L: lending

Status: planned.

Goal: support a real temporary loan instead of account sharing.

Planned work includes:

- temporary borrower authority
- owner rules during a loan
- return flow
- expiration behavior
- offline behavior
- lost borrower device behavior

## Stage M: third-party developer preview

Status: planned.

Goal: let another developer integrate DADE without needing internal Pajic knowledge.

Planned work includes:

- clean SDK boundary
- verifier library
- issuer tooling
- developer documentation
- compatibility tests
- example integration
- commercial license process

## Stage N: DADE 1 production release

Status: planned.

Goal: freeze DADE 1 only after the system has been tested outside the reference environment.

Required work includes:

- external security review
- conformance suite
- final specification
- final licensing terms
- release signing
- migration rules
- long-term verification plan

## Later: DADE 2

DADE 2 is reserved for a future version built with major platform and hardware companies if DADE earns that opportunity.

The aim would be native operating system and secure hardware support for ownership, device approval, lending, gifting, sale, and transfer.

DADE 1 has to prove the idea first.
