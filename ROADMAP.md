# DADE 1 roadmap

This is the current build order. It will change as the design gets tested.

## Stage A: ownership model

Goal: define what DADE means by ownership before writing a lot of code.

- settle the DADE identity model
- define what a digital deed proves
- define the minimum rights model
- separate owner, issuer, store, and device roles
- write the offline ownership rules
- write the recovery rules
- document the limits we cannot solve perfectly

## Stage B: legal and IP review

Goal: protect the work before publishing technical details that may matter later.

- review DADE name and trademark strategy
- review patentable technical ideas before disclosure
- draft commercial licensing terms
- decide what evaluation and research use will be allowed
- decide contribution terms
- define rules for future DADE certification marks

Stage B can run beside the rest of the early design work, but sensitive implementation details should not be published ahead of that review.

## Stage C: deed format draft

Goal: create the smallest useful deed format.

- identifiers
- issuer information
- owner reference
- asset reference
- rights
- timestamps and versioning
- signatures
- canonical encoding
- exported deed format, if needed
- three-character file extension, if needed
- test vectors

## Stage D: local verifier

Goal: prove that an owned product can verify a deed without calling a Pajic server.

- parse a deed
- verify issuer signature
- verify asset match
- verify ownership proof
- verify device authorization
- return a small result the application can understand
- support a fully offline test path

## Stage E: identity and devices

Goal: let one person use owned products across their own devices without turning each device into a separate owner.

- create a DADE identity
- enroll a second device
- remove a device
- protect device keys
- test hardware-backed keys where available
- design behavior for platforms without secure hardware
- test abuse cases around device sharing

## Stage F: issuance

Goal: issue real deeds for a test asset.

- issuer key setup
- test issuer
- deed issuance
- receipt linkage without making the receipt the ownership source
- key rotation
- test and production trust separation

## Stage G: first Pajic game integration

Goal: ship a real vertical slice.

- purchase test
- deed issuance
- install
- offline launch
- second-device setup
- archived reinstall test
- store account deletion test
- service outage test

The vertical slice should prove that normal use survives without a live DADE service.

## Stage H: transfer and gifting

Goal: move ownership from one DADE identity to another without creating two legitimate owners.

This is one of the areas most likely to need private design work and IP review before full publication.

- transfer authorization
- old-owner relinquishment
- new-owner acceptance
- replay protection
- rollback resistance
- offline-device behavior
- audit history

## Stage I: lending

Goal: support a real loan instead of account sharing.

- temporary borrower authority
- owner rules during a loan
- return flow
- expiration behavior
- offline behavior
- lost borrower device behavior

## Stage J: recovery

Goal: recover access without casually duplicating ownership.

- device loss
- identity recovery
- optional provider-assisted recovery
- stronger self-custody mode
- recovery after long offline periods
- recovery abuse tests

## Stage K: third-party developer preview

Goal: let another developer integrate DADE without needing internal Pajic knowledge.

- clean SDK boundary
- verifier library
- issuer tooling
- documentation
- compatibility tests
- example integration
- commercial license process

## Stage L: DADE 1 production release

Goal: freeze a real version only after the system has been tested.

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
