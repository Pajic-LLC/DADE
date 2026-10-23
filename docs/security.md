# Security model

This file describes the security goals for DADE 1. It does not lock in the final cryptographic design.

## What DADE needs to protect

DADE should protect four things:

1. A deed cannot be forged by someone who is not an authorized issuer.
2. A person cannot claim ownership of a deed they do not control.
3. A transfer cannot create two legitimate current owners.
4. Normal offline use should not depend on a central server being available.

## What DADE does not promise

DADE does not promise that digital files can never be copied.

DADE does not promise that a determined attacker can never crack software that runs on hardware they control.

DADE does not promise that a device with no connection to the outside world can learn about an event that happened somewhere else.

Those limits matter. The design should not pretend they do not exist.

## Ownership keys

A DADE identity will use cryptographic keys to prove control.

The final key hierarchy is not fixed yet.

The design should make it possible to use hardware-backed key storage where the platform supports it. Private ownership keys should not be exposed to normal application code when that can be avoided.

## Device keys

A device should have its own key rather than receiving a copy of an owner's main private key.

A device authorization should be bound to that device key. Copying the authorization file alone should not make another computer trusted.

Where supported, device keys should use secure hardware such as a Secure Enclave, TPM, or equivalent protected key store.

## Issuer keys

An issuer signs deeds and related ownership records.

Production issuer keys must be treated as high-value secrets. The reference design should support non-exportable keys held by managed key hardware or an HSM.

A compromised issuer key must have a defined rotation and incident process.

## Offline verification

An owned product should be able to verify the information needed for normal offline use without contacting Pajic or a store every time it starts.

That means the verifier needs enough trusted public information locally to decide whether the presented deed and device authorization are valid for that use.

The exact proof format is still open.

## Transfer and offline devices

This is one of the hardest DADE 1 problems.

If a device is completely offline, it cannot learn that a deed was transferred somewhere else after the device went offline.

DADE 1 must choose and document an honest behavior for this case. Possible designs include hardware-backed ownership state, owner-presence proofs, bounded device authorizations, or accepting that an isolated old installation can remain technically usable while no longer representing legitimate ownership.

No option should be presented as perfect if it is not.

Detailed transfer mechanisms may stay private while Pajic reviews possible intellectual property protection.

## Recovery

Recovery cannot be allowed to create a second valid owner by accident.

The security model must explain what happens when every trusted device or key is lost.

A recovery option that depends on Pajic should be clearly described as a convenience service, not as the thing that makes the deed valid.

## Privacy

A deed should use opaque identifiers where possible.

Public ownership proofs should not require a person's legal name, email address, phone number, or store username.

Systems that publish ownership events must avoid turning the protocol into a public list of people's purchases.

## Network security

Online purchase, transfer, lending, recovery, and issuer administration must use current transport security and authenticated requests.

Specific protocol versions and algorithms will be selected in the technical specification after the architecture is stable enough to justify locking them in.

## Secure defaults

The first implementation should prefer secure behavior even when that makes development slower.

Examples:

- no private keys in source control
- no long-lived bearer secrets where a stronger option is practical
- no silent downgrade from hardware-backed storage to plain files
- explicit key rotation
- signed release artifacts
- reproducible test vectors
- clear separation between test and production trust roots
- no security decisions based only on hidden client code

## External review

DADE should not call itself secure because Pajic says so.

Before a production release, the important protocol and implementation pieces should receive independent security review.
