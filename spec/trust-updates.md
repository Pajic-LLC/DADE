# Trust updates

DADE does not require a permanent online revocation service.

A verifier works with the newest signed trust state it has actually received.

If a machine stays offline forever, it cannot learn about a later compromise or lost device. DADE does not pretend otherwise.

## Snapshot model

DADE 1 uses signed trust snapshots instead of unsigned blocklists or mandatory online checks.

A snapshot describes the current trust state for one authority domain and carries a monotonically increasing sequence number.

There are two public trust domains in this draft:

- owner trust, signed by the owner anchor
- issuer trust, signed by the issuer root

A verifier that has securely remembered sequence 12 must reject a snapshot with sequence 11.

A verifier that has never seen sequence 12 cannot know that it exists while offline.

## Owner trust snapshot

An owner trust snapshot is signed by the owner anchor.

It contains:

1. snapshot version
2. owner ID
3. sequence number
4. issued time
5. revoked controller entries

Each revoked controller entry contains:

1. controller ID
2. revoked time

Once a verifier accepts a snapshot that lists a controller as revoked, any ownership chain through that controller must fail.

This is deliberately strong revocation. Devices that were authorized through that controller must be authorized again through a controller that is still trusted.

Revoking a controller does not change the owner ID and does not rewrite any deeds.

## Issuer trust snapshot

An issuer trust snapshot is signed by the issuer root.

It contains:

1. snapshot version
2. issuer ID
3. sequence number
4. issued time
5. signing-key revocation entries

Each signing-key revocation entry contains:

1. signing key ID
2. reject-from time

A deed signed by that key is rejected when its `issued_at` value is equal to or later than the reject-from time.

This lets an issuer preserve deeds that were issued before a known compromise window.

If the whole signing key must be treated as untrusted, the reject-from value can be zero.

Routine key rotation is not revocation. A normally retired signing key can continue to verify old deeds that were issued inside its signing credential window.

## Sequence numbers

Sequence numbers start at zero or greater and increase whenever a new trust snapshot replaces an older one.

A verifier should securely remember the highest accepted sequence number for each trust domain where the platform makes that possible.

Examples include hardware-backed secure storage, TPM state, Secure Enclave related application state, or another rollback-resistant local mechanism.

The DADE protocol does not require one specific hardware feature.

Without rollback-resistant storage, a verifier can still validate signatures but cannot always tell whether local trust state was rolled back to an older signed snapshot.

## Distribution

Trust snapshots are portable signed objects.

They can arrive through:

- a game or application update
- a store update
- an operating system update
- a DADE-compatible wallet
- direct device-to-device sync
- removable media
- a publisher or issuer download
- a Pajic service

Pajic is not required to be the only distributor.

The signature, not the transport, establishes authenticity.

## Offline behavior

No trust snapshot has an expiry time that forces a permanent owner back online just to keep using owned content.

A verifier uses the newest valid snapshot it knows about.

If no newer snapshot is available, normal offline use continues under the last known trusted state.

This is a deliberate ownership property, not a networking bug.

## Recovery

After recovery, the same owner anchor can publish a newer owner trust snapshot that revokes a lost controller.

Devices that receive that newer snapshot will reject the lost controller.

Devices that remain permanently offline with older trust state may continue accepting it until they receive a newer snapshot.

## Not ownership transfer

Trust updates are not the sale, gift, lending, or transfer mechanism.

They deal with compromised trust relationships inside the existing ownership state.

The transfer design remains separate and behind the DADE IP review gate.
