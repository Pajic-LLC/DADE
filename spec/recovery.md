# Recovery

DADE 1 recovery restores control of the same owner identity.

It does not create a replacement owner.

## The rule

A recovered owner must have the same `owner_id` as before recovery.

Existing deeds must not need to be reissued just because a phone, computer, or controller was lost.

DADE 1 therefore uses credential continuity for the first recovery profile.

The owner anchor is restored from protected recovery material. Once restored, it can authorize new controller credentials for the same owner identity.

## What recovery restores

Recovery restores the owner anchor private key.

The owner anchor is the root of the DADE owner identity. Its public key determines the `owner_id` used by deeds.

A recovered anchor must derive the same `owner_id` as the original anchor.

If it does not, recovery has failed.

## Recovery bundle

DADE 1 defines a portable encrypted recovery bundle.

The bundle contains the minimum private material needed to restore the owner anchor. The private material is encrypted before it leaves the device creating the backup.

The first recovery profile uses:

- AES-256-GCM
- a random 256-bit recovery secret
- a random 96-bit nonce
- deterministic CBOR for the bundle container
- the owner ID as authenticated associated data

The recovery secret is not stored inside the bundle.

A copied bundle by itself must not be enough to recover ownership.

## Recovery secret

The recovery secret is 32 random bytes.

It is not a password and must not be derived directly from a normal human password.

User-facing software may later encode the recovery secret as words, a QR code, a hardware token, or another recovery method. Those are presentation and storage choices around the same cryptographic secret.

DADE core does not require Pajic to hold the recovery secret.

## Optional provider storage

A provider may store the encrypted recovery bundle for convenience.

That provider must not need the plaintext owner anchor or the recovery secret just to store the bundle.

This means a Pajic account can help somebody find their encrypted backup without becoming the owner of the digital property.

Provider-assisted storage is optional.

A person can instead keep the recovery bundle and recovery secret entirely on their own.

## Keep the parts separate

The recovery bundle and recovery secret should not normally be stored together in the same unprotected location.

Anyone who obtains both can restore the owner anchor and gain owner-level authority.

DADE cannot make a stolen complete recovery set harmless.

## Lost controller

Losing a controller is not the same as losing ownership.

If another trusted controller is still available, normal device management can continue without using the recovery bundle.

If no usable controller remains, the owner can restore the anchor and issue a new controller credential.

## Old controllers after recovery

Recovery does not magically erase an old controller that is offline somewhere else.

A controller credential that was valid before recovery can remain cryptographically valid to a verifier that has never received newer revocation information.

That is a real offline limitation.

DADE must not pretend otherwise.

Controller revocation and trust updates are separate work. Recovery restores control. It does not claim instant remote revocation of unreachable credentials.

## No silent second owner

Recovery must never generate a fresh unrelated owner anchor and call it the same ownership.

That would create a new `owner_id` and break the deed chain.

The recovery flow must verify that the restored anchor derives exactly the owner ID recorded by the recovery bundle and expected by the user's deeds.

## No magical reset

If every controller is gone, the owner anchor is gone, the recovery bundle is gone, and every copy of the recovery secret is gone, DADE has no secret back door that can recreate ownership authority.

That is a consequence of making ownership independent from a permanent central account provider.

Products may offer optional managed recovery services, but those services must be explicit and must not silently turn a provider account into the real owner.

## Portable file

The first draft uses `.drb` for an exported DADE Recovery Bundle.

The extension is three characters by design.

Applications should normally present this as a recovery backup rather than exposing the file extension to everyday users.

## Not covered here

This stage does not define:

- controller revocation distribution
- transfer or resale invalidation
- lending state
- inheritance
- social recovery policy
- password-derived recovery secrets
- cloud account recovery rules

Those can build on this recovery primitive later.
