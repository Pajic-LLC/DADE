# Recovery security requirements

The recovery profile has one job: restore control of the same DADE owner identity without turning a store account or cloud provider into the owner.

## Required properties

A conforming recovery implementation must:

- keep the recovery secret separate from the encrypted recovery bundle
- use a cryptographically secure random recovery secret
- use a fresh nonce for every AES-GCM encryption under the same recovery secret
- authenticate the owner ID with the recovery bundle
- reject any bundle that fails authenticated decryption
- verify that the restored owner anchor derives the expected owner ID
- never treat successful account login by itself as proof of DADE ownership
- never silently replace a missing owner anchor with a new unrelated key

## Provider-assisted storage

A provider can store an encrypted recovery bundle without being able to decrypt it.

That is the preferred shape for ordinary cloud backup.

If a provider offers a stronger managed-recovery service that can help reconstruct the recovery secret, that service is a separate trust choice and must be presented as such.

## Local key handling

The owner anchor is high-value material.

It should not be loaded into ordinary application memory more often or for longer than necessary.

A production implementation should clear temporary private-key material where the platform permits it and should prefer operating-system protected storage for recovery files and secrets.

## Offline limits

Recovery cannot prove that a lost controller was physically destroyed.

A verifier that stays offline forever cannot learn about a later controller revocation event.

The recovery protocol therefore must not claim immediate global invalidation of every old controller.

## Threat model

The recovery bundle is designed to resist:

- theft of the encrypted bundle by itself
- accidental cloud exposure of the encrypted bundle
- modification of the bundle
- substitution of another owner ID
- use of the wrong recovery secret

It does not protect ownership if an attacker gets both the valid recovery bundle and the recovery secret.
