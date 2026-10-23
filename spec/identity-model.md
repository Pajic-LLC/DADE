# DADE identity model

This document defines the first public DADE 1 identity model.

The goal is to answer one question clearly:

> What does it mean when a deed says that you own something?

## The short answer

A DADE identity is anchored to a cryptographic public key.

The deed names the identity, not a Pajic account, email address, legal name, phone number, or device.

The person proves control of the identity through keys that the identity has authorized.

## Identity anchor

Every DADE identity starts with an identity anchor key.

The first DADE 1 profile uses a P-256 public key for the anchor.

The private half is high-value ownership material. Ordinary games and applications should never receive it.

The anchor exists to establish the identity and authorize lower-level controller keys.

It should not need to sign every game launch.

## Owner ID

The owner ID in a deed is derived from the identity anchor public key.

For the first draft:

```text
owner_id = first 16 bytes of SHA-256(
  "DADE1 owner" || canonical public anchor key
)
```

The exact canonical COSE_Key representation will be defined with the identity wire format.

This makes the owner ID self-certifying.

A verifier can receive the public anchor key, derive the owner ID, and compare it to the owner ID signed into the deed.

Someone cannot claim the same owner ID with another key without finding a cryptographic preimage collision against the identifier construction.

## Why the deed does not contain a name

A person can change their:

- name
- email address
- phone number
- store account
- device

None of those changes should rewrite every deed they own.

DADE therefore treats names and accounts as optional metadata around the identity, not as the identity itself.

## Controller keys

The anchor key should not be used for routine work.

Instead, the identity can authorize one or more controller keys.

A controller key can be allowed to do specific owner actions such as:

- approve a personal device
- remove a device when that device can receive the change
- approve an owner proof for a local setup

The first implementation should keep controller authority narrow.

A controller does not automatically gain authority to transfer ownership, change recovery rules, or create another controller unless its credential explicitly grants that scope.

## Controller credential

A controller credential is signed by the identity anchor.

Logically it contains:

```text
owner ID
controller public key
controller ID
allowed scopes
issued time
optional expiry
```

A verifier can check:

1. the controller credential was signed by the anchor key
2. the anchor key derives the owner ID named in the deed
3. the controller has the scope needed for the action

The final binary labels will be defined separately.

## Local authentication is not the identity

Face ID, Touch ID, Windows Hello, a device passcode, or a passkey can be used to confirm that the person intends to approve an action.

Those are user authentication methods.

They are not the DADE owner ID and they are not the digital deed.

For example:

```text
Scan QR code
Face ID confirms the person is present
DADE controller key signs the device approval
```

The cryptographic DADE signature is what another DADE verifier checks.

Face ID is what the local device can use before allowing that signature.

Keeping those jobs separate avoids making DADE ownership depend on one account provider or biometric system.

## More than one controller

A person may eventually want more than one controller device.

For example:

```text
DADE identity
    |
    +-- iPhone controller
    +-- Mac controller
    +-- hardware key controller
```

That can improve resilience if one device is lost.

The exact rules for adding controllers and recovering after all controllers are lost are not final yet.

## Recovery

Recovery is intentionally not solved by saying "Pajic can reset it."

If Pajic can replace the owner key whenever it wants, Pajic is still the real authority.

The identity model must leave room for recovery methods that the owner controls.

Possible future recovery methods include encrypted recovery material, multiple recovery keys, or threshold recovery.

The final recovery protocol is separate work.

## What must be available offline

A device that is already set up for permanent offline use needs enough local information to verify the identity chain.

That can include:

- the identity anchor public key
- the controller credential used to authorize the device
- the device authorization
- the public issuer information needed to verify the deed

None of those require the identity anchor private key to be handed to the game.

## What this model does not solve

This model does not claim that an offline device can learn about a later event somewhere else.

It also does not prevent the owner from deliberately approving another person's device and pretending it is personal.

Those are separate anti-abuse and state-change problems.

DADE should be honest about them instead of weakening permanent offline ownership with hidden periodic checks.
