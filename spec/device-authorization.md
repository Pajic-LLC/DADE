# Personal device authorization

A person owns the deed. Their devices only receive permission to use it.

This document defines the first DADE 1 model for approving a personal device.

## Device key

When DADE is set up on a new device, that device creates its own signing key.

The private key should use hardware-backed storage when the platform supports it.

Examples include Secure Enclave, TPM-backed storage, or another protected key store.

The private device key should not be exportable as an ordinary file when the platform can prevent that.

The public key can be shared as part of an authorization request.

## A device means a DADE profile on a device

DADE should not treat a motherboard serial number or advertising identifier as the security identity of a device.

A DADE device key belongs to the person's DADE profile on that machine.

That matters on shared computers where two operating system users may have separate DADE identities.

## Approval flow

A simple approval flow can work like this:

1. The new device creates a device key.
2. It creates a one-time authorization request containing its public key and a random challenge.
3. The new device shows the request as a QR code or sends it over a local authenticated channel.
4. An already trusted DADE controller reads the request.
5. The controller shows the person what is being approved.
6. The person confirms using local authentication such as Face ID, Touch ID, Windows Hello, or a device passcode.
7. The controller signs a device authorization.
8. The new device stores that authorization with its private device key.

A screenshot of the QR code is not an ownership credential.

The QR code is only a request to authorize a particular device public key.

## Device authorization

A device authorization logically contains:

```text
authorization ID
owner ID
device public key
controller ID
allowed scope
issued time
optional expiry
```

The first useful scope is:

```text
use_owned_assets
```

A device with only that scope can use products owned by the identity when each deed also grants the requested use.

It cannot:

- approve another device
- create another controller
- change recovery rules
- sell or gift a deed

Those are owner management actions, not ordinary device use.

## Why the owner key is not copied

The new device does not receive the identity anchor private key.

It receives:

- its own private device key
- the public identity information
- the controller credential
- a signed device authorization

That means copying the authorization file to another computer is not enough.

The other computer would also need the matching private device key.

When the key is hardware-backed and non-exportable, copying the authorization file is useless by itself.

## Local proof on launch

A game that needs proof from an authorized device can issue a fresh random challenge.

The DADE device component signs that challenge with the device key.

The verifier checks:

1. the deed is valid
2. the deed owner ID matches the identity anchor
3. the controller credential is valid for that owner
4. the device authorization was signed by that controller
5. the authorization includes the required scope
6. the device can sign a fresh challenge with the authorized device key
7. the deed grants the requested right for the asset

All of those checks can be performed locally after setup.

## Offline use

A permanent device authorization does not need a periodic network renewal just to remain usable.

If the deed grants permanent offline use, a properly set up device can keep verifying locally.

This is intentional.

## Removing a device

Removing a connected or reachable device is straightforward. DADE can tell that device to destroy or retire its local authorization and key.

A lost device that is permanently offline is harder.

No other device can remotely change state on a machine that receives no information.

DADE 1 must not pretend otherwise.

The future transfer and state model may add stronger rules for this case, especially on platforms with suitable secure hardware.

## Sharing abuse

Cryptography can prove that a controller approved a device.

It cannot prove that the computer physically belongs to the same human without adding more intrusive identity checks.

DADE can use reasonable policy and product rules to discourage mass sharing, but it should not turn permanent ownership into a permanent online check just to make sharing impossible.

A legitimate lending feature should also reduce the need for people to fake another person's computer as their own device.

## Device limits

DADE does not currently freeze a universal personal-device limit.

A hard number such as three devices may be too restrictive for normal ownership.

The eventual policy may include reasonable limits or anti-abuse controls, but those should be separate from the basic ownership model.

## Privacy

A device authorization should not need:

- the person's legal name
- their email address
- their phone number
- their store username
- a hardware serial number visible to the issuer

The authorization needs the cryptographic device key and the owner relationship, not a broad device fingerprint.
