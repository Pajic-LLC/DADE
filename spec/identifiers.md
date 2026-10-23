# Identifiers

DADE needs stable identifiers for deeds, assets, issuers, owners, controllers, and devices.

## General rules

Identifiers should be:

- stable
- safe to compare as exact values
- independent from display names
- free of personal information unless there is a strong reason otherwise
- usable without contacting Pajic

An identifier should not become invalid just because someone changes their email address, username, company name, or device name.

## Deed ID

Every deed needs a globally unique identifier.

The deed ID identifies the deed itself, not the owner or asset.

The first wire-format draft uses a 16-byte value.

## Asset ID

The asset ID identifies the digital product covered by the deed.

The same asset ID should continue to refer to the same owned product across normal software updates.

A publisher can use separate asset IDs when there is a real ownership difference, such as:

- standard edition
- deluxe edition
- separately owned expansion
- separately owned soundtrack

An update from version 1.2 to 1.3 should normally not create a new asset ID.

## Issuer ID

The issuer ID identifies the party authorized to issue deeds for an asset.

The issuer ID must be resolvable to trusted public verification material without requiring a person's private account information.

Display names can change without changing the underlying issuer identity.

The first wire-format draft uses a 16-byte value. The final issuer trust and identifier construction are still open.

## Owner ID

The owner ID identifies a DADE identity.

The first DADE 1 identity draft derives this 16-byte value from the identity anchor public key.

The construction is defined in [identity-credentials.md](identity-credentials.md).

That lets a verifier confirm locally that a presented anchor public key belongs to the owner ID signed into a deed.

The owner ID does not contain a legal name, email address, phone number, store username, or device serial number.

It remains the same when the person:

- changes email address
- changes store account
- replaces a phone
- replaces a computer
- changes a display name

Changing the identity anchor itself is a separate recovery or identity-migration problem and is not defined yet.

## Controller ID

A controller ID identifies a controller public key authorized by a DADE identity.

The first draft derives a 16-byte controller ID from the controller public key using a DADE-specific hash prefix.

A controller can approve actions only within the scopes granted by its credential.

## Device ID

A device ID identifies one DADE device public key.

The first draft derives a 16-byte device ID from that public key using a DADE-specific hash prefix.

A friendly name such as `Gaming PC` is metadata, not the security identity.

Where supported, the private device key should use hardware-backed storage so it cannot simply be copied to another machine.

## Do not overload identifiers

An identifier should identify one kind of thing.

Bad:

```text
leon@example.com
```

That could be treated as an account name, contact address, identity, or recovery route depending on context.

Better:

```text
owner_id: <DADE owner identifier>
email: <optional account metadata somewhere else>
```

Keeping those separate makes ownership less dependent on one provider.

## Human-readable names

Applications can show friendly names beside DADE identifiers.

Examples:

```text
Pajic Studios
VICE
Leon's Gaming PC
```

Those names are for people. They should not be used as the cryptographic identity of the issuer, asset, owner, controller, or device.
