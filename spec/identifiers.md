# Identifiers

DADE needs stable identifiers for deeds, assets, issuers, owners, and devices.

This document defines the first rules for those identifiers without freezing their final encoded syntax.

## General rules

Identifiers should be:

- stable
- opaque where possible
- safe to compare as exact values
- independent from display names
- free of personal information unless there is a strong reason otherwise
- usable without contacting Pajic

An identifier should not become invalid just because someone changes their email address, username, company name, or device name.

## Deed ID

Every deed needs a globally unique identifier.

The deed ID identifies the deed itself, not the owner or asset.

Changing ownership must not require reusing another deed's identifier.

The final identifier format is not fixed yet.

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

## Owner ID

The owner ID identifies a DADE identity.

It must not require a legal name, email address, phone number, store username, or device serial number.

The owner ID should remain stable when the person:

- changes email address
- changes store account
- replaces a phone
- replaces a computer
- changes a display name

The final public-key and recovery model is not fixed yet.

## Device ID

A device ID identifies one device authorization target.

A friendly name such as `Gaming PC` is metadata, not the security identity.

Where supported, the device identity should be tied to a device key that cannot simply be copied to another machine.

The final hardware binding rules are not fixed yet.

## Do not overload identifiers

An identifier should identify one kind of thing.

Bad:

```text
leon@example.com
```

That could be treated as an account name, contact address, identity, or recovery route depending on context.

Better:

```text
owner_id: <opaque DADE identity reference>
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

Those names are for people. They should not be used as the cryptographic identity of the issuer, asset, owner, or device.
