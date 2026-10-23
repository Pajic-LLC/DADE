# Ownership model

This is the first public draft of what ownership means in DADE 1.

It describes the model, not the final cryptographic implementation.

## The short version

A person controls a DADE identity.

A digital deed belongs to that identity.

The deed says which asset is owned and what rights came with it.

The person can authorize their own devices to use the asset. Those devices do not become owners.

A store can sell and deliver the product, but the store account is not the ownership itself.

## The parts

### Person

The human who owns the digital product.

DADE does not need to know the person's legal name for ordinary ownership.

### DADE identity

The cryptographic identity controlled by the person.

A DADE identity is the owner named by a deed.

It is not the same thing as:

- a Pajic account
- a Steam account
- a Microsoft account
- an email address
- a phone number
- one computer or phone

Those things can be linked for convenience, but changing or losing one of them should not automatically change who owns the deed.

The exact key and recovery design is not final yet.

### Digital deed

The ownership record for a digital asset.

At minimum, a deed needs to identify:

- the asset
- the issuer
- the owner
- the rights that came with the purchase
- the version of the DADE rules used to interpret it
- enough signed information to verify that the deed is genuine

The final data format is not fixed yet.

### Asset

The thing the deed represents.

Examples:

- a game
- a software product
- an album
- a movie
- a book
- a plugin
- a font

The asset identifier needs to stay stable even when the product is updated.

### Issuer

The party allowed to issue a deed for an asset.

For a Pajic game, Pajic would be the issuer.

The issuer signs the deed so a verifier can tell that the deed is genuine.

### Store

The place where the person bought the product.

A store can handle:

- payment
- receipts
- downloads
- updates
- cloud saves
- multiplayer services
- support

The store does not have to be the owner authority.

A person should not lose a permanently owned offline-capable product just because the store account is deleted or the store later closes.

### Device

A computer, phone, console, tablet, handheld, or other machine that uses the asset.

A device is not the owner.

A device can receive authorization from the owner's DADE identity to use an asset.

The final device authorization rules are not fixed yet.

## What the deed proves

A valid deed should let a verifier answer a small set of questions:

1. Is this deed genuine?
2. Which asset does it cover?
3. Which DADE identity owns it?
4. Which rights came with it?
5. Is this device or session allowed to exercise the requested right?

The verifier should not need a person's legal name to answer those questions.

## Ownership is not a login

A login proves access to an account.

A DADE deed proves ownership of an asset.

Those are different things.

A person might sign into a Pajic account to buy a game. After purchase, the game can be linked to the person's DADE identity.

The Pajic account can still be useful for receipts, downloads, friends, cloud saves, multiplayer, and support. It should not be the only thing making the game theirs.

## Ownership is not a device

A person can own one deed and use the asset on more than one personal device.

Conceptually:

```text
Person
  |
  v
DADE identity
  |
  v
Digital deed
  |
  +-- personal computer
  +-- laptop
  +-- handheld
  +-- phone
```

The deed still has one owner.

The devices only receive use authority.

DADE needs anti-abuse rules so personal-device support does not become unlimited public sharing. Those rules are not final yet.

## Permanent offline ownership

For a product sold as permanently owned and offline-capable, DADE should support normal use without periodic calls to Pajic, DADE, or the original store.

That means the owner should be able to keep using a valid local setup even during a long outage or after the original seller stops operating.

This does not mean every DADE product can work offline.

An online multiplayer game, streaming service, or cloud application can depend on a live service by nature. The deed should state that dependency clearly.

DADE must not describe a service-dependent product as if every part of it can work forever on an isolated device.

## Reinstalling

A permanently owned product should be designed so the owner can keep an archival copy where the publisher allows that distribution model.

If the owner has the product files and the ownership material needed by DADE, reinstalling should not require the original store to still exist.

The exact archive and installation format is product-specific and not part of this first ownership-model draft.

## Rights

A deed should make the purchased rights clear.

Possible rights include:

- permanent use
- offline use
- use on personal devices
- supported platforms
- gifting
- resale
- lending
- family use
- access to specific editions or content

Not every asset has to include every right.

The important rule is that the rights sold with the deed are explicit.

A publisher should not be able to quietly replace the original ownership terms after sale and pretend nothing changed.

## Transfer

If a deed is sold or gifted, the ownership moves from one DADE identity to another.

After a completed transfer, the old identity is no longer the legitimate owner and the new identity is.

The detailed mechanism for making that safe, including offline devices and rollback attacks, is not part of this public draft yet.

## Lending

A loan is different from a transfer.

During a loan, the original person remains the owner while another person receives temporary use authority under rules attached to the deed and loan.

The exact rules for offline lending, return, expiration, and owner use during a loan are still open.

## Recovery

Recovery is necessary for normal people, but it can weaken ownership if it is careless.

A recovery process must not casually create a second independent owner while an old ownership credential still works.

DADE should support a model where Pajic is not required for ownership to exist.

Provider-assisted recovery may still be offered as an optional convenience.

## What happens if Pajic disappears

For a permanently owned offline-capable asset, the goal is that the following remain enough for normal use:

- the product files
- the valid deed
- the owner's valid local ownership material
- the public information needed to verify the issuer and deed

A live call to Pajic should not be required just to keep using what was already bought.

## What this draft does not solve yet

This draft does not settle:

- the final cryptographic key hierarchy
- the deed encoding
- the exported file format
- the three-character deed file extension
- the device limit or anti-sharing policy
- the transfer invalidation mechanism
- rollback resistance
- the final recovery model
- lending semantics
- the commercial licensing model

Those are separate decisions.

## Test for future designs

When we consider a new DADE feature, ask:

> If Pajic, the store, and the network disappeared after a legitimate permanent purchase, would the person still own something useful?

If the answer is no for a product that was sold as permanently owned and offline-capable, the design has probably drifted back toward ordinary licensing.
