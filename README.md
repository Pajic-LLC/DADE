# DADE

DADE stands for Digital Asset Deed Exchange.

DADE is a technology for digital ownership. The goal is simple: if you buy a digital product, owning it should mean more than a store account saying you have access to it.

A DADE-compatible purchase can issue a digital deed. The deed is meant to prove ownership, describe the rights that came with the purchase, and keep working without making normal use depend on the original store staying online forever.

DADE is being developed by Pajic.

## What we want DADE to do

For a normal person, it should feel simple:

1. Buy a digital product.
2. Receive a digital deed.
3. Use the product on your own devices.
4. Keep using supported owned content offline.
5. Keep proof of ownership even if the original store goes away.
6. Gift, lend, or sell the deed when the rights attached to that product allow it.

The cryptography and device security should stay in the background. People should see words like **Owned**, **Digital deed**, **Verify ownership**, **Lend**, **Gift**, and **Sell**.

## What DADE is not

DADE is not a cryptocurrency.

DADE is not an NFT project.

DADE is not a new game store.

DADE is not meant to make every digital file impossible to copy. Files are copyable. DADE is about proving who holds the legitimate ownership right.

## DADE 1

DADE 1 is the version we can build now.

The first implementation is expected to focus on software and games, with a future Pajic title as the first real production use case.

The early work will cover:

- digital deeds
- ownership verification
- offline ownership
- use across a person's own devices
- gifting and transfer
- lending
- recovery
- issuer trust
- security and abuse resistance

Some of those parts are still design work. We are not going to pretend they are solved before they are.

## DADE 2

DADE 2 is reserved for a possible future industry standard built with major operating system, hardware, storefront, and platform companies.

The long-term idea is native support in operating systems and secure hardware. A software installer could ask to verify ownership, show a QR code, and let a person approve the request from a phone or other trusted device. The software would receive a device authorization without turning the store account into the owner.

DADE 2 is not the current project. DADE 1 comes first.

## Public does not mean free commercial use

This repository is public so the work can be inspected and discussed.

No commercial license is granted by the existence of this repository. Unless a file says otherwise, Pajic retains all rights to the material in this repository.

We plan to publish clear licensing terms before third-party production use. Commercial use of DADE will require permission from Pajic unless future licensing terms explicitly say otherwise.

We are also reviewing the intellectual property around the technical design before publishing implementation details that may need separate protection.

See [LEGAL.md](LEGAL.md) before using any material from this repository.

## Status

Early design work.

The current job is to define the ownership model, security rules, terminology, threat model, and a small first implementation without locking ourselves into bad decisions too early.

## One rule we care about

If a person bought something as an owned product, normal use of that product should not stop just because DADE, Pajic, or the original store is offline.
