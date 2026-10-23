# Rights model

A DADE deed should say what the owner actually bought.

This document defines the first logical rights vocabulary for DADE 1.

It does not define the final binary encoding or legal wording.

## Why rights belong in the model

A deed that only says `owned` is too vague.

A person needs to know whether the purchase includes offline use, use on personal devices, lending, gifting, resale, or a live service dependency.

DADE should make those differences visible instead of hiding them in changing store text.

## Core rights

### Use

Defines how long the owner may use the asset.

Initial values:

- `permanent`
- `until <time>`
- `subscription`

A product sold with `permanent` use must not require periodic license renewal just to keep the ownership alive.

A permanent product can still contain features that depend on a live service. Those dependencies must be stated separately.

### Offline

States whether the owned product can exercise its core use right without a network connection after valid setup.

Initial values:

- `true`
- `false`
- `partial`

`partial` means some owned parts work offline while other parts require a service.

If `partial` is used, the product should describe what depends on the service.

### Personal devices

States whether the owner may use the asset on more than one device they control.

The first DADE 1 model treats personal-device authorization as separate from ownership.

The deed can permit personal-device use without turning each device into another owner.

The final device limits and anti-sharing rules are not fixed yet.

### Gift

States whether the owner may transfer the deed to another person without a resale transaction.

Initial values:

- `true`
- `false`

The transfer mechanism is not defined in this public draft.

### Resale

States whether the owner may transfer the deed as part of a sale.

Initial values:

- `true`
- `false`

DADE does not have to process the payment. A marketplace can handle the commercial transaction while DADE handles ownership change.

### Lend

States whether the owner may grant temporary use authority to another DADE identity.

Initial values:

- `true`
- `false`

Loan duration, offline behavior, return rules, and simultaneous owner use are not fixed yet.

### Platforms

Lists the product platforms covered by the deed when platform scope matters.

Examples:

```text
windows
macos
linux
xbox
playstation
```

A deed may cover one platform or several.

DADE should not assume that buying one platform automatically grants every other platform.

### Service dependencies

Describes features that require a live third-party or publisher service.

Examples:

- multiplayer servers
- cloud rendering
- streaming catalog access
- cloud saves
- online account features

A service dependency is not automatically a reason to classify the entire asset as temporary.

For example, a game can be permanently owned while its online multiplayer service remains dependent on servers.

## Rights must not contradict each other silently

Implementations should reject or clearly flag impossible or misleading combinations.

Examples:

- `use: permanent` with a hidden monthly renewal requirement
- `offline: true` when the product cannot launch without a network call
- `resale: true` when the issuer has no transfer path at all

A publisher can choose restrictive rights. DADE's job is to make those rights explicit and stable.

## Rights at issuance

The deed must bind the rights that existed when it was issued.

A later policy update must not silently reduce an already issued permanent deed.

If a publisher offers the owner a voluntary upgrade, conversion, or replacement deed, that should be represented as a new action the owner can understand.

## Consumer wording

Normal product screens should use plain language.

Good:

```text
Owned permanently
Works offline
Use on your personal devices
Can be gifted
Can be resold
Can be lent
```

Bad:

```text
entitlement_policy_flags: 0x3F
```

The protocol can be technical underneath. The ownership terms should not be.
