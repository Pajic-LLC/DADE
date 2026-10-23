# User flows

These are plain-language flows for how DADE should feel to a normal person.

They describe the experience we want. They do not lock in the final protocol.

## First purchase

A person buys a DADE-compatible game.

If they already have a DADE identity, the new deed is issued to that identity.

If they do not have one yet, the product helps create one without forcing them to understand cryptographic keys.

The result should feel like:

```text
Purchase complete

VICE
Owned
Digital deed created
```

The person should not have to make a separate Pajic account just to have a DADE identity.

A store account may still be needed for the store's own services.

## Play on the first device

The game checks the local ownership material and confirms that the current device is allowed to use the deed.

For a permanently owned offline-capable game, normal launches should not require a live call to Pajic or the store.

The user sees:

```text
VICE
Owned
Play
```

Not:

```text
Contacting license server
```

## Add a second personal device

A person installs the same game on another computer.

The new device asks to be added to the person's DADE setup.

One possible experience is:

1. The new computer shows a QR code.
2. The person scans it with an already trusted phone or device.
3. The trusted device shows what is being added.
4. The person confirms with local authentication such as Face ID, Touch ID, a passcode, or another supported method.
5. The new computer receives its own device authorization.

The new computer does not receive a copy of the person's main private ownership key.

The QR code is only a pairing request. A screenshot of it should not be the ownership credential.

The exact approval protocol is still being designed.

## Use the product with no internet

Once a permanently owned offline-capable product and device are validly set up, the person disconnects from the internet.

The product still works.

There is no monthly or 30-day check just to prove the purchase still exists.

## Reinstall from an archive

The person keeps an allowed archival copy of the product and the ownership material needed for DADE.

Years later, the original store is unavailable.

The person installs the product from the archive and proves ownership using their DADE identity or an authorized recovery path.

The goal is that the original store does not need to come back online for the person to use a product they already bought.

The exact reinstall and recovery steps are not final yet.

## Gift a product

The owner chooses to gift a transferable deed.

The recipient provides or creates a DADE identity.

The owner confirms the transfer.

After the transfer finishes:

```text
Old holder: no longer owner
New holder: owner
```

The detailed transfer mechanism is intentionally not described here yet.

## Sell a product

A resale uses the same ownership transfer idea as a gift, with payment handled by a marketplace or seller.

DADE's job is to move the ownership right correctly.

DADE does not have to be the marketplace itself.

A future third-party store could handle discovery, price, payment, tax, and buyer protection while DADE handles the ownership change.

## Lend a product

The owner chooses a lend action if the deed allows it.

The borrower receives temporary use authority.

The owner remains the owner.

The product should make the state clear:

```text
Owner: Leon
Borrower: Jona
Loan ends: November 6
```

Whether the owner can use the product at the same time depends on the final lending rules and the rights attached to the deed.

## Delete the original store account

The person deletes the account they used to buy the product.

For a permanently owned offline-capable product, that account deletion should not erase the deed.

Store-only services can stop working because the account is gone. Examples include cloud saves, social features, or store-managed downloads.

Ownership itself should remain with the DADE identity.

## Lose one device

The person loses a phone or computer.

Losing one device should not normally mean losing every deed.

The person uses another trusted device or an approved recovery method to continue controlling the DADE identity.

How recovery works when every trusted device is lost is still an open design question.

## Store closes

The original store shuts down.

For a permanently owned offline-capable product, a person who already has the product files and valid ownership material should still be able to use it.

DADE should not turn store failure into ownership failure.

## Pajic service outage

Pajic services go offline for a week.

Already set up permanently owned offline-capable products should keep working.

New purchases, transfers, lending changes, recovery, or other network actions may be unavailable during the outage.

That is acceptable. Existing ownership should not stop working because the service is down.

## DADE 2 example

DADE 2 is a future idea, not the current implementation.

A possible future native flow for software could look like this:

```text
Activate Windows

Verify ownership with a digital deed
[ QR code ]
```

The person scans the code with a phone that can prove they own the Windows deed, confirms locally, and the new computer receives an authorization.

The user sees a normal ownership action. DADE stays mostly in the background as the technology making it work.
