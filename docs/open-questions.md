# Open questions

DADE is early enough that some of the most important choices should stay open until we can test them properly.

This list exists so we do not accidentally turn guesses from an early draft into permanent protocol rules.

## Identity

- How is a DADE identity created on first use?
- Which keys belong to the identity and which belong to individual devices?
- How does a person add a second device without copying a master private key around?
- What recovery options can exist without weakening ownership?
- Can a person use DADE without ever creating an account with Pajic or another provider? The intended answer is yes.

## Deed format

- What is the smallest useful deed format?
- Which fields are mandatory?
- Which rights are represented directly in the deed?
- Which rights are referenced through a separate policy document?
- Which canonical encoding do we use?
- Which signature formats do we support first?
- How do we keep old deeds verifiable decades later?
- What three-character file extension should be used for exported deed files, if exported files are part of the final design?

## Devices

- How does a person approve a new personal device?
- Which devices can approve other devices?
- How do we stop device approval from becoming unlimited account sharing?
- Should there be a personal-device limit, rate limit, cooldown, or another anti-abuse model?
- What is the right behavior on platforms without secure hardware?

## Offline ownership

- What proof does a game or application need to verify ownership with no network connection?
- Can a permanently owned product remain offline forever after valid setup?
- How do we support reinstalling from archived files without contacting the original seller?
- What information has to be stored with the product so verification survives the issuer going away?

## Transfer

- What must be relinquished before a deed can move to another owner?
- Can DADE 1 make an old ownership credential locally unusable after transfer without requiring periodic online checks?
- How do hardware-backed credentials change the answer?
- How do we prevent rollback to an old system image from restoring ownership?
- What do we do on devices that were already offline before a transfer happened?

Detailed answers in this area may stay private until Pajic completes intellectual property review.

## Lending

- Does a loan move use authority while leaving title with the owner?
- Can the owner use the product during a loan?
- Can a loan work fully offline after it is created?
- How does an offline loan return cleanly?
- How do we handle a borrower device that never comes back online?

## Storefronts

- What can DADE do with a store that does not support transferable licenses?
- What does a basic Steam integration look like without Valve changing Steam?
- What rights can be independently exercised outside the original storefront?
- How do we describe platform-specific rights without making the deed misleading?

## Recovery

- What happens if a person loses every trusted device?
- Can recovery be optional?
- Can a person choose a stronger mode where losing all recovery material really means losing access?
- How do we prevent a recovered identity and an old offline identity from both acting as the owner?

## Business and licensing

- What parts of DADE are free to inspect?
- What evaluation use can be allowed before a commercial license is needed?
- What should commercial pricing be based on?
- Which parts should be licensed per publisher, per title, per deed, or through an enterprise agreement?
- Which marks can only be used by certified implementations?
- Which technical inventions should be reviewed for patent protection before publication?

## DADE 2

DADE 2 is not being designed in detail yet.

The current long-term idea is native ownership support from operating systems, hardware vendors, storefronts, and consoles. DADE 1 should avoid choices that would make that future path needlessly difficult.
