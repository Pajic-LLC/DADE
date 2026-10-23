# DADE 1 specification

This directory holds the technical DADE 1 specification work.

The specification is intentionally small right now. We are still deciding parts of the ownership and security model, and some implementation details may stay private until Pajic finishes intellectual property review.

## Current drafts

- [Identifiers](identifiers.md)
- [Digital deed model](deed-model.md)
- [Rights model](rights.md)
- [Local verifier contract](verifier-contract.md)
- [Encoding and signature profile](encoding-profile.md)
- [DADE 1 deed wire format](wire-format.md)
- [DADE 1 CDDL schema](dade1.cddl)
- [DADE identity model](identity-model.md)
- [Identity credential formats](identity-credentials.md)
- [Personal device authorization](device-authorization.md)
- [Device proof](device-proof.md)
- [Issuer trust](issuer-trust.md)
- [Issuer signing credential](issuer-credential.md)
- [Recovery](recovery.md)
- [Recovery bundle schema](recovery.cddl)

The logical deed model and first signed wire format now have a working reference verifier.

The identity drafts define a separate owner anchor, controller keys, and personal device keys so a device can use owned content without becoming the owner or receiving the owner's main private key.

The issuer trust drafts separate a stable issuer root from routine deed signing keys. That allows signing-key rotation without changing the issuer identity or invalidating old deeds.

The recovery draft restores the same owner anchor from an encrypted portable backup. A successful recovery keeps the same owner ID and does not require deeds to be reissued.

The first technical profile uses deterministic CBOR, COSE_Sign1, and ES256. The wire-format draft proposes `.ddc` as the three-character portable deed extension. The recovery draft proposes `.drb` for an exported recovery bundle.

The reference work includes a complete offline test chain from issuer root to signing key to deed, then from deed to owner anchor to controller to personal device to a fresh launch proof. Recovery adds a separate path for restoring the same owner anchor when every normal controller is unavailable.

These choices are still draft until broader implementation and security review prove them.

## Planned sections

The first complete draft is expected to define:

1. versioning
2. identifiers
3. digital deed structure
4. issuer identity and trust
5. owner identity
6. device authorization
7. ownership proof
8. offline verification
9. transfer
10. gifting
11. lending
12. recovery
13. rights and policy representation
14. key rotation
15. error handling
16. compatibility rules
17. security requirements
18. privacy requirements
19. test vectors
20. conformance requirements

## Design rule

A technical choice does not belong in the standard just because it is convenient for Pajic's first implementation.

DADE should separate the protocol from Pajic's hosted services so an existing deed can still be verified without needing a live Pajic API.

## Current status

No protocol version has been frozen.

The first encoding, signature, wire-format, identity, device, issuer-trust, and recovery models are proposed, not final.

No production implementation should claim DADE 1 conformance yet.
