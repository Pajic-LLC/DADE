# DADE 1 specification

This directory holds the technical DADE 1 specification work.

The specification is intentionally small right now. We are still deciding parts of the ownership and security model, and some implementation details may stay private until Pajic finishes intellectual property review.

## Current drafts

- [Identifiers](identifiers.md)
- [Digital deed model](deed-model.md)
- [Rights model](rights.md)
- [Local verifier contract](verifier-contract.md)
- [Encoding and signature profile](encoding-profile.md)

The logical model is now defined well enough to start wire-format work.

The encoding profile proposes deterministic CBOR, COSE_Sign1, and ES256 for the first implementation. It is still a draft until test vectors and implementation work prove the choice.

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

No exported deed file extension has been frozen. If DADE uses one, it will use a three-character extension.

The first encoding and signature profile is proposed, not final.

No production implementation should claim DADE 1 conformance yet.
