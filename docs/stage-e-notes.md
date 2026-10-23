# Stage E notes

This stage proves issuer trust and routine signing-key rotation.

It intentionally does not claim that a fully offline verifier can instantly learn that a key was compromised somewhere else.

That requires updated trust information to reach the verifier.

The next issuer-trust work after this stage should define signed trust updates for:

- signing-key compromise
- signing-key revocation
- issuer root migration

Those updates must preserve the same DADE rule used elsewhere: existing permanent ownership should not depend on a live Pajic service just to remain usable.
