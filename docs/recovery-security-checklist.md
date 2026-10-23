# Recovery security checklist

A DADE recovery implementation should satisfy all of these before it is treated as production-ready.

- generate the recovery secret with a cryptographically secure random number generator
- generate a fresh AES-GCM nonce for every recovery bundle
- never reuse a nonce with the same recovery secret
- never store the recovery secret inside the recovery bundle
- authenticate the owner ID as part of the encrypted bundle
- reject modified or non-canonical recovery bundles
- verify that the restored anchor derives the expected owner ID
- keep the owner anchor out of normal application code except during controlled recovery or owner-management operations
- make provider-assisted storage optional
- make it clear that possession of both the recovery bundle and recovery secret grants owner-level control
- do not claim that recovery revokes old offline controllers
- do not use a normal account password directly as the AES key

Production applications should also make recovery setup understandable enough that a normal person knows what must be kept safe and what happens if every recovery factor is lost.
