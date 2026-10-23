# Stage F notes

This stage proves recovery by restoring the same owner anchor from encrypted backup material.

It intentionally does not claim that recovery revokes old controller credentials on machines that never receive an update.

That is a separate trust-update problem.

The recovery model also does not hide the consequences of losing every recovery factor. If the owner anchor, every controller, the recovery bundle, and every copy of the recovery secret are all gone, DADE has no central reset key that silently recreates ownership authority.

Future recovery work can add better user-facing storage and optional managed recovery around this core primitive. It must not change the rule that the owner identity is cryptographic and not just a store account.
