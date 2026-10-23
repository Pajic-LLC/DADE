# Security

DADE deals with ownership, identity, keys, and transfer. Security reports need to be handled carefully.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could let someone forge ownership, steal a deed, bypass a transfer rule, expose private keys, or compromise issuer credentials.

Until Pajic publishes a dedicated security contact and disclosure process, contact Pajic privately through an established company contact channel and include:

- a short description of the problem
- the affected file, component, or protocol area
- steps to reproduce it
- the impact you believe it has
- proof of concept material if it is safe to share

Do not include real private keys, personal data, production credentials, or someone else's account information.

## Scope

The most important security areas include:

- deed forgery
- issuer impersonation
- ownership proof bypass
- unauthorized device approval
- transfer duplication
- replay attacks
- rollback attacks
- recovery abuse
- key extraction
- signature verification errors
- privacy leaks

## Early project warning

DADE is not production-ready yet.

The repository may contain incomplete designs, placeholders, and code that has not received independent security review. Do not use an early DADE draft to protect valuable production assets.
