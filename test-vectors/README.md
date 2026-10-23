# Test vectors

These vectors are for DADE protocol development only.

The keys in this directory are test keys. They must never be used for production issuance.

## valid-deed.hex

A complete tagged COSE_Sign1 object encoded as hexadecimal text.

Expected result:

```text
COSE structure valid
Signature valid
DADE version 1
Asset com.pajic.vice
Use permanent
Offline full
Personal devices allowed
Gift allowed
Resale allowed
Lend allowed
```

SHA-256 of the binary COSE object:

```text
a1549efd0c124eb872d1949c74931bdb3b1cb39b76ff29d843989a9af31477e9
```

The protected COSE header decodes to:

```text
alg: -7
kid: 65c3c676b246f30c
```

The key ID is the first eight bytes of SHA-256 over the canonical public COSE_Key.

The issuer public key is in `issuer-public-key.pem`.

## invalid-tampered-asset.hex

This starts from the valid signed object and changes the signed asset ID from:

```text
com.pajic.vice
```

to:

```text
com.pajic.vica
```

The signature is not changed.

Expected result:

```text
Signature invalid
```

SHA-256 of the tampered binary object:

```text
a49e1cb4436a7f785499b68fb1c86fb3878aab302a4615daf317d5b0e6ae209c
```

## Identity chain

The `identity` directory contains a complete owner, controller, device authorization, and device proof chain.

See [identity/README.md](identity/README.md) for the expected identifiers and verification steps.

## Reading the hex files

Each `.hex` file contains lowercase hexadecimal text with a final newline.

A test runner should decode the hexadecimal text into binary before parsing it as COSE.

The final exported deed format is binary. The hex files only exist so the vectors can live in the public repository and be reviewed easily.
