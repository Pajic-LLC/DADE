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
83baf3b43ec5828fbe3f1026b9723ea97e02f27c867e477e1bf46745c18bbdec
```

The protected COSE header decodes to:

```text
alg: -7
kid: 3356f52ab50e2120
```

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
edadca06f840aa3d8414dea4a47259dedf8721c25ea8e5460b0eeed00eb0f257
```

## Reading the hex files

Each `.hex` file contains lowercase hexadecimal text with a final newline.

A test runner should decode the hexadecimal text into binary before parsing it as COSE.

The final exported deed format is binary. The hex files only exist so the vectors can live in the public repository and be reviewed easily.
