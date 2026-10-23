# Recovery flow

This is the first DADE 1 recovery flow.

## Create a backup

1. The owner device has access to the owner anchor for a controlled backup operation.
2. DADE generates a random 32-byte recovery secret.
3. DADE generates a fresh 12-byte AES-GCM nonce.
4. DADE encrypts the owner anchor private value into a recovery bundle.
5. The bundle records the expected owner ID in authenticated form.
6. The recovery secret is shown or stored separately from the bundle.

The user can keep the encrypted bundle locally, in cloud storage, with Pajic, or with another provider.

The provider does not need the recovery secret just to store the bundle.

## Restore ownership control

1. The user provides the recovery bundle.
2. The user provides the recovery secret.
3. DADE authenticates and decrypts the bundle.
4. DADE reconstructs the owner anchor.
5. DADE derives the owner ID from the recovered public key.
6. Recovery succeeds only if that ID matches the owner ID authenticated by the bundle.
7. The recovered anchor can issue a new controller credential.

Existing deeds do not change because the owner identity did not change.

## What the user should see

The normal user-facing language should stay simple.

A setup flow could say:

```text
Protect your digital deeds

Create a recovery backup so you can restore ownership if you lose every trusted device.
```

A restore flow could say:

```text
Restore your digital deeds

Use your recovery backup and recovery key to restore ownership on this device.
```

The UI does not need to expose terms such as private scalar, AES-GCM, or owner anchor unless the user opens technical details.
