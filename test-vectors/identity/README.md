# Identity chain test vectors

These files test the DADE 1 owner, controller, and personal device model.

All keys are public test material. Nothing in this directory is suitable for production use.

## Expected identifiers

```text
owner_id       6a68a10eb0a0747a549dfda8cfa82fe8
controller_id  7547b84b4bdc8a90839042c1310163a8
device_id      17ccc41d5b1723cae307d65b2008b8c7
```

## Files

`owned-device-deed.hex`

A deed for `com.pajic.vice` issued to the test owner ID.

SHA-256 of the binary object:

```text
5a0db5739e60b2b712b24337350e1424c2040b2beda120db690bcb06f6239588
```

`anchor-public-key.pem`

The test identity anchor public key.

`controller-credential.hex`

A controller credential signed by the anchor. The controller has scopes `authorize_devices` and `prove_owner`.

SHA-256:

```text
e6d8584e93441c50b817f7e3cf6da04c6216f7be9644a5246324f7249b793f12
```

`device-authorization.hex`

A personal device authorization signed by the controller. The device has the `use_owned_assets` scope.

SHA-256:

```text
1581e7951c1ee4a8a98ed2dbe2213cde3093b055ff366b96fda8dd7716fc1237
```

`device-proof.hex`

A launch proof signed by the device key for asset `com.pajic.vice` and right `use`.

The challenge is:

```text
fca6dee2372a043effc2f57dc8aaedb639ff31cee6777a4221414a18b47e8fac
```

SHA-256:

```text
c249085e2c79719f652044792d7bc22ff6319b42178c9edb74bb13368eab063d
```

## Expected result

A complete offline verification should succeed only when all of the following are true:

1. the issuer signature on the deed is valid
2. the anchor public key derives the owner ID in the deed
3. the anchor signature on the controller credential is valid
4. the controller credential belongs to the same owner ID
5. the controller public key derives the controller ID in the credential
6. the controller has `authorize_devices`
7. the controller signature on the device authorization is valid
8. the device authorization belongs to the same owner and controller
9. the device public key derives the device ID in the authorization
10. the device authorization has `use_owned_assets`
11. the device proof signature is valid
12. the device proof uses the expected challenge, asset, right, owner ID, and device ID

No network request is needed for this test.
