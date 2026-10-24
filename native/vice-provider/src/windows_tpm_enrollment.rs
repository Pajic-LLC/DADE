use std::mem::size_of;
use std::ptr::{null, null_mut};

use p256::PublicKey;
use rand_core::{OsRng, RngCore};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, MS_PLATFORM_CRYPTO_PROVIDER,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_KEY_HANDLE,
    NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_PERSIST_FLAG, NCRYPT_PROV_HANDLE,
};

use crate::protocol;

pub struct WindowsTpmEnrollment {
    pub device_id: [u8; 16],
    pub key_name: String,
    pub public_key: PublicKey,
}

fn cng_error(operation: &str, status: i32) -> String {
    format!("{operation} failed with CNG status 0x{:08x}", status as u32)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct ProviderHandle(NCRYPT_PROV_HANDLE);

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}

struct KeyHandle {
    handle: NCRYPT_KEY_HANDLE,
    delete_on_drop: bool,
}

impl KeyHandle {
    fn persist(&mut self) {
        self.delete_on_drop = false;
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if self.handle == 0 {
            return;
        }
        unsafe {
            if self.delete_on_drop {
                NCryptDeleteKey(self.handle, 0);
            } else {
                NCryptFreeObject(self.handle);
            }
        }
    }
}

fn open_provider() -> Result<ProviderHandle, String> {
    let mut provider = 0;
    let status = unsafe {
        NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0)
    };
    if status < 0 {
        return Err(cng_error("opening Microsoft Platform Crypto Provider", status));
    }
    Ok(ProviderHandle(provider))
}

fn export_public_key(key: NCRYPT_KEY_HANDLE) -> Result<PublicKey, String> {
    let mut required = 0_u32;
    let status = unsafe {
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            null(),
            null_mut(),
            0,
            &mut required,
            0,
        )
    };
    if status < 0 {
        return Err(cng_error("TPM public-key sizing", status));
    }
    if required < 72 || required > 4096 {
        return Err(format!(
            "TPM returned an unexpected public-key blob size of {required} bytes"
        ));
    }

    let mut blob = vec![0_u8; required as usize];
    let mut written = 0_u32;
    let status = unsafe {
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            null(),
            blob.as_mut_ptr(),
            blob.len() as u32,
            &mut written,
            0,
        )
    };
    if status < 0 {
        return Err(cng_error("TPM public-key export", status));
    }
    blob.truncate(written as usize);
    if blob.len() != 72 {
        return Err("TPM returned a malformed P-256 public-key blob".to_string());
    }

    let magic = u32::from_le_bytes(blob[0..4].try_into().unwrap());
    let coordinate_bytes = u32::from_le_bytes(blob[4..8].try_into().unwrap()) as usize;
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || coordinate_bytes != 32 {
        return Err("TPM key is not an ECDSA P-256 key".to_string());
    }

    let mut sec1 = [0_u8; 65];
    sec1[0] = 4;
    sec1[1..33].copy_from_slice(&blob[8..40]);
    sec1[33..65].copy_from_slice(&blob[40..72]);
    PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| "TPM returned an invalid P-256 public key".to_string())
}

fn random_key_name() -> String {
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    format!("DADE-device-{}", hex::encode(random))
}

pub fn enroll() -> Result<WindowsTpmEnrollment, String> {
    let provider = open_provider()?;
    let key_name = random_key_name();
    let name = wide(&key_name);
    let mut raw_key = 0;
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut raw_key,
            NCRYPT_ECDSA_P256_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    };
    if status < 0 {
        return Err(cng_error("creating TPM device key", status));
    }
    let mut key = KeyHandle {
        handle: raw_key,
        delete_on_drop: true,
    };

    let usage = NCRYPT_ALLOW_SIGNING_FLAG;
    let status = unsafe {
        NCryptSetProperty(
            key.handle,
            NCRYPT_KEY_USAGE_PROPERTY,
            (&usage as *const u32).cast::<u8>(),
            size_of::<u32>() as u32,
            NCRYPT_PERSIST_FLAG,
        )
    };
    if status < 0 {
        return Err(cng_error("setting TPM signing-only usage", status));
    }

    let status = unsafe { NCryptFinalizeKey(key.handle, 0) };
    if status < 0 {
        return Err(cng_error("finalizing TPM device key", status));
    }

    let public_key = export_public_key(key.handle)?;
    let device_id = protocol::device_id(&public_key).map_err(|error| error.to_string())?;
    key.persist();

    Ok(WindowsTpmEnrollment {
        device_id,
        key_name,
        public_key,
    })
}

pub fn public_key_for_name(key_name: &str) -> Result<PublicKey, String> {
    if key_name.is_empty() || key_name.len() > 128 || key_name.contains('\0') {
        return Err("Windows TPM key name has an invalid length or value".to_string());
    }

    let provider = open_provider()?;
    let name = wide(key_name);
    let mut raw_key = 0;
    let status = unsafe { NCryptOpenKey(provider.0, &mut raw_key, name.as_ptr(), 0, 0) };
    if status < 0 {
        return Err(cng_error("opening TPM device key", status));
    }
    let key = KeyHandle {
        handle: raw_key,
        delete_on_drop: false,
    };
    export_public_key(key.handle)
}
