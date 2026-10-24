use std::fs;
use std::io::Write;
use std::path::Path;

use ciborium::value::Value;
use p256::ecdsa::{
    signature::Signer,
    Signature,
    SigningKey,
};
use p256::{PublicKey, SecretKey};

use crate::{protocol, store};

const SUPPORTED_ALG: i64 = -7;
const MAX_SIGNER_DESCRIPTOR_BYTES: u64 = 1024;
const FILE_BACKEND: &str = "file-pkcs8-v1";
const MACOS_SECURE_ENCLAVE_BACKEND: &str = "macos-secure-enclave-v1";

pub trait DeviceSigner {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

struct FileDeviceSigner {
    private_key: SecretKey,
}

impl DeviceSigner for FileDeviceSigner {
    fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        let signing_key = SigningKey::from(self.private_key.clone());
        let signature: Signature = signing_key.sign(message);
        let bytes = signature.to_bytes();
        let mut output = [0_u8; 64];
        output.copy_from_slice(&bytes);
        Ok(output)
    }
}

#[derive(Debug)]
enum SignerLocator {
    FilePkcs8,
    MacosSecureEnclave { application_label: Vec<u8> },
}

fn read_signer_locator(home: &Path, device_id: &[u8; 16]) -> Result<SignerLocator, String> {
    let path = store::device_signer_path(home, device_id);
    let metadata = match fs::metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SignerLocator::FilePkcs8);
        }
        Err(error) => {
            return Err(format!("could not inspect device signer descriptor: {error}"));
        }
    };
    if !metadata.is_file() {
        return Err("device signer descriptor is not a file".to_string());
    }
    if metadata.len() > MAX_SIGNER_DESCRIPTOR_BYTES {
        return Err("device signer descriptor is too large".to_string());
    }

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("could not read device signer descriptor: {error}"))?;
    let fields: Vec<_> = raw.split_whitespace().collect();
    let Some(backend) = fields.first().copied() else {
        return Err("device signer descriptor is empty".to_string());
    };

    match backend {
        FILE_BACKEND if fields.len() == 1 => Ok(SignerLocator::FilePkcs8),
        MACOS_SECURE_ENCLAVE_BACKEND if fields.len() == 2 => {
            let application_label = hex::decode(fields[1])
                .map_err(|_| "Secure Enclave application label is not valid hex".to_string())?;
            if application_label.is_empty() || application_label.len() > 64 {
                return Err("Secure Enclave application label has an invalid length".to_string());
            }
            Ok(SignerLocator::MacosSecureEnclave { application_label })
        }
        FILE_BACKEND | MACOS_SECURE_ENCLAVE_BACKEND => {
            Err("device signer descriptor has the wrong number of fields".to_string())
        }
        _ => Err(format!("unsupported device signer backend `{backend}`")),
    }
}

fn write_macos_secure_enclave_locator(
    home: &Path,
    device_id: &[u8; 16],
    application_label: &[u8],
) -> Result<(), String> {
    if application_label.is_empty() || application_label.len() > 64 {
        return Err("Secure Enclave application label has an invalid length".to_string());
    }
    let path = store::device_signer_path(home, device_id);
    let parent = path
        .parent()
        .ok_or_else(|| "device signer descriptor has no parent directory".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create device signer directory: {error}"))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("could not create device signer descriptor: {error}"))?;
    writeln!(
        file,
        "{MACOS_SECURE_ENCLAVE_BACKEND} {}",
        hex::encode(application_label)
    )
    .map_err(|error| format!("could not write device signer descriptor: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("could not sync device signer descriptor: {error}"))?;
    Ok(())
}

fn load_file_signer(home: &Path, device_id: &[u8; 16]) -> Result<Box<dyn DeviceSigner>, String> {
    let path = store::device_key_path(home, device_id);
    let pem = store::read_pem(&path)
        .map_err(|error| format!("could not load device signing key: {error}"))?;
    let private_key = protocol::load_private_key(&pem, "device signing key")
        .map_err(|error| error.to_string())?;
    Ok(Box::new(FileDeviceSigner { private_key }))
}

#[cfg(target_os = "macos")]
pub struct MacosSecureEnclaveEnrollment {
    pub device_id: [u8; 16],
    pub application_label: Vec<u8>,
    pub public_key: PublicKey,
}

#[cfg(target_os = "macos")]
mod macos {
    use p256::ecdsa::Signature;
    use p256::PublicKey;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::item::{
        ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
    };
    use security_framework::key::{
        Algorithm, GenerateKeyOptions, KeyType, SecKey, Token,
    };
    use security_framework::passwords_options::AccessControlOptions;

    use crate::protocol;

    use super::{DeviceSigner, MacosSecureEnclaveEnrollment};

    pub struct SecureEnclaveDeviceSigner {
        private_key: SecKey,
        public_key: PublicKey,
    }

    impl DeviceSigner for SecureEnclaveDeviceSigner {
        fn public_key(&self) -> PublicKey {
            self.public_key.clone()
        }

        fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
            let der = self
                .private_key
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
                .map_err(|error| format!("Secure Enclave signing failed: {error}"))?;
            let signature = Signature::from_der(&der)
                .map_err(|_| "Secure Enclave returned an invalid ECDSA signature".to_string())?;
            let signature = signature.normalize_s().unwrap_or(signature);
            let bytes = signature.to_bytes();
            let mut output = [0_u8; 64];
            output.copy_from_slice(&bytes);
            Ok(output)
        }
    }

    fn public_key(private_key: &SecKey) -> Result<PublicKey, String> {
        let key = private_key
            .public_key()
            .ok_or_else(|| "Secure Enclave key has no public key".to_string())?;
        let encoded = key
            .external_representation()
            .ok_or_else(|| "Secure Enclave public key cannot be exported".to_string())?;
        PublicKey::from_sec1_bytes(&encoded.to_vec())
            .map_err(|_| "Secure Enclave returned an invalid P-256 public key".to_string())
    }

    pub fn load(application_label: &[u8]) -> Result<Box<dyn DeviceSigner>, String> {
        let mut query = ItemSearchOptions::new();
        query
            .key_class(KeyClass::private())
            .application_label(application_label)
            .load_refs(true)
            .limit(2_i64)
            .ignore_legacy_keychains();

        let mut results = query
            .search()
            .map_err(|error| format!("could not load Secure Enclave device key: {error}"))?;
        if results.len() != 1 {
            return Err(format!(
                "expected one Secure Enclave device key, found {}",
                results.len()
            ));
        }
        let private_key = match results.pop() {
            Some(SearchResult::Ref(Reference::Key(key))) => key,
            _ => return Err("Secure Enclave lookup did not return a private key".to_string()),
        };
        let public_key = public_key(&private_key)?;
        Ok(Box::new(SecureEnclaveDeviceSigner {
            private_key,
            public_key,
        }))
    }

    pub fn enroll() -> Result<MacosSecureEnclaveEnrollment, String> {
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            AccessControlOptions::PRIVATE_KEY_USAGE.bits(),
        )
        .map_err(|error| format!("could not create Secure Enclave access control: {error}"))?;

        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label("DADE device")
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access_control);

        let private_key = SecKey::new(&options)
            .map_err(|error| format!("could not create Secure Enclave device key: {error}"))?;
        let application_label = match private_key.application_label() {
            Some(value) if !value.is_empty() => value,
            _ => {
                let _ = private_key.delete();
                return Err("Secure Enclave key has no application label".to_string());
            }
        };
        let public_key = match public_key(&private_key) {
            Ok(value) => value,
            Err(error) => {
                let _ = private_key.delete();
                return Err(error);
            }
        };
        let device_id = match protocol::device_id(&public_key) {
            Ok(value) => value,
            Err(error) => {
                let _ = private_key.delete();
                return Err(error.to_string());
            }
        };

        Ok(MacosSecureEnclaveEnrollment {
            device_id,
            application_label,
            public_key,
        })
    }
}

#[cfg(target_os = "macos")]
pub fn enroll_macos_secure_enclave() -> Result<MacosSecureEnclaveEnrollment, String> {
    macos::enroll()
}

#[cfg(target_os = "macos")]
pub fn install_macos_secure_enclave_locator(
    home: &Path,
    device_id: &[u8; 16],
    application_label: &[u8],
) -> Result<(), String> {
    let signer = macos::load(application_label)?;
    let actual_device_id = protocol::device_id(&signer.public_key())
        .map_err(|error| error.to_string())?;
    if actual_device_id != *device_id {
        return Err("Secure Enclave key does not match the requested DADE device ID".to_string());
    }
    write_macos_secure_enclave_locator(home, device_id, application_label)
}

pub fn load_device_signer(
    home: &Path,
    device_id: &[u8; 16],
) -> Result<Box<dyn DeviceSigner>, String> {
    match read_signer_locator(home, device_id)? {
        SignerLocator::FilePkcs8 => load_file_signer(home, device_id),
        SignerLocator::MacosSecureEnclave { application_label } => {
            #[cfg(target_os = "macos")]
            {
                return macos::load(&application_label);
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = application_label;
                Err("macOS Secure Enclave signer is unavailable on this platform".to_string())
            }
        }
    }
}

pub fn sign_device_proof(
    signer: &dyn DeviceSigner,
    challenge: [u8; 32],
    asset_id: &str,
    owner: [u8; 16],
    device: [u8; 16],
) -> Result<Vec<u8>, String> {
    let public_key = signer.public_key();
    let key_id = protocol::key_id(&public_key).map_err(|error| error.to_string())?;
    let protected = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(SUPPORTED_ALG.into())),
        (Value::Integer(4.into()), Value::Bytes(key_id.to_vec())),
    ]);
    let protected = protocol::encode_canonical(&protected)
        .map_err(|error| error.to_string())?;
    let payload = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(1.into())),
        (Value::Integer(2.into()), Value::Bytes(challenge.to_vec())),
        (Value::Integer(3.into()), Value::Text(asset_id.to_string())),
        (Value::Integer(4.into()), Value::Integer(protocol::RIGHT_USE.into())),
        (Value::Integer(5.into()), Value::Bytes(owner.to_vec())),
        (Value::Integer(6.into()), Value::Bytes(device.to_vec())),
    ]);
    let payload = protocol::encode_canonical(&payload)
        .map_err(|error| error.to_string())?;
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.clone()),
    ]);
    let sig_structure = protocol::encode_canonical(&sig_structure)
        .map_err(|error| error.to_string())?;
    let signature = signer.sign(&sig_structure)?;
    let cose = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(signature.to_vec()),
        ])),
    );
    protocol::encode_canonical(&cose).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;
    use std::io::Write;

    fn temporary_home(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "dade-signer-{name}-{}-{}",
            std::process::id(),
            rand_core::OsRng.next_u64()
        ));
        std::fs::create_dir_all(root.join("devices")).expect("create temporary DADE home");
        root
    }

    #[test]
    fn missing_descriptor_keeps_file_backend_compatibility() {
        let home = temporary_home("missing");
        let device_id = [7_u8; 16];
        assert!(matches!(
            read_signer_locator(&home, &device_id).unwrap(),
            SignerLocator::FilePkcs8
        ));
        std::fs::remove_dir_all(home).ok();
    }

    #[test]
    fn secure_enclave_descriptor_parses_application_label() {
        let home = temporary_home("secure-enclave");
        let device_id = [8_u8; 16];
        let path = store::device_signer_path(&home, &device_id);
        let mut file = std::fs::File::create(path).unwrap();
        writeln!(file, "{MACOS_SECURE_ENCLAVE_BACKEND} 001122aabbcc").unwrap();
        match read_signer_locator(&home, &device_id).unwrap() {
            SignerLocator::MacosSecureEnclave { application_label } => {
                assert_eq!(application_label, hex::decode("001122aabbcc").unwrap());
            }
            SignerLocator::FilePkcs8 => panic!("wrong signer backend"),
        }
        std::fs::remove_dir_all(home).ok();
    }

    #[test]
    fn unknown_signer_backend_fails_closed() {
        let home = temporary_home("unknown");
        let device_id = [9_u8; 16];
        let path = store::device_signer_path(&home, &device_id);
        std::fs::write(path, "mystery-signer-v1\n").unwrap();
        let error = read_signer_locator(&home, &device_id).unwrap_err();
        assert!(error.contains("unsupported device signer backend"));
        std::fs::remove_dir_all(home).ok();
    }

    #[test]
    fn signer_descriptor_is_create_only() {
        let home = temporary_home("create-only");
        let device_id = [10_u8; 16];
        write_macos_secure_enclave_locator(&home, &device_id, &[1, 2, 3]).unwrap();
        let error = write_macos_secure_enclave_locator(&home, &device_id, &[4, 5, 6]).unwrap_err();
        assert!(error.contains("could not create device signer descriptor"));
        std::fs::remove_dir_all(home).ok();
    }
}
