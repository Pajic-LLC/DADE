use std::path::Path;

use p256::ecdsa::{
    signature::Signer,
    Signature,
    SigningKey,
};
use p256::{PublicKey, SecretKey};

use crate::{protocol, store};

pub trait DeviceSigner {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String>;
    fn backend_name(&self) -> &'static str;
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

    fn backend_name(&self) -> &'static str {
        "file-pkcs8-v1"
    }
}

pub fn load_device_signer(
    home: &Path,
    device_id: &[u8; 16],
) -> Result<Box<dyn DeviceSigner>, String> {
    let path = store::device_key_path(home, device_id);
    let pem = store::read_pem(&path)
        .map_err(|error| format!("could not load device signing key: {error}"))?;
    let private_key = protocol::load_private_key(&pem, "device signing key")
        .map_err(|error| error.to_string())?;
    Ok(Box::new(FileDeviceSigner { private_key }))
}
