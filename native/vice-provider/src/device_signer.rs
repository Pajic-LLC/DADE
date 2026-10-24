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
