use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::io::Cursor;

use ciborium::value::Value;
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

const SUPPORTED_ALG: i64 = -7;
const OWNER_PREFIX: &[u8] = b"DADE1-OWNER\0";
const CONTROLLER_PREFIX: &[u8] = b"DADE1-CONTROLLER\0";
const DEVICE_PREFIX: &[u8] = b"DADE1-DEVICE\0";
const ISSUER_PREFIX: &[u8] = b"DADE1-ISSUER\0";

pub const CONTROLLER_SCOPE_AUTHORIZE_DEVICES: u64 = 1;
pub const DEVICE_SCOPE_USE_OWNED_ASSETS: u64 = 1;
pub const RIGHT_USE: u64 = 1;

#[derive(Debug, Clone)]
pub struct ProtocolError(pub String);

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ProtocolError {}

type Result<T> = std::result::Result<T, ProtocolError>;

fn error(message: impl Into<String>) -> ProtocolError {
    ProtocolError(message.into())
}

fn decode_value(bytes: &[u8], label: &str) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|_| error(format!("invalid {label}")))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(error(format!("{label} contains trailing data")));
    }
    Ok(value)
}

fn raw_encode(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    ciborium::ser::into_writer(value, &mut output)
        .map_err(|_| error("could not encode CBOR"))?;
    Ok(output)
}

fn canonicalize(value: &Value) -> Result<Value> {
    match value {
        Value::Integer(value) => Ok(Value::Integer(value.clone())),
        Value::Bytes(value) => Ok(Value::Bytes(value.clone())),
        Value::Text(value) => Ok(Value::Text(value.clone())),
        Value::Bool(value) => Ok(Value::Bool(*value)),
        Value::Null => Ok(Value::Null),
        Value::Array(values) => Ok(Value::Array(
            values
                .iter()
                .map(canonicalize)
                .collect::<Result<Vec<_>>>()?,
        )),
        Value::Tag(tag, value) => Ok(Value::Tag(*tag, Box::new(canonicalize(value)?))),
        Value::Map(entries) => {
            let mut normalized = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let key = canonicalize(key)?;
                let value = canonicalize(value)?;
                let encoded_key = raw_encode(&key)?;
                normalized.push((encoded_key, key, value));
            }
            normalized.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            for pair in normalized.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(error("CBOR map contains duplicate keys"));
                }
            }
            Ok(Value::Map(
                normalized
                    .into_iter()
                    .map(|(_, key, value)| (key, value))
                    .collect(),
            ))
        }
        Value::Float(_) => Err(error("floating-point CBOR is not supported by DADE 1")),
        _ => Err(error("unsupported CBOR value")),
    }
}

pub fn encode_canonical(value: &Value) -> Result<Vec<u8>> {
    raw_encode(&canonicalize(value)?)
}

fn as_map<'a>(value: &'a Value, label: &str) -> Result<&'a [(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries.as_slice()),
        _ => Err(error(format!("{label} must be a map"))),
    }
}

fn as_array<'a>(value: &'a Value, label: &str) -> Result<&'a [Value]> {
    match value {
        Value::Array(values) => Ok(values.as_slice()),
        _ => Err(error(format!("{label} must be an array"))),
    }
}

fn as_u64(value: &Value, label: &str) -> Result<u64> {
    match value {
        Value::Integer(value) => u64::try_from(value.clone())
            .map_err(|_| error(format!("{label} must be an unsigned integer"))),
        _ => Err(error(format!("{label} must be an unsigned integer"))),
    }
}

fn as_i64(value: &Value, label: &str) -> Result<i64> {
    match value {
        Value::Integer(value) => i64::try_from(value.clone())
            .map_err(|_| error(format!("{label} must be an integer"))),
        _ => Err(error(format!("{label} must be an integer"))),
    }
}

fn as_bool(value: &Value, label: &str) -> Result<bool> {
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(error(format!("{label} must be boolean"))),
    }
}

fn as_text(value: &Value, label: &str, max_bytes: usize) -> Result<String> {
    match value {
        Value::Text(value) if !value.is_empty() && value.len() <= max_bytes => Ok(value.clone()),
        Value::Text(_) => Err(error(format!("{label} has an invalid length"))),
        _ => Err(error(format!("{label} must be text"))),
    }
}

fn as_bytes(value: &Value, label: &str, size: usize) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(value) if value.len() == size => Ok(value.clone()),
        Value::Bytes(_) => Err(error(format!("{label} must be {size} bytes"))),
        _ => Err(error(format!("{label} must be bytes"))),
    }
}

fn fixed_bytes<const N: usize>(value: &Value, label: &str) -> Result<[u8; N]> {
    let bytes = as_bytes(value, label, N)?;
    bytes
        .try_into()
        .map_err(|_| error(format!("{label} must be {N} bytes")))
}

fn int_key(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(value) => i64::try_from(value.clone()).ok(),
        _ => None,
    }
}

fn get_int(entries: &[(Value, Value)], key: i64) -> Option<&Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (int_key(candidate) == Some(key)).then_some(value))
}

fn required_int<'a>(entries: &'a [(Value, Value)], key: i64, label: &str) -> Result<&'a Value> {
    get_int(entries, key).ok_or_else(|| error(format!("{label} is missing field {key}")))
}

fn integer_key_set(entries: &[(Value, Value)], label: &str) -> Result<HashSet<i64>> {
    let mut keys = HashSet::new();
    for (key, _) in entries {
        let key = int_key(key).ok_or_else(|| error(format!("{label} has a non-integer field")))?;
        if !keys.insert(key) {
            return Err(error(format!("{label} has a duplicate field")));
        }
    }
    Ok(keys)
}

fn exact_keys(entries: &[(Value, Value)], expected: &[i64], label: &str) -> Result<()> {
    let keys = integer_key_set(entries, label)?;
    let expected: HashSet<_> = expected.iter().copied().collect();
    if keys != expected {
        return Err(error(format!("invalid {label} fields")));
    }
    Ok(())
}

fn required_subset(
    entries: &[(Value, Value)],
    required: &[i64],
    allowed: &[i64],
    label: &str,
) -> Result<()> {
    let keys = integer_key_set(entries, label)?;
    if required.iter().any(|key| !keys.contains(key)) {
        return Err(error(format!("{label} is missing a required field")));
    }
    if keys.iter().any(|key| !allowed.contains(key)) {
        return Err(error(format!("unsupported {label} field")));
    }
    Ok(())
}

fn public_key_cose_value(public_key: &PublicKey) -> Result<Value> {
    let point = public_key.to_encoded_point(false);
    let x = point.x().ok_or_else(|| error("P-256 public key has no x coordinate"))?;
    let y = point.y().ok_or_else(|| error("P-256 public key has no y coordinate"))?;
    Ok(Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
    ]))
}

fn canonical_public_key(public_key: &PublicKey) -> Result<Vec<u8>> {
    encode_canonical(&public_key_cose_value(public_key)?)
}

pub fn key_id(public_key: &PublicKey) -> Result<[u8; 8]> {
    let digest = Sha256::digest(canonical_public_key(public_key)?);
    Ok(digest[..8].try_into().expect("slice length is fixed"))
}

fn prefixed_id(prefix: &[u8], public_key: &PublicKey) -> Result<[u8; 16]> {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(canonical_public_key(public_key)?);
    let digest = hasher.finalize();
    Ok(digest[..16].try_into().expect("slice length is fixed"))
}

pub fn owner_id(public_key: &PublicKey) -> Result<[u8; 16]> {
    prefixed_id(OWNER_PREFIX, public_key)
}

pub fn controller_id(public_key: &PublicKey) -> Result<[u8; 16]> {
    prefixed_id(CONTROLLER_PREFIX, public_key)
}

pub fn device_id(public_key: &PublicKey) -> Result<[u8; 16]> {
    prefixed_id(DEVICE_PREFIX, public_key)
}

pub fn issuer_id(public_key: &PublicKey) -> Result<[u8; 16]> {
    prefixed_id(ISSUER_PREFIX, public_key)
}

pub fn load_public_key(pem: &[u8], label: &str) -> Result<PublicKey> {
    let text = std::str::from_utf8(pem).map_err(|_| error(format!("invalid {label}")))?;
    PublicKey::from_public_key_pem(text).map_err(|_| error(format!("invalid {label}")))
}

pub fn load_private_key(pem: &[u8], label: &str) -> Result<SecretKey> {
    let text = std::str::from_utf8(pem).map_err(|_| error(format!("invalid {label}")))?;
    SecretKey::from_pkcs8_pem(text).map_err(|_| error(format!("invalid {label}")))
}

fn cose_public_key(value: &Value) -> Result<PublicKey> {
    let entries = as_map(value, "COSE_Key")?;
    exact_keys(entries, &[1, -1, -2, -3], "COSE_Key")?;
    if as_i64(required_int(entries, 1, "COSE_Key")?, "COSE_Key kty")? != 2 {
        return Err(error("COSE_Key must use EC2"));
    }
    if as_i64(required_int(entries, -1, "COSE_Key")?, "COSE_Key curve")? != 1 {
        return Err(error("COSE_Key must use P-256"));
    }
    let x = as_bytes(required_int(entries, -2, "COSE_Key")?, "COSE_Key x", 32)?;
    let y = as_bytes(required_int(entries, -3, "COSE_Key")?, "COSE_Key y", 32)?;
    let mut encoded = Vec::with_capacity(65);
    encoded.push(4);
    encoded.extend_from_slice(&x);
    encoded.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&encoded).map_err(|_| error("invalid P-256 public key"))
}

struct Sign1Parts {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn decode_sign1(raw: &[u8]) -> Result<Sign1Parts> {
    let value = decode_value(raw, "signed CBOR")?;
    let array = match value {
        Value::Tag(18, value) => match *value {
            Value::Array(values) if values.len() == 4 => values,
            _ => return Err(error("invalid COSE_Sign1 structure")),
        },
        _ => return Err(error("expected tagged COSE_Sign1")),
    };

    let protected = match &array[0] {
        Value::Bytes(value) => value.clone(),
        _ => return Err(error("protected header must be bytes")),
    };
    let unprotected = as_map(&array[1], "unprotected headers")?;
    if !unprotected.is_empty() {
        return Err(error("unprotected headers are not allowed"));
    }
    let payload = match &array[2] {
        Value::Bytes(value) => value.clone(),
        _ => return Err(error("embedded payload is required")),
    };
    let signature = as_bytes(&array[3], "ES256 signature", 64)?;
    Ok(Sign1Parts {
        protected,
        payload,
        signature,
    })
}

pub fn peek_deed_issuer(raw: &[u8]) -> Result<[u8; 16]> {
    if raw.len() > 64 * 1024 {
        return Err(error("deed exceeds the maximum size"));
    }
    let sign1 = decode_sign1(raw)?;
    let payload = decode_value(&sign1.payload, "deed payload")?;
    let entries = as_map(&payload, "deed payload")?;
    fixed_bytes(required_int(entries, 4, "deed")?, "issuer_id")
}

fn verify_signed_map(raw: &[u8], public_key: &PublicKey) -> Result<Value> {
    let sign1 = decode_sign1(raw)?;
    let protected_value = decode_value(&sign1.protected, "protected header")?;
    let protected = as_map(&protected_value, "protected header")?;
    let keys = integer_key_set(protected, "protected header")?;
    if keys.iter().any(|key| *key != 1 && *key != 4) {
        return Err(error("unsupported protected header"));
    }
    if as_i64(required_int(protected, 1, "protected header")?, "signature algorithm")?
        != SUPPORTED_ALG
    {
        return Err(error("unsupported signature algorithm"));
    }
    let claimed_kid = fixed_bytes::<8>(
        required_int(protected, 4, "protected header")?,
        "signing key id",
    )?;
    if claimed_kid != key_id(public_key)? {
        return Err(error("signing key id does not match"));
    }

    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(sign1.protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(sign1.payload.clone()),
    ]);
    let sig_structure = encode_canonical(&sig_structure)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key.to_encoded_point(false).as_bytes())
        .map_err(|_| error("invalid verifying key"))?;
    let signature = Signature::from_slice(&sign1.signature)
        .map_err(|_| error("invalid ES256 signature encoding"))?;
    verifying_key
        .verify(&sig_structure, &signature)
        .map_err(|_| error("signature invalid"))?;

    let payload = decode_value(&sign1.payload, "signed payload")?;
    if encode_canonical(&payload)? != sign1.payload {
        return Err(error("signed payload is not deterministic CBOR"));
    }
    as_map(&payload, "signed payload")?;
    Ok(payload)
}

#[derive(Debug, Clone)]
pub struct Rights {
    pub use_mode: u64,
    pub personal_devices: bool,
    pub platforms: Option<Vec<String>>,
    pub use_until: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Deed {
    pub asset_id: String,
    pub deed_id: [u8; 16],
    pub issuer_id: [u8; 16],
    pub owner_id: [u8; 16],
    pub rights: Rights,
    pub issued_at: u64,
}

fn verify_rights(value: &Value) -> Result<Rights> {
    let entries = as_map(value, "rights")?;
    for key in 1..=6 {
        required_int(entries, key, "rights")?;
    }

    let use_mode = as_u64(required_int(entries, 1, "rights")?, "use mode")?;
    if !matches!(use_mode, 0 | 1 | 2) {
        return Err(error("invalid use mode"));
    }
    let offline_mode = as_u64(required_int(entries, 2, "rights")?, "offline mode")?;
    if !matches!(offline_mode, 0 | 1 | 2) {
        return Err(error("invalid offline mode"));
    }
    let personal_devices = as_bool(required_int(entries, 3, "rights")?, "rights field 3")?;
    for key in 4..=6 {
        as_bool(required_int(entries, key, "rights")?, &format!("rights field {key}"))?;
    }

    let use_until = get_int(entries, 8)
        .map(|value| as_u64(value, "use_until"))
        .transpose()?;
    if use_mode == 1 && use_until.is_none() {
        return Err(error("use_until is required for fixed-time use"));
    }
    if use_mode != 1 && use_until.is_some() {
        return Err(error("use_until is only valid for fixed-time use"));
    }

    let platforms = if let Some(value) = get_int(entries, 7) {
        let values = as_array(value, "platforms")?;
        if values.is_empty() || values.len() > 32 {
            return Err(error("invalid platforms list"));
        }
        let mut output = Vec::with_capacity(values.len());
        for value in values {
            output.push(as_text(value, "platform", 32)?);
        }
        Some(output)
    } else {
        None
    };

    if let Some(value) = get_int(entries, 9) {
        let values = as_array(value, "service dependencies")?;
        if values.is_empty() || values.len() > 32 {
            return Err(error("invalid service dependency list"));
        }
        for value in values {
            as_text(value, "service dependency", 128)?;
        }
    }

    Ok(Rights {
        use_mode,
        personal_devices,
        platforms,
        use_until,
    })
}

pub fn verify_deed(raw: &[u8], signing_public_key: &PublicKey) -> Result<Deed> {
    if raw.len() > 64 * 1024 {
        return Err(error("deed exceeds the maximum size"));
    }
    let payload = verify_signed_map(raw, signing_public_key)?;
    let entries = as_map(&payload, "deed payload")?;
    for key in 1..=8 {
        required_int(entries, key, "deed")?;
    }

    if let Some(value) = get_int(entries, 11) {
        let critical = as_array(value, "critical field list")?;
        if critical.len() > 32 {
            return Err(error("invalid critical field list"));
        }
        for field in critical {
            let field = as_u64(field, "critical field label")?;
            if !(1..=11).contains(&field) {
                return Err(error(format!("unknown critical field {field}")));
            }
        }
    }

    if as_u64(required_int(entries, 1, "deed")?, "DADE version")? != 1 {
        return Err(error("unsupported DADE version"));
    }
    let deed_id = fixed_bytes(required_int(entries, 2, "deed")?, "deed_id")?;
    let asset_id = as_text(required_int(entries, 3, "deed")?, "asset_id", 255)?;
    let issuer_id = fixed_bytes(required_int(entries, 4, "deed")?, "issuer_id")?;
    let owner_id = fixed_bytes(required_int(entries, 5, "deed")?, "owner_id")?;
    let rights = verify_rights(required_int(entries, 6, "deed")?)?;
    let issued_at = as_u64(required_int(entries, 7, "deed")?, "issued_at")?;
    fixed_bytes::<32>(required_int(entries, 8, "deed")?, "terms_sha256")?;
    if let Some(value) = get_int(entries, 9) {
        as_text(value, "terms_uri", 2048)?;
    }
    if let Some(value) = get_int(entries, 10) {
        as_text(value, "edition", 128)?;
    }

    Ok(Deed {
        asset_id,
        deed_id,
        issuer_id,
        owner_id,
        rights,
        issued_at,
    })
}

#[derive(Debug, Clone)]
pub struct SigningCredential {
    pub credential_id: [u8; 16],
    pub issuer_id: [u8; 16],
    pub signing_key_id: [u8; 8],
    pub signing_public_key: PublicKey,
    pub valid_from: u64,
    pub valid_until: u64,
}

pub fn verify_signing_credential(
    raw: &[u8],
    root_public_key: &PublicKey,
    expected_issuer_id: [u8; 16],
) -> Result<SigningCredential> {
    let payload = verify_signed_map(raw, root_public_key)?;
    let entries = as_map(&payload, "signing credential")?;
    exact_keys(entries, &[1, 2, 3, 4, 5, 6, 7], "signing credential")?;
    if as_u64(required_int(entries, 1, "signing credential")?, "signing credential version")? != 1 {
        return Err(error("unsupported signing credential version"));
    }
    let credential_id = fixed_bytes(required_int(entries, 2, "signing credential")?, "signing credential_id")?;
    let claimed_issuer_id = fixed_bytes(required_int(entries, 3, "signing credential")?, "signing credential issuer_id")?;
    let claimed_key_id = fixed_bytes(required_int(entries, 4, "signing credential")?, "signing credential key_id")?;
    let signing_public_key = cose_public_key(required_int(entries, 5, "signing credential")?)?;
    if key_id(&signing_public_key)? != claimed_key_id {
        return Err(error("signing key id does not match signing key"));
    }
    let valid_from = as_u64(required_int(entries, 6, "signing credential")?, "valid_from")?;
    let valid_until = as_u64(required_int(entries, 7, "signing credential")?, "valid_until")?;
    if valid_until < valid_from {
        return Err(error("signing credential validity window is invalid"));
    }
    let derived_issuer = issuer_id(root_public_key)?;
    if claimed_issuer_id != derived_issuer {
        return Err(error("signing credential belongs to the wrong issuer root"));
    }
    if claimed_issuer_id != expected_issuer_id {
        return Err(error("signing credential issuer does not match"));
    }
    Ok(SigningCredential {
        credential_id,
        issuer_id: claimed_issuer_id,
        signing_key_id: claimed_key_id,
        signing_public_key,
        valid_from,
        valid_until,
    })
}

#[derive(Debug, Clone)]
pub struct OwnerTrustState {
    pub owner_id: [u8; 16],
    pub sequence: u64,
    pub revoked_controllers: HashMap<[u8; 16], u64>,
}

pub fn verify_owner_trust_snapshot(
    raw: &[u8],
    anchor_public_key: &PublicKey,
    minimum_sequence: Option<u64>,
) -> Result<OwnerTrustState> {
    let payload = verify_signed_map(raw, anchor_public_key)?;
    let entries = as_map(&payload, "owner trust snapshot")?;
    exact_keys(entries, &[1, 2, 3, 4, 5], "owner trust snapshot")?;
    if as_u64(required_int(entries, 1, "owner trust snapshot")?, "owner trust version")? != 1 {
        return Err(error("unsupported owner trust snapshot version"));
    }
    let expected_owner = owner_id(anchor_public_key)?;
    let claimed_owner = fixed_bytes(required_int(entries, 2, "owner trust snapshot")?, "owner trust owner_id")?;
    if claimed_owner != expected_owner {
        return Err(error("owner trust snapshot belongs to the wrong owner"));
    }
    let sequence = as_u64(required_int(entries, 3, "owner trust snapshot")?, "trust snapshot sequence")?;
    if minimum_sequence.is_some_and(|minimum| sequence < minimum) {
        return Err(error("trust snapshot is older than remembered state"));
    }
    as_u64(required_int(entries, 4, "owner trust snapshot")?, "owner trust issued_at")?;
    let values = as_array(required_int(entries, 5, "owner trust snapshot")?, "revoked controller list")?;
    if values.len() > 1024 {
        return Err(error("too many revoked controllers"));
    }
    let mut revoked = HashMap::new();
    for value in values {
        let entry = as_map(value, "revoked controller entry")?;
        exact_keys(entry, &[1, 2], "revoked controller entry")?;
        let controller = fixed_bytes(required_int(entry, 1, "revoked controller entry")?, "revoked controller_id")?;
        let revoked_at = as_u64(required_int(entry, 2, "revoked controller entry")?, "controller revoked_at")?;
        if revoked.insert(controller, revoked_at).is_some() {
            return Err(error("duplicate revoked controller"));
        }
    }
    Ok(OwnerTrustState {
        owner_id: claimed_owner,
        sequence,
        revoked_controllers: revoked,
    })
}

#[derive(Debug, Clone)]
pub struct IssuerTrustState {
    pub issuer_id: [u8; 16],
    pub sequence: u64,
    pub rejected_signing_keys: HashMap<[u8; 8], u64>,
}

pub fn verify_issuer_trust_snapshot(
    raw: &[u8],
    root_public_key: &PublicKey,
    minimum_sequence: Option<u64>,
) -> Result<IssuerTrustState> {
    let payload = verify_signed_map(raw, root_public_key)?;
    let entries = as_map(&payload, "issuer trust snapshot")?;
    exact_keys(entries, &[1, 2, 3, 4, 5], "issuer trust snapshot")?;
    if as_u64(required_int(entries, 1, "issuer trust snapshot")?, "issuer trust version")? != 1 {
        return Err(error("unsupported issuer trust snapshot version"));
    }
    let expected_issuer = issuer_id(root_public_key)?;
    let claimed_issuer = fixed_bytes(required_int(entries, 2, "issuer trust snapshot")?, "issuer trust issuer_id")?;
    if claimed_issuer != expected_issuer {
        return Err(error("issuer trust snapshot belongs to the wrong issuer"));
    }
    let sequence = as_u64(required_int(entries, 3, "issuer trust snapshot")?, "trust snapshot sequence")?;
    if minimum_sequence.is_some_and(|minimum| sequence < minimum) {
        return Err(error("trust snapshot is older than remembered state"));
    }
    as_u64(required_int(entries, 4, "issuer trust snapshot")?, "issuer trust issued_at")?;
    let values = as_array(required_int(entries, 5, "issuer trust snapshot")?, "rejected signing-key list")?;
    if values.len() > 1024 {
        return Err(error("too many rejected signing keys"));
    }
    let mut rejected = HashMap::new();
    for value in values {
        let entry = as_map(value, "rejected signing-key entry")?;
        exact_keys(entry, &[1, 2], "rejected signing-key entry")?;
        let signing_key = fixed_bytes(required_int(entry, 1, "rejected signing-key entry")?, "rejected signing key_id")?;
        let reject_from = as_u64(required_int(entry, 2, "rejected signing-key entry")?, "reject_from")?;
        if rejected.insert(signing_key, reject_from).is_some() {
            return Err(error("duplicate rejected signing key"));
        }
    }
    Ok(IssuerTrustState {
        issuer_id: claimed_issuer,
        sequence,
        rejected_signing_keys: rejected,
    })
}

#[derive(Debug, Clone)]
pub struct ControllerCredential {
    pub controller_id: [u8; 16],
    pub public_key: PublicKey,
    pub scopes: HashSet<u64>,
}

pub fn verify_controller_credential(
    raw: &[u8],
    anchor_public_key: &PublicKey,
    expected_owner_id: [u8; 16],
) -> Result<ControllerCredential> {
    let payload = verify_signed_map(raw, anchor_public_key)?;
    let entries = as_map(&payload, "controller credential")?;
    required_subset(entries, &[1, 2, 3, 4, 5, 6, 7], &[1, 2, 3, 4, 5, 6, 7, 8], "controller credential")?;
    if as_u64(required_int(entries, 1, "controller credential")?, "controller credential version")? != 1 {
        return Err(error("unsupported controller credential version"));
    }
    fixed_bytes::<16>(required_int(entries, 2, "controller credential")?, "controller credential_id")?;
    let owner = fixed_bytes(required_int(entries, 3, "controller credential")?, "controller owner_id")?;
    if owner != expected_owner_id {
        return Err(error("controller belongs to the wrong owner"));
    }
    let claimed_controller = fixed_bytes(required_int(entries, 4, "controller credential")?, "controller_id")?;
    let public_key = cose_public_key(required_int(entries, 5, "controller credential")?)?;
    if controller_id(&public_key)? != claimed_controller {
        return Err(error("controller_id does not match controller key"));
    }
    let scope_values = as_array(required_int(entries, 6, "controller credential")?, "controller scopes")?;
    if scope_values.is_empty() {
        return Err(error("controller scopes must be a non-empty array"));
    }
    let mut scopes = HashSet::new();
    for value in scope_values {
        let scope = as_u64(value, "controller scope")?;
        if !scopes.insert(scope) {
            return Err(error("controller scopes must not contain duplicates"));
        }
    }
    let issued_at = as_u64(required_int(entries, 7, "controller credential")?, "controller issued_at")?;
    if let Some(value) = get_int(entries, 8) {
        let expires_at = as_u64(value, "controller expires_at")?;
        if expires_at < issued_at {
            return Err(error("controller expires_at precedes issued_at"));
        }
    }
    Ok(ControllerCredential {
        controller_id: claimed_controller,
        public_key,
        scopes,
    })
}

#[derive(Debug, Clone)]
pub struct DeviceAuthorization {
    pub device_id: [u8; 16],
    pub public_key: PublicKey,
    pub scopes: HashSet<u64>,
}

pub fn verify_device_authorization(
    raw: &[u8],
    controller_public_key: &PublicKey,
    expected_owner_id: [u8; 16],
    expected_controller_id: [u8; 16],
) -> Result<DeviceAuthorization> {
    let payload = verify_signed_map(raw, controller_public_key)?;
    let entries = as_map(&payload, "device authorization")?;
    required_subset(entries, &[1, 2, 3, 4, 5, 6, 7, 8], &[1, 2, 3, 4, 5, 6, 7, 8, 9], "device authorization")?;
    if as_u64(required_int(entries, 1, "device authorization")?, "device authorization version")? != 1 {
        return Err(error("unsupported device authorization version"));
    }
    fixed_bytes::<16>(required_int(entries, 2, "device authorization")?, "device authorization_id")?;
    let owner = fixed_bytes(required_int(entries, 3, "device authorization")?, "device owner_id")?;
    if owner != expected_owner_id {
        return Err(error("device belongs to the wrong owner"));
    }
    let controller = fixed_bytes(required_int(entries, 4, "device authorization")?, "device controller_id")?;
    if controller != expected_controller_id {
        return Err(error("device authorization was issued by the wrong controller"));
    }
    let claimed_device = fixed_bytes(required_int(entries, 5, "device authorization")?, "device_id")?;
    let public_key = cose_public_key(required_int(entries, 6, "device authorization")?)?;
    if device_id(&public_key)? != claimed_device {
        return Err(error("device_id does not match device key"));
    }
    let scope_values = as_array(required_int(entries, 7, "device authorization")?, "device scopes")?;
    if scope_values.is_empty() {
        return Err(error("device scopes must be a non-empty array"));
    }
    let mut scopes = HashSet::new();
    for value in scope_values {
        let scope = as_u64(value, "device scope")?;
        if !scopes.insert(scope) {
            return Err(error("device scopes must not contain duplicates"));
        }
    }
    let issued_at = as_u64(required_int(entries, 8, "device authorization")?, "device issued_at")?;
    if let Some(value) = get_int(entries, 9) {
        let expires_at = as_u64(value, "device expires_at")?;
        if expires_at < issued_at {
            return Err(error("device expires_at precedes issued_at"));
        }
    }
    Ok(DeviceAuthorization {
        device_id: claimed_device,
        public_key,
        scopes,
    })
}

pub fn verify_device_proof(
    raw: &[u8],
    device_public_key: &PublicKey,
    expected_challenge: &[u8; 32],
    expected_asset: &str,
    expected_owner_id: [u8; 16],
    expected_device_id: [u8; 16],
) -> Result<()> {
    let payload = verify_signed_map(raw, device_public_key)?;
    let entries = as_map(&payload, "device proof")?;
    exact_keys(entries, &[1, 2, 3, 4, 5, 6], "device proof")?;
    if as_u64(required_int(entries, 1, "device proof")?, "device proof version")? != 1 {
        return Err(error("unsupported device proof version"));
    }
    let challenge = fixed_bytes::<32>(required_int(entries, 2, "device proof")?, "device proof challenge")?;
    if &challenge != expected_challenge {
        return Err(error("device proof challenge does not match"));
    }
    let asset = as_text(required_int(entries, 3, "device proof")?, "device proof asset_id", 255)?;
    if asset != expected_asset {
        return Err(error("device proof asset does not match"));
    }
    if as_u64(required_int(entries, 4, "device proof")?, "device proof right")? != RIGHT_USE {
        return Err(error("device proof right does not match"));
    }
    let owner = fixed_bytes(required_int(entries, 5, "device proof")?, "device proof owner_id")?;
    if owner != expected_owner_id {
        return Err(error("device proof owner does not match"));
    }
    let device = fixed_bytes(required_int(entries, 6, "device proof")?, "device proof device_id")?;
    if device != expected_device_id {
        return Err(error("device proof device does not match"));
    }
    Ok(())
}

pub fn sign_device_proof(
    private_key: &SecretKey,
    challenge: [u8; 32],
    asset_id: &str,
    owner: [u8; 16],
    device: [u8; 16],
) -> Result<Vec<u8>> {
    let public_key = private_key.public_key();
    let protected = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(SUPPORTED_ALG.into())),
        (Value::Integer(4.into()), Value::Bytes(key_id(&public_key)?.to_vec())),
    ]);
    let protected = encode_canonical(&protected)?;
    let payload = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(1.into())),
        (Value::Integer(2.into()), Value::Bytes(challenge.to_vec())),
        (Value::Integer(3.into()), Value::Text(asset_id.to_string())),
        (Value::Integer(4.into()), Value::Integer(RIGHT_USE.into())),
        (Value::Integer(5.into()), Value::Bytes(owner.to_vec())),
        (Value::Integer(6.into()), Value::Bytes(device.to_vec())),
    ]);
    let payload = encode_canonical(&payload)?;
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.clone()),
    ]);
    let sig_structure = encode_canonical(&sig_structure)?;
    let signing_key = SigningKey::from(private_key.clone());
    let signature: Signature = signing_key.sign(&sig_structure);
    let cose = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(signature.to_bytes().to_vec()),
        ])),
    );
    encode_canonical(&cose)
}
