mod protocol;
mod store;

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};

use protocol::{
    controller_id, device_id, issuer_id, load_private_key, load_public_key, owner_id,
    peek_deed_issuer, sign_device_proof, verify_controller_credential, verify_deed,
    verify_device_authorization, verify_device_proof, verify_issuer_trust_snapshot,
    verify_owner_trust_snapshot, verify_signing_credential, CONTROLLER_SCOPE_AUTHORIZE_DEVICES,
    DEVICE_SCOPE_USE_OWNED_ASSETS,
};

const ABI_VERSION: u32 = 1;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionCode {
    Owned = 0,
    NotOwned = 1,
    WrongAsset = 2,
    InvalidDeed = 3,
    UntrustedIssuer = 4,
    OwnerProofFailed = 5,
    DeviceNotAuthorized = 6,
    DeviceProofFailed = 7,
    ControllerRevoked = 8,
    IssuerKeyRevoked = 9,
    TrustStateRollback = 10,
    RightNotGranted = 11,
    ProviderError = 12,
}

impl DecisionCode {
    fn name(self) -> &'static str {
        match self {
            Self::Owned => "owned",
            Self::NotOwned => "not_owned",
            Self::WrongAsset => "wrong_asset",
            Self::InvalidDeed => "invalid_deed",
            Self::UntrustedIssuer => "untrusted_issuer",
            Self::OwnerProofFailed => "owner_proof_failed",
            Self::DeviceNotAuthorized => "device_not_authorized",
            Self::DeviceProofFailed => "device_proof_failed",
            Self::ControllerRevoked => "controller_revoked",
            Self::IssuerKeyRevoked => "issuer_key_revoked",
            Self::TrustStateRollback => "trust_state_rollback",
            Self::RightNotGranted => "right_not_granted",
            Self::ProviderError => "provider_error",
        }
    }
}

#[derive(Debug, Clone)]
struct Decision {
    code: DecisionCode,
    detail: String,
}

impl Decision {
    fn allow(detail: impl Into<String>) -> Self {
        Self {
            code: DecisionCode::Owned,
            detail: detail.into(),
        }
    }

    fn deny(code: DecisionCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

#[repr(C)]
pub struct VerifyRequest {
    abi_version: u32,
    size: usize,
    asset_id: *const c_char,
    platform: *const c_char,
    project_root: *const c_char,
}

#[repr(C)]
pub struct VerifyResult {
    abi_version: u32,
    size: usize,
    code: DecisionCode,
    detail: *const c_char,
}

thread_local! {
    static DETAIL_BUFFER: RefCell<CString> = RefCell::new(
        CString::new("provider error").expect("static detail has no NUL")
    );
}

fn detail_pointer(detail: &str) -> *const c_char {
    DETAIL_BUFFER.with(|buffer| {
        let clean = detail.replace('\0', " ");
        *buffer.borrow_mut() = CString::new(clean)
            .unwrap_or_else(|_| CString::new("provider error").expect("static detail has no NUL"));
        buffer.borrow().as_ptr()
    })
}

fn valid_asset_id(asset_id: &str) -> bool {
    let bytes = asset_id.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 || !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_')
    })
}

fn valid_platform(platform: &str) -> bool {
    !platform.is_empty()
        && platform.len() <= 32
        && platform
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_'))
}

fn protocol_detail(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".to_string())
}

fn read_required_hex(path: &Path, code: DecisionCode, label: &str) -> Result<Vec<u8>, Decision> {
    store::read_hex(path).map_err(|error| {
        Decision::deny(code, format!("could not load {label}: {error}"))
    })
}

fn read_required_pem(path: &Path, code: DecisionCode, label: &str) -> Result<Vec<u8>, Decision> {
    store::read_pem(path).map_err(|error| {
        Decision::deny(code, format!("could not load {label}: {error}"))
    })
}

fn verify_at_home(home: &Path, asset_id: &str, platform: &str) -> Decision {
    if !valid_asset_id(asset_id) {
        return Decision::deny(DecisionCode::ProviderError, "DADE asset ID is invalid");
    }
    if !valid_platform(platform) {
        return Decision::deny(DecisionCode::ProviderError, "platform identifier is invalid");
    }

    let asset_root = store::asset_root(home, asset_id);
    let deed_path = asset_root.join("deed.hex");
    match fs::metadata(&deed_path) {
        Ok(metadata) if !metadata.is_file() => {
            return Decision::deny(DecisionCode::InvalidDeed, "local deed path is not a file");
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Decision::deny(DecisionCode::NotOwned, "no local deed is available");
        }
        Err(error) => {
            return Decision::deny(
                DecisionCode::ProviderError,
                format!("could not inspect local deed: {error}"),
            );
        }
    }

    let declared_issuer = match store::read_fixed_hex::<16>(&asset_root.join("issuer-id.hex")) {
        Ok(value) => value,
        Err(error) => {
            return Decision::deny(
                DecisionCode::ProviderError,
                format!("could not load asset issuer metadata: {error}"),
            );
        }
    };

    let deed_raw = match store::read_hex(&deed_path) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::InvalidDeed, error),
    };

    if let Ok(peeked_issuer) = peek_deed_issuer(&deed_raw) {
        if peeked_issuer != declared_issuer {
            return Decision::deny(
                DecisionCode::UntrustedIssuer,
                "deed issuer does not match local asset issuer metadata",
            );
        }
    }

    let issuer_root = store::issuer_root(home, &declared_issuer);
    let root_pem = match read_required_pem(
        &issuer_root.join("root.pem"),
        DecisionCode::UntrustedIssuer,
        "trusted issuer root",
    ) {
        Ok(value) => value,
        Err(decision) => return decision,
    };
    let root_public_key = match load_public_key(&root_pem, "issuer root public key") {
        Ok(value) => value,
        Err(error) => {
            return Decision::deny(DecisionCode::UntrustedIssuer, protocol_detail(error));
        }
    };
    let derived_issuer = match issuer_id(&root_public_key) {
        Ok(value) => value,
        Err(error) => {
            return Decision::deny(DecisionCode::UntrustedIssuer, protocol_detail(error));
        }
    };
    if derived_issuer != declared_issuer {
        return Decision::deny(
            DecisionCode::UntrustedIssuer,
            "trusted issuer root does not match the asset issuer ID",
        );
    }

    let signing_credential_raw = match read_required_hex(
        &asset_root.join("signing-credential.hex"),
        DecisionCode::ProviderError,
        "issuer signing credential",
    ) {
        Ok(value) => value,
        Err(decision) => return decision,
    };
    let signing_credential = match verify_signing_credential(
        &signing_credential_raw,
        &root_public_key,
        declared_issuer,
    ) {
        Ok(value) => value,
        Err(error) => {
            return Decision::deny(DecisionCode::UntrustedIssuer, protocol_detail(error));
        }
    };

    let deed = match verify_deed(&deed_raw, &signing_credential.signing_public_key) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::InvalidDeed, protocol_detail(error)),
    };
    if deed.asset_id != asset_id {
        return Decision::deny(DecisionCode::WrongAsset, "deed belongs to another asset");
    }
    if deed.issuer_id != declared_issuer {
        return Decision::deny(
            DecisionCode::UntrustedIssuer,
            "deed issuer does not match trusted issuer",
        );
    }
    if deed.issued_at < signing_credential.valid_from || deed.issued_at > signing_credential.valid_until {
        return Decision::deny(
            DecisionCode::UntrustedIssuer,
            "deed was issued outside the signing credential validity window",
        );
    }

    let issuer_snapshot_path = issuer_root.join("snapshot.hex");
    let issuer_snapshot = match store::read_optional_hex(&issuer_snapshot_path) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::ProviderError, error),
    };
    if let Some(snapshot_raw) = issuer_snapshot {
        let sequence_path = store::issuer_sequence_path(home, &declared_issuer);
        let remembered = match store::read_sequence(&sequence_path) {
            Ok(value) => value,
            Err(error) => return Decision::deny(DecisionCode::ProviderError, error),
        };
        let state = match verify_issuer_trust_snapshot(&snapshot_raw, &root_public_key, remembered) {
            Ok(value) => value,
            Err(error) if error.0.contains("older than remembered state") => {
                return Decision::deny(DecisionCode::TrustStateRollback, error.0);
            }
            Err(error) => {
                return Decision::deny(DecisionCode::UntrustedIssuer, error.0);
            }
        };
        if let Err(error) = store::remember_sequence(&sequence_path, state.sequence) {
            return Decision::deny(DecisionCode::ProviderError, error);
        }
        if state.issuer_id != declared_issuer {
            return Decision::deny(
                DecisionCode::UntrustedIssuer,
                "issuer trust state belongs to another issuer",
            );
        }
        if let Some(reject_from) = state
            .rejected_signing_keys
            .get(&signing_credential.signing_key_id)
        {
            if deed.issued_at >= *reject_from {
                return Decision::deny(
                    DecisionCode::IssuerKeyRevoked,
                    "deed was issued after signing key compromise cutoff",
                );
            }
        }
    }

    if !deed.rights.personal_devices {
        return Decision::deny(
            DecisionCode::RightNotGranted,
            "deed does not allow use on personal devices",
        );
    }
    if let Some(platforms) = &deed.rights.platforms {
        if !platforms.iter().any(|candidate| candidate == platform) {
            return Decision::deny(
                DecisionCode::RightNotGranted,
                format!("deed does not include platform {platform}"),
            );
        }
    }
    match deed.rights.use_mode {
        0 => {}
        1 => {
            let now = match now_unix() {
                Ok(value) => value,
                Err(error) => return Decision::deny(DecisionCode::ProviderError, error),
            };
            let Some(use_until) = deed.rights.use_until else {
                return Decision::deny(DecisionCode::RightNotGranted, "fixed-time use has no end time");
            };
            if now > use_until {
                return Decision::deny(
                    DecisionCode::RightNotGranted,
                    "fixed-time use right has expired",
                );
            }
        }
        2 => {
            return Decision::deny(
                DecisionCode::RightNotGranted,
                "subscription state is not defined by the local DADE 1 provider",
            );
        }
        _ => {
            return Decision::deny(DecisionCode::RightNotGranted, "unsupported use right");
        }
    }

    let owner_root = store::owner_root(home, &deed.owner_id);
    let anchor_pem = match read_required_pem(
        &owner_root.join("anchor.pem"),
        DecisionCode::OwnerProofFailed,
        "owner anchor",
    ) {
        Ok(value) => value,
        Err(decision) => return decision,
    };
    let anchor_public_key = match load_public_key(&anchor_pem, "owner anchor public key") {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::OwnerProofFailed, error.0),
    };
    let derived_owner = match owner_id(&anchor_public_key) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::OwnerProofFailed, error.0),
    };
    if derived_owner != deed.owner_id {
        return Decision::deny(
            DecisionCode::OwnerProofFailed,
            "deed owner does not match identity anchor",
        );
    }

    let owner_snapshot_path = owner_root.join("snapshot.hex");
    let owner_snapshot = match store::read_optional_hex(&owner_snapshot_path) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::ProviderError, error),
    };
    let mut owner_trust = None;
    if let Some(snapshot_raw) = owner_snapshot {
        let sequence_path = store::owner_sequence_path(home, &deed.owner_id);
        let remembered = match store::read_sequence(&sequence_path) {
            Ok(value) => value,
            Err(error) => return Decision::deny(DecisionCode::ProviderError, error),
        };
        let state = match verify_owner_trust_snapshot(&snapshot_raw, &anchor_public_key, remembered) {
            Ok(value) => value,
            Err(error) if error.0.contains("older than remembered state") => {
                return Decision::deny(DecisionCode::TrustStateRollback, error.0);
            }
            Err(error) => return Decision::deny(DecisionCode::OwnerProofFailed, error.0),
        };
        if let Err(error) = store::remember_sequence(&sequence_path, state.sequence) {
            return Decision::deny(DecisionCode::ProviderError, error);
        }
        if state.owner_id != deed.owner_id {
            return Decision::deny(
                DecisionCode::OwnerProofFailed,
                "owner trust state belongs to another owner",
            );
        }
        owner_trust = Some(state);
    }

    let controller_raw = match read_required_hex(
        &owner_root.join("controller.hex"),
        DecisionCode::OwnerProofFailed,
        "controller credential",
    ) {
        Ok(value) => value,
        Err(decision) => return decision,
    };
    let controller = match verify_controller_credential(
        &controller_raw,
        &anchor_public_key,
        deed.owner_id,
    ) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::OwnerProofFailed, error.0),
    };
    if !controller
        .scopes
        .contains(&CONTROLLER_SCOPE_AUTHORIZE_DEVICES)
    {
        return Decision::deny(
            DecisionCode::DeviceNotAuthorized,
            "controller cannot authorize personal devices",
        );
    }
    if owner_trust
        .as_ref()
        .is_some_and(|state| state.revoked_controllers.contains_key(&controller.controller_id))
    {
        return Decision::deny(DecisionCode::ControllerRevoked, "controller has been revoked");
    }

    let device_authorization_raw = match read_required_hex(
        &owner_root.join("device-authorization.hex"),
        DecisionCode::DeviceNotAuthorized,
        "device authorization",
    ) {
        Ok(value) => value,
        Err(decision) => return decision,
    };
    let device = match verify_device_authorization(
        &device_authorization_raw,
        &controller.public_key,
        deed.owner_id,
        controller.controller_id,
    ) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::DeviceNotAuthorized, error.0),
    };
    if !device.scopes.contains(&DEVICE_SCOPE_USE_OWNED_ASSETS) {
        return Decision::deny(
            DecisionCode::DeviceNotAuthorized,
            "device cannot use owned assets",
        );
    }

    let device_key_pem = match read_required_pem(
        &store::device_key_path(home, &device.device_id),
        DecisionCode::DeviceProofFailed,
        "device signing key",
    ) {
        Ok(value) => value,
        Err(decision) => return decision,
    };
    let device_private_key = match load_private_key(&device_key_pem, "device signing key") {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::DeviceProofFailed, error.0),
    };
    let private_device_id = match device_id(&device_private_key.public_key()) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::DeviceProofFailed, error.0),
    };
    if private_device_id != device.device_id {
        return Decision::deny(
            DecisionCode::DeviceProofFailed,
            "device signing key does not match the authorized device",
        );
    }

    let mut challenge = [0_u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let proof = match sign_device_proof(
        &device_private_key,
        challenge,
        asset_id,
        deed.owner_id,
        device.device_id,
    ) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::DeviceProofFailed, error.0),
    };
    if let Err(error) = verify_device_proof(
        &proof,
        &device.public_key,
        &challenge,
        asset_id,
        deed.owner_id,
        device.device_id,
    ) {
        return Decision::deny(DecisionCode::DeviceProofFailed, error.0);
    }

    let controller_from_key = match controller_id(&controller.public_key) {
        Ok(value) => value,
        Err(error) => return Decision::deny(DecisionCode::OwnerProofFailed, error.0),
    };
    if controller_from_key != controller.controller_id {
        return Decision::deny(
            DecisionCode::OwnerProofFailed,
            "controller ID changed during verification",
        );
    }

    Decision::allow("local ownership proof is valid")
}

unsafe fn request_text(pointer: *const c_char, label: &str) -> Result<String, String> {
    if pointer.is_null() {
        return Err(format!("{label} is null"));
    }
    CStr::from_ptr(pointer)
        .to_str()
        .map(|value| value.to_string())
        .map_err(|_| format!("{label} is not UTF-8"))
}

unsafe fn write_result(output: *mut VerifyResult, decision: Decision) {
    let detail = detail_pointer(&decision.detail);
    *output = VerifyResult {
        abi_version: ABI_VERSION,
        size: std::mem::size_of::<VerifyResult>(),
        code: decision.code,
        detail,
    };
}

#[no_mangle]
pub unsafe extern "C" fn vice_dade_verify(
    host_abi_version: u32,
    request: *const VerifyRequest,
    result: *mut VerifyResult,
) -> bool {
    if host_abi_version != ABI_VERSION || request.is_null() || result.is_null() {
        return false;
    }
    if (*request).abi_version != ABI_VERSION || (*request).size < std::mem::size_of::<VerifyRequest>() {
        return false;
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let asset_id = unsafe { request_text((*request).asset_id, "asset_id") }?;
        let platform = unsafe { request_text((*request).platform, "platform") }?;
        let _project_root = unsafe { request_text((*request).project_root, "project_root") }?;
        let home = store::home_from_environment()?;
        Ok::<Decision, String>(verify_at_home(&home, &asset_id, &platform))
    }));

    let decision = match outcome {
        Ok(Ok(decision)) => decision,
        Ok(Err(error)) => Decision::deny(DecisionCode::ProviderError, error),
        Err(_) => Decision::deny(DecisionCode::ProviderError, "native DADE provider panicked"),
    };
    write_result(result, decision);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::path::PathBuf;

    fn fixture_root() -> PathBuf {
        std::env::var_os("DADE_FIXTURE_ROOT")
            .map(PathBuf::from)
            .expect("DADE_FIXTURE_ROOT must point to generated cross-language fixtures")
    }

    #[test]
    fn native_decisions_match_python_expectations() {
        let root = fixture_root();
        let expectations = std::fs::read_to_string(root.join("expectations.tsv"))
            .expect("read fixture expectations");
        for line in expectations.lines().skip(1) {
            let columns: Vec<_> = line.split('\t').collect();
            assert_eq!(columns.len(), 4, "invalid expectation row: {line}");
            let scenario = columns[0];
            let asset = columns[1];
            let platform = columns[2];
            let expected = columns[3];
            let decision = verify_at_home(&root.join(scenario), asset, platform);
            assert_eq!(
                decision.code.name(),
                expected,
                "scenario {scenario} returned {}: {}",
                decision.code.name(),
                decision.detail
            );
        }
    }

    #[test]
    fn vice_abi_returns_owned_for_reference_fixture() {
        let root = fixture_root().join("owned-abi");
        std::env::set_var("DADE_HOME", &root);

        let asset = CString::new("com.pajic.vice").unwrap();
        let platform = CString::new("windows").unwrap();
        let project = CString::new("fixture-project").unwrap();
        let request = VerifyRequest {
            abi_version: ABI_VERSION,
            size: std::mem::size_of::<VerifyRequest>(),
            asset_id: asset.as_ptr(),
            platform: platform.as_ptr(),
            project_root: project.as_ptr(),
        };
        let mut result = VerifyResult {
            abi_version: 0,
            size: 0,
            code: DecisionCode::ProviderError,
            detail: std::ptr::null(),
        };

        let completed = unsafe { vice_dade_verify(ABI_VERSION, &request, &mut result) };
        assert!(completed);
        assert_eq!(result.abi_version, ABI_VERSION);
        assert_eq!(result.size, std::mem::size_of::<VerifyResult>());
        assert_eq!(result.code, DecisionCode::Owned);
        assert!(!result.detail.is_null());
        let detail = unsafe { CStr::from_ptr(result.detail) }
            .to_str()
            .expect("ABI detail is UTF-8");
        assert_eq!(detail, "local ownership proof is valid");
    }
}
