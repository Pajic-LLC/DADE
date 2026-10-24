#[cfg(any(target_os = "macos", target_os = "windows"))]
#[path = "../device_signer.rs"]
mod device_signer;
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[path = "../protocol.rs"]
mod protocol;
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[path = "../store.rs"]
mod store;
#[cfg(target_os = "windows")]
#[path = "../windows_tpm_enrollment.rs"]
mod windows_tpm_enrollment;

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn parse_device_id(value: &str) -> Result<[u8; 16], String> {
    let raw = hex::decode(value).map_err(|_| "device ID is not valid hex".to_string())?;
    raw.try_into()
        .map_err(|_| "device ID must contain exactly 16 bytes".to_string())
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), String> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let mut arguments = std::env::args().skip(1);
    let Some(command) = arguments.next() else {
        return Err(
            "usage: dade-device enroll-macos | activate-macos <device-id-hex> <application-label-hex>"
                .to_string(),
        );
    };

    match command.as_str() {
        "enroll-macos" => {
            if arguments.next().is_some() {
                return Err("enroll-macos does not accept arguments".to_string());
            }
            let enrollment = device_signer::enroll_macos_secure_enclave()?;
            let public_key = enrollment.public_key.to_encoded_point(false);
            println!("device_id={}", hex::encode(enrollment.device_id));
            println!(
                "application_label={}",
                hex::encode(&enrollment.application_label)
            );
            println!("public_key_sec1={}", hex::encode(public_key.as_bytes()));
            println!(
                "signer_descriptor=macos-secure-enclave-v1 {}",
                hex::encode(&enrollment.application_label)
            );
            println!(
                "next=authorize this public key as the DADE device, then run activate-macos"
            );
            Ok(())
        }
        "activate-macos" => {
            let device_id = arguments
                .next()
                .ok_or_else(|| "activate-macos requires a device ID".to_string())?;
            let application_label = arguments
                .next()
                .ok_or_else(|| "activate-macos requires an application label".to_string())?;
            if arguments.next().is_some() {
                return Err("activate-macos received too many arguments".to_string());
            }

            let device_id = parse_device_id(&device_id)?;
            let application_label = hex::decode(application_label)
                .map_err(|_| "application label is not valid hex".to_string())?;
            let home = store::home_from_environment()?;
            device_signer::install_macos_secure_enclave_locator(
                &home,
                &device_id,
                &application_label,
            )?;
            println!(
                "installed={}",
                store::device_signer_path(&home, &device_id).display()
            );
            Ok(())
        }
        _ => Err(format!("unknown command `{command}`")),
    }
}

#[cfg(target_os = "windows")]
fn install_windows_tpm_locator(
    home: &std::path::Path,
    device_id: &[u8; 16],
    key_name: &str,
) -> Result<(), String> {
    use std::io::Write;

    if key_name.is_empty() || key_name.len() > 128 || key_name.contains('\0') {
        return Err("Windows TPM key name has an invalid length or value".to_string());
    }

    let public_key = windows_tpm_enrollment::public_key_for_name(key_name)?;
    let actual_device_id = protocol::device_id(&public_key).map_err(|error| error.to_string())?;
    if actual_device_id != *device_id {
        return Err("TPM key does not match the requested DADE device ID".to_string());
    }

    let path = store::device_signer_path(home, device_id);
    let parent = path
        .parent()
        .ok_or_else(|| "device signer descriptor has no parent directory".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("could not create device signer directory: {error}"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("could not create device signer descriptor: {error}"))?;
    writeln!(file, "windows-tpm-v1 {}", hex::encode(key_name.as_bytes()))
        .map_err(|error| format!("could not write device signer descriptor: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("could not sync device signer descriptor: {error}"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn run() -> Result<(), String> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let mut arguments = std::env::args().skip(1);
    let Some(command) = arguments.next() else {
        return Err(
            "usage: dade-device enroll-windows | activate-windows <device-id-hex> <key-name-hex>"
                .to_string(),
        );
    };

    match command.as_str() {
        "enroll-windows" => {
            if arguments.next().is_some() {
                return Err("enroll-windows does not accept arguments".to_string());
            }
            let enrollment = windows_tpm_enrollment::enroll()?;
            let public_key = enrollment.public_key.to_encoded_point(false);
            println!("device_id={}", hex::encode(enrollment.device_id));
            println!("key_name={}", hex::encode(enrollment.key_name.as_bytes()));
            println!("public_key_sec1={}", hex::encode(public_key.as_bytes()));
            println!(
                "signer_descriptor=windows-tpm-v1 {}",
                hex::encode(enrollment.key_name.as_bytes())
            );
            println!(
                "next=authorize this public key as the DADE device, then run activate-windows"
            );
            Ok(())
        }
        "activate-windows" => {
            let device_id = arguments
                .next()
                .ok_or_else(|| "activate-windows requires a device ID".to_string())?;
            let key_name = arguments
                .next()
                .ok_or_else(|| "activate-windows requires a key name".to_string())?;
            if arguments.next().is_some() {
                return Err("activate-windows received too many arguments".to_string());
            }

            let device_id = parse_device_id(&device_id)?;
            let key_name = hex::decode(key_name)
                .map_err(|_| "key name is not valid hex".to_string())?;
            let key_name = String::from_utf8(key_name)
                .map_err(|_| "key name is not valid UTF-8".to_string())?;
            let home = store::home_from_environment()?;
            install_windows_tpm_locator(&home, &device_id, &key_name)?;
            println!(
                "installed={}",
                store::device_signer_path(&home, &device_id).display()
            );
            Ok(())
        }
        _ => Err(format!("unknown command `{command}`")),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn main() {
    eprintln!("dade-device hardware enrollment is only available on macOS and Windows");
    std::process::exit(1);
}
