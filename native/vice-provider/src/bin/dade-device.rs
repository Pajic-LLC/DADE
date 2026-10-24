#[cfg(target_os = "macos")]
#[path = "../device_signer.rs"]
mod device_signer;
#[cfg(target_os = "macos")]
#[path = "../protocol.rs"]
mod protocol;
#[cfg(target_os = "macos")]
#[path = "../store.rs"]
mod store;

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("dade-device Secure Enclave enrollment is only available on macOS");
    std::process::exit(1);
}
