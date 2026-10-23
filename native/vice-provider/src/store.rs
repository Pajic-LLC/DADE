use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MAX_PEM_BYTES: u64 = 64 * 1024;
pub const MAX_HEX_TEXT_BYTES: u64 = 256 * 1024;

pub fn home_from_environment() -> Result<PathBuf, String> {
    if let Some(value) = env::var_os("DADE_HOME") {
        if !value.is_empty() {
            return Ok(PathBuf::from(value));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let base = env::var_os("LOCALAPPDATA")
            .ok_or_else(|| "DADE_HOME is not set and LOCALAPPDATA is unavailable".to_string())?;
        return Ok(PathBuf::from(base).join("DADE"));
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME")
            .ok_or_else(|| "DADE_HOME is not set and HOME is unavailable".to_string())?;
        return Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("DADE"));
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        if let Some(base) = env::var_os("XDG_DATA_HOME") {
            if !base.is_empty() {
                return Ok(PathBuf::from(base).join("dade"));
            }
        }
        let home = env::var_os("HOME")
            .ok_or_else(|| "DADE_HOME is not set and HOME is unavailable".to_string())?;
        Ok(PathBuf::from(home).join(".local").join("share").join("dade"))
    }
}

pub fn asset_root(home: &Path, asset_id: &str) -> PathBuf {
    home.join("assets").join(asset_id)
}

pub fn issuer_root(home: &Path, issuer_id: &[u8; 16]) -> PathBuf {
    home.join("trust").join("issuers").join(hex::encode(issuer_id))
}

pub fn owner_root(home: &Path, owner_id: &[u8; 16]) -> PathBuf {
    home.join("owners").join(hex::encode(owner_id))
}

pub fn device_key_path(home: &Path, device_id: &[u8; 16]) -> PathBuf {
    home.join("devices").join(format!("{}.pem", hex::encode(device_id)))
}

pub fn issuer_sequence_path(home: &Path, issuer_id: &[u8; 16]) -> PathBuf {
    home.join("state")
        .join("issuers")
        .join(format!("{}.seq", hex::encode(issuer_id)))
}

pub fn owner_sequence_path(home: &Path, owner_id: &[u8; 16]) -> PathBuf {
    home.join("state")
        .join("owners")
        .join(format!("{}.seq", hex::encode(owner_id)))
}

pub fn read_bytes(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    if metadata.len() > max_bytes {
        return Err(format!("{} is too large", path.display()));
    }
    fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))
}

pub fn read_pem(path: &Path) -> Result<Vec<u8>, String> {
    read_bytes(path, MAX_PEM_BYTES)
}

pub fn read_hex(path: &Path) -> Result<Vec<u8>, String> {
    let raw = read_bytes(path, MAX_HEX_TEXT_BYTES)?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| format!("{} is not UTF-8 hex text", path.display()))?;
    let compact: String = text.chars().filter(|value| !value.is_whitespace()).collect();
    if compact.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    hex::decode(&compact).map_err(|_| format!("{} contains invalid hex", path.display()))
}

pub fn read_fixed_hex<const N: usize>(path: &Path) -> Result<[u8; N], String> {
    let value = read_hex(path)?;
    value
        .try_into()
        .map_err(|_| format!("{} must contain exactly {N} bytes", path.display()))
}

pub fn read_optional_hex(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(format!("{} is not a file", path.display()));
            }
            read_hex(path).map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("could not inspect {}: {error}", path.display())),
    }
}

pub fn read_sequence(path: &Path) -> Result<Option<u64>, String> {
    let raw = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not read {}: {error}", path.display())),
    };
    let value = raw
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{} contains an invalid trust sequence", path.display()))?;
    Ok(Some(value))
}

pub fn remember_sequence(path: &Path, sequence: u64) -> Result<(), String> {
    if read_sequence(path)?.is_some_and(|current| current >= sequence) {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create {}: {error}", parent.display()))?;

    let temporary = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&temporary)
            .map_err(|error| format!("could not create {}: {error}", temporary.display()))?;
        writeln!(file, "{sequence}")
            .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("could not sync {}: {error}", temporary.display()))?;
    }

    #[cfg(target_os = "windows")]
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("could not replace {}: {error}", path.display()))?;
    }

    fs::rename(&temporary, path)
        .map_err(|error| format!("could not install {}: {error}", path.display()))?;
    Ok(())
}
