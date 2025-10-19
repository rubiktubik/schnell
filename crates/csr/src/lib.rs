use chrono::Utc;
use core_lib::shared::{
    errors::KeyGenError,
    models::{CreateCsrRequest, PrivateKeyPEM},
    ports::KeyGeneratorPort,
};
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey, pkcs8::LineEnding};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Default)]
pub struct PlaceholderKeyGenerator;

impl PlaceholderKeyGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl KeyGeneratorPort for PlaceholderKeyGenerator {
    fn generate_private_key(
        &self,
        output_path: Option<PathBuf>,
    ) -> Result<PrivateKeyPEM, KeyGenError> {
        let path_ref = output_path.as_deref();
        generate_private_key_impl(path_ref)
    }

    fn create_csr(&self, req: &CreateCsrRequest) -> Result<String, KeyGenError> {
        create_csr_impl(req)
    }
}

fn generate_private_key_impl(output_path: Option<&Path>) -> Result<PrivateKeyPEM, KeyGenError> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|err| KeyGenError::GenerateKey(err.to_string()))?;
    let pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|err| KeyGenError::SerializePrivateKey(err.to_string()))?;

    let pem_string = pem.to_string();
    let file_path = resolve_output_path(output_path)?;

    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| KeyGenError::PersistPrivateKey(err.to_string()))?;
    }

    fs::write(&file_path, pem_string.as_bytes())
        .map_err(|err| KeyGenError::PersistPrivateKey(err.to_string()))?;

    Ok(PrivateKeyPEM {
        content: pem_string,
        path: file_path.to_string_lossy().into_owned(),
    })
}

fn resolve_output_path(output_path: Option<&Path>) -> Result<PathBuf, KeyGenError> {
    let base_path = match output_path {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()
            .map_err(|err| KeyGenError::ResolvePrivateKeyPath(err.to_string()))?,
    };

    let is_file = output_path
        .map(|path| path.extension().is_some())
        .unwrap_or(false);

    if is_file {
        return Ok(base_path);
    }

    let filename = format!("private_key_{}.key", Utc::now().format("%Y%m%d%H%M%S"));
    Ok(base_path.join(filename))
}

fn create_csr_impl(req: &CreateCsrRequest) -> Result<String, KeyGenError> {
    let key_pair = KeyPair::from_pem(req.private_key_pem.content.as_str())
        .map_err(|err| KeyGenError::InvalidPrivateKey(err.to_string()))?;

    let mut params = CertificateParams::default();
    params.distinguished_name = build_placeholder_dn();

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|err| KeyGenError::CsrGeneration(err.to_string()))?;

    csr.pem()
        .map_err(|err| KeyGenError::CsrGeneration(err.to_string()))
}

fn build_placeholder_dn() -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "CSR");
    dn
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_key_to_specified_directory() {
        let dir = tempdir().expect("tempdir");

        let key = generate_private_key_impl(Some(dir.path())).expect("key generated");

        let saved_path = PathBuf::from(&key.path);
        assert!(saved_path.starts_with(dir.path()));
        assert_eq!(
            saved_path.extension().and_then(|ext| ext.to_str()),
            Some("key")
        );
        assert_eq!(fs::read_to_string(&saved_path).expect("read"), key.content);
    }

    #[test]
    fn uses_provided_file_path_when_extension_present() {
        let dir = tempdir().expect("tempdir");
        let target_file = dir.path().join("custom-name.key");

        let key = generate_private_key_impl(Some(target_file.as_path())).expect("key generated");

        assert_eq!(Path::new(&key.path), target_file.as_path());
        assert!(target_file.exists());
    }
}
