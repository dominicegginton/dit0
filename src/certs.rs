use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

pub trait CertLoader {
    fn load_certs(&self) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>;
}

pub struct Certificates {
    cert_dir: PathBuf,
}

impl Certificates {
    pub fn new(cert_dir: PathBuf) -> Self {
        Certificates { cert_dir }
    }
}

impl CertLoader for Certificates {
    fn load_certs(&self) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let mut crt_path: Option<PathBuf> = None;
        let mut key_path: Option<PathBuf> = None;

        if self.cert_dir.exists() {
            for entry in std::fs::read_dir(&self.cert_dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "crt" {
                        crt_path = Some(path);
                    } else if ext == "key"
                        && !path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .contains("acme-account")
                    {
                        key_path = Some(path);
                    }
                }
            }
        }

        let crt_path_val = crt_path.ok_or_else(|| anyhow::anyhow!("Certificate (.crt) not found in {:?}. Run with HTTP/80 first or manually generate certs.", self.cert_dir))?;
        let key_path_val = key_path.ok_or_else(|| {
            anyhow::anyhow!("Private key (.key) not found in {:?}.", self.cert_dir)
        })?;

        let certs =
            certs(&mut BufReader::new(File::open(crt_path_val)?)).collect::<Result<Vec<_>, _>>()?;
        let key_der = private_key(&mut BufReader::new(File::open(key_path_val)?))?
            .ok_or_else(|| anyhow::anyhow!("No private key found in file"))?;

        Ok((certs, key_der))
    }
}
