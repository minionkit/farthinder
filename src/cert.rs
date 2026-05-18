use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

struct HostCert {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

pub struct CaState {
    ca_params: CertificateParams,
    ca_key: KeyPair,
    ca_cert_pem: String,
    host_certs: HashMap<String, HostCert>,
}

impl CaState {
    pub fn new() -> anyhow::Result<Self> {
        let ca_key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "farthinder CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = params.self_signed(&ca_key)?;
        let ca_cert_pem = ca_cert.pem();
        Ok(Self {
            ca_params: params,
            ca_key,
            ca_cert_pem,
            host_certs: HashMap::new(),
        })
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn tls_acceptor_for_host(&mut self, host: &str) -> anyhow::Result<TlsAcceptor> {
        if !self.host_certs.contains_key(host) {
            let host_key = KeyPair::generate()?;
            let mut params = CertificateParams::new(vec![host.to_string()])?;
            params.distinguished_name.push(DnType::CommonName, host);
            let issuer = Issuer::new(self.ca_params.clone(), &self.ca_key);
            let host_cert = params.signed_by(&host_key, &issuer)?;

            let cert_der = CertificateDer::from(host_cert.der().to_vec());
            let key_der = PrivateKeyDer::from(host_key);
            self.host_certs.insert(
                host.to_string(),
                HostCert {
                    cert: cert_der,
                    key: key_der,
                },
            );
        }

        let entry = self.host_certs.get(host).context("host cert missing")?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![entry.cert.clone()], entry.key.clone_key())
            .context("invalid TLS config")?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}
