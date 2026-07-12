// Per-hub certificate authority. The hub generates a CA once (persisted to
// HUB_DATA) and signs short-lived leaf certs for agents, so a controller (MCP /
// CLI) can validate a *direct* LAN connection to an agent against the hub CA —
// no self-signed `-k`. The CA public cert is served at /ca.crt for controllers
// to trust; leaves are minted on demand over the relay at /relay/cert.
use std::sync::OnceLock;

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

use crate::data_dir;

fn ca_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    (data_dir().join("ca.crt"), data_dir().join("ca.key"))
}

/// The hub CA cert PEM + its key pair — loaded from HUB_DATA or generated once.
fn ca() -> &'static (String, KeyPair) {
    static CA: OnceLock<(String, KeyPair)> = OnceLock::new();
    CA.get_or_init(|| {
        let (cp, kp) = ca_paths();
        if let (Ok(cert_pem), Ok(key_pem)) = (std::fs::read_to_string(&cp), std::fs::read_to_string(&kp)) {
            if let Ok(key) = KeyPair::from_pem(&key_pem) {
                return (cert_pem, key);
            }
        }
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "HaiveControl Hub CA");
        params.distinguished_name = dn;
        let key = KeyPair::generate().expect("ca key");
        let cert = params.self_signed(&key).expect("ca self-signed");
        let cert_pem = cert.pem();
        let _ = std::fs::create_dir_all(data_dir());
        let _ = std::fs::write(&cp, &cert_pem);
        let _ = std::fs::write(&kp, key.serialize_pem());
        (cert_pem, key)
    })
}

/// The CA public cert PEM (served at /ca.crt so controllers can trust it).
pub fn ca_cert_pem() -> String {
    ca().0.clone()
}

/// Sign a leaf cert for the given SANs (an agent's LAN IPs + its stable name).
/// Returns (cert_pem, key_pem). Phase 1 mints the leaf key here; Phase 2 can
/// switch to a CSR so the key never leaves the agent.
pub fn sign_leaf(sans: Vec<String>) -> Option<(String, String)> {
    let (ca_cert_pem, ca_key) = ca();
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem).ok()?;
    let ca_cert = ca_params.self_signed(ca_key).ok()?;
    let mut leaf = CertificateParams::new(sans).ok()?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "haive-agent");
    leaf.distinguished_name = dn;
    let leaf_key = KeyPair::generate().ok()?;
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, ca_key).ok()?;
    Some((leaf_cert.pem(), leaf_key.serialize_pem()))
}
