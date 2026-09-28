//! Network transports used by LocalGroups-rs to talk to Windows hosts.
//!
//! * `smb`: SMB and MS RPC transport. IPC$ pipes (here: `\samr`) for the local
//!   group module, and the SYSVOL share helpers kept verbatim from
//!   RustHound-CE so the two trees stay byte-identical.
//! * `gss`: minimal SPNEGO framing for a Kerberos AP-REQ carried in an SMB2
//!   SESSION_SETUP.
//! * `kerberos`: pass the ticket helper. Loads a TGT from a ccache, requests a
//!   cifs/<host> service ticket and builds the AP-REQ for SMB Kerberos auth.
//!
//! These three files are copied unchanged from RustHound-CE's `src/transport/`
//! <https://github.com/g0h4n/RustHound-CE/tree/main/src/transport> so that the
//! eventual port is a move, not a rewrite. Do not "improve" them here: fix
//! upstream first, then re-copy. The Kerberos path itself is RustHound-CE#61;
//! this tool's use of it is RustHound-CE#69.
//!
//! RustHound-CE's `ldap` and `cert` modules are deliberately absent, this tool
//! never speaks LDAP, and SAMR carries no client certificate path.
//!
//! The SYSVOL/file helpers in `smb` are unused by this binary; they are kept
//! for drift-freedom, hence the blanket allow below.

#![allow(dead_code)]

pub mod smb;
pub mod gss;
pub mod kerberos;

use anyhow::Result;
use log::debug;
use smb2_client::SmbClient;

/// How the operator asked us to authenticate, resolved once from the CLI.
///
/// This is the *configuration*; `smb::SmbAuth` is the *per-host credential*
/// derived from it. They differ because Kerberos material is host-specific:
/// the AP-REQ targets that host's `cifs/<host>` SPN, so it must be rebuilt for
/// every target, while a password or NT hash is reused as-is.
/// `Debug` is implemented by hand below so that a stray `{:?}` on `Options`
/// can never print a password or an NT hash.
#[derive(Clone)]
pub enum AuthConfig {
    /// NTLMv2 with a clear text password.
    Password(String),
    /// Pass the hash with a raw 16 byte NT hash.
    Hash([u8; 16]),
    /// Pass the ticket: path to the MIT ccache (KRB5CCNAME) plus the KDC to
    /// ask for each `cifs/<host>` service ticket.
    Kerberos { ccache: String, kdc: String },
}

impl std::fmt::Debug for AuthConfig {
    /// Redacted: prints the *kind* of credential, never the material itself.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Password(<redacted>)"),
            Self::Hash(_)     => f.write_str("Hash(<redacted>)"),
            Self::Kerberos { ccache, kdc } => {
                // A ccache path and a KDC name are not secrets, the SPN and
                // realm already travel in clear on the wire.
                write!(f, "Kerberos {{ ccache: {ccache:?}, kdc: {kdc:?} }}")
            }
        }
    }
}

impl AuthConfig {
    /// Short label for the banner. Never prints secret material.
    pub fn label(&self) -> String {
        match self {
            Self::Password(_) => "NTLMv2 password".to_string(),
            Self::Hash(h)     => format!("NTLMv2 PTH [{:02x}{:02x}{:02x}…]", h[0], h[1], h[2]),
            Self::Kerberos { ccache, kdc } => {
                format!("Kerberos pass-the-ticket (ccache: {ccache}, kdc: {kdc})")
            }
        }
    }
}

/// Connect to `host` and mount IPC$, authenticating per `auth`.
///
/// For Kerberos this builds a fresh `cifs/<host>` AP-REQ per target, exactly as
/// RustHound-CE's sessions module does, the ticket is bound to that host's SPN
/// and cannot be reused across hosts.
///
/// ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/modules/sessions/mod.rs
pub async fn connect_ipc_with(
    host: &str,
    domain: &str,
    user: &str,
    auth: &AuthConfig,
) -> Result<SmbClient> {
    match auth {
        AuthConfig::Kerberos { ccache, kdc } => {
            let spn = format!("cifs/{host}");
            debug!("[{host}] Kerberos: requesting {spn} from {kdc}");
            let (gss_blob, session_key) =
                kerberos::kerberos_material_for(ccache, &spn, kdc).await?;
            let a = smb::SmbAuth::Kerberos {
                gss_blob: &gss_blob,
                session_key: &session_key,
            };
            smb::connect_ipc(host, domain, user, a).await
        }
        AuthConfig::Hash(h) => smb::connect_ipc(host, domain, user, smb::SmbAuth::Hash(h)).await,
        AuthConfig::Password(p) => {
            smb::connect_ipc(host, domain, user, smb::SmbAuth::Password(p)).await
        }
    }
}
