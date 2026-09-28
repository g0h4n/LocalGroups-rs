//! Data structures: what we collect, and what we print.

use crate::args::Alias;
use crate::rpc::samr_alias::guess_object_type;
use serde::Serialize;
use std::collections::BTreeMap;

// What we collect

/// One alias read on one host.
pub struct AliasFinding {
    pub alias:     Alias,
    /// The BloodHound ObjectIdentifier of the group.
    pub group_sid: String,
    pub members:   Vec<String>,
    /// Resolved names, aligned with `members` by index. Empty when --resolve
    /// is off, or when LSAT could not name a member.
    pub names:     Vec<String>,
    /// BloodHound ObjectType per member, aligned by index. "Base" when unknown.
    pub types:     Vec<String>,
    /// Members dropped as local. Logged, kept for the RustHound-CE port.
    #[allow(dead_code)]
    pub local_drops: usize,
    pub collected: bool,
    pub failure:   Option<String>,
}

/// Everything learned about one host.
pub struct HostFindings {
    pub host:        String,
    pub machine_sid: Option<String>,
    /// On a DC, `machine_sid` is the domain SID.
    pub is_dc:       bool,
    /// False if we never got far enough to read any alias.
    pub collected:   bool,
    pub failure:     Option<String>,
    pub aliases:     Vec<AliasFinding>,
    pub errors:      Vec<String>,
}

impl HostFindings {
    pub fn new(host: &str) -> Self {
        Self {
            host: host.to_string(),
            machine_sid: None,
            is_dc: false,
            collected: false,
            failure: None,
            aliases: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Record a fatal error for this host and stop there.
    pub fn abort(mut self, message: String) -> Self {
        self.errors.push(message.clone());
        self.failure = Some(message);
        self
    }
}

// What we print
//
// LocalGroup matches RustHound-CE's objects::common::LocalGroup field for field.
// ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/objects/common.rs

#[derive(Serialize)]
pub struct Member {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}

#[derive(Serialize)]
pub struct LocalGroup {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "Results")]
    pub results: Vec<Member>,
    /// Names for `results`, aligned by index. Filled by --resolve.
    #[serde(rename = "LocalNames")]
    pub local_names: Vec<String>,
    #[serde(rename = "Collected")]
    pub collected: bool,
    #[serde(rename = "FailureReason")]
    pub failure_reason: Option<String>,
}

#[derive(Serialize)]
pub struct ComputerEntry {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_sid: Option<String>,
    /// On a DC, `machine_sid` is the domain SID and no local filtering ran.
    pub is_domain_controller: bool,
    #[serde(rename = "Collected")]
    pub collected: bool,
    #[serde(rename = "FailureReason")]
    pub failure_reason: Option<String>,
    #[serde(rename = "LocalGroups")]
    pub local_groups: Vec<LocalGroup>,
}

/// One membership, flattened for the operator.
#[derive(Serialize)]
pub struct LocalGroupEdge {
    pub principal: String,
    pub host:      String,
    /// AdminTo | CanRDP | ExecuteDCOM | CanPSRemote
    pub edge:      &'static str,
    /// The BUILTIN group it came from.
    pub via:       &'static str,
}

#[derive(Serialize)]
pub struct LocalGroupsReport {
    pub domain:        String,
    pub hosts_scanned: Vec<String>,
    pub edge_count:    usize,
    pub edges:         Vec<LocalGroupEdge>,
    pub by_principal:  BTreeMap<String, Vec<String>>,
    pub computers:     Vec<ComputerEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors:        Vec<String>,
}

/// Guess an ObjectType from a SID string. Domain SIDs come back as "Base";
/// RustHound-CE resolves those against the graph.
pub fn object_type_of(sid_str: &str) -> String {
    let parts: Vec<&str> = sid_str.split('-').collect();
    if parts.len() < 3 {
        return "Base".to_string();
    }
    let revision: u8 = parts[1].parse().unwrap_or(1);
    let identifier_authority: u64 = parts[2].parse().unwrap_or(5);
    let sub_authorities = parts[3..].iter().filter_map(|p| p.parse().ok()).collect();
    guess_object_type(&windows_sddl::sid::Sid {
        revision,
        identifier_authority,
        sub_authorities,
    })
    .to_string()
}
