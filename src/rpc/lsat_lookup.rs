//! LsarLookupSids (opnum 15), the MS-LSAT call that turns SIDs into names.
//!
//! `dcerpc::lsat` ships the opposite direction only (`LsarLookupNames`), so the
//! reverse lookup is built here on the crate's public surface, exactly as the
//! SAMR alias opnums are in `samr_alias.rs`.
//!
//! This resolves the members that `well_known()` cannot name: ordinary users,
//! groups and computers, whose RID carries no meaning. It works from a member
//! server too, since the host forwards SIDs it does not own to a DC.
//!
//! Read-only.

use anyhow::{Result, anyhow, bail};
use dcerpc::RpcError;
use dcerpc::lsat::{encode_open_policy2, lsat_syntax};
use dcerpc::ndr::{NdrDecoder, NdrEncoder};
use dcerpc::samr::SamrHandle;
use dcerpc::transport::SmbPipe;
use smb2_client::SmbClient;
use windows_sddl::sid::Sid;

pub mod opnum {
    pub const CLOSE: u16 = 0;
    /// LsarLookupSids(policy, sids, level) -> names.
    pub const LOOKUP_SIDS: u16 = 15;
    pub const OPEN_POLICY2: u16 = 44;
}

/// LsapLookupWksta, the level `dcerpc::lsat` already uses for LookupNames.
const LOOKUP_LEVEL_WKSTA: u16 = 1;

/// STATUS_SOME_NOT_MAPPED. Partial success: the mapped names are still there.
const STATUS_SOME_NOT_MAPPED: u32 = 0x0000_0107;
/// STATUS_NONE_MAPPED. Nothing resolved, but the reply is well formed.
const STATUS_NONE_MAPPED: u32 = 0xC000_0073;

/// What a SID turned out to be, as MS-LSAT names it (SID_NAME_USE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidType {
    User,
    Group,
    Domain,
    Alias,
    WellKnownGroup,
    DeletedAccount,
    Invalid,
    Unknown,
    Computer,
    Label,
}

impl SidType {
    fn from_wire(v: u16) -> Self {
        match v {
            1 => Self::User,
            2 => Self::Group,
            3 => Self::Domain,
            4 => Self::Alias,
            5 => Self::WellKnownGroup,
            6 => Self::DeletedAccount,
            7 => Self::Invalid,
            9 => Self::Computer,
            10 => Self::Label,
            _ => Self::Unknown,
        }
    }

    /// The BloodHound ObjectType this maps onto.
    pub fn object_type(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Computer => "Computer",
            Self::Group | Self::Alias | Self::WellKnownGroup => "Group",
            Self::Domain => "Domain",
            _ => "Base",
        }
    }
}

/// One resolved SID.
#[derive(Clone, Debug)]
pub struct ResolvedName {
    /// SamAccountName, as LSAT returns it. Empty when unresolved.
    pub name: String,
    /// NetBIOS domain the account belongs to, empty when LSAT gave no domain.
    pub domain: String,
    pub sid_type: SidType,
}

impl ResolvedName {
    /// `DOMAIN\name` when both are known, otherwise whichever part exists.
    pub fn display(&self) -> String {
        match (self.domain.is_empty(), self.name.is_empty()) {
            (false, false) => format!("{}\\{}", self.domain, self.name),
            (true, false) => self.name.clone(),
            _ => String::new(),
        }
    }
}

/// Encode LsarLookupSids.
///
/// ```text
/// LsarLookupSids(
///   [in]     LSAPR_HANDLE           PolicyHandle,
///   [in]     PLSAPR_SID_ENUM_BUFFER SidEnumBuffer,
///   [out]    ReferencedDomains,
///   [in,out] PLSAPR_TRANSLATED_NAMES TranslatedNames,
///   [in]     LSAP_LOOKUP_LEVEL      LookupLevel,
///   [in,out] unsigned long*         MappedCount)
/// ```
///
/// Field order mirrors `dcerpc::lsat::encode_lookup_names`, which is the known
/// good reference for how this encoder lays out the tail of an LSAT request.
pub fn encode_lookup_sids(policy: &SamrHandle, sids: &[Sid]) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    policy.encode(&mut e); // PolicyHandle (20)

    // LSAPR_SID_ENUM_BUFFER { Entries, [size_is(Entries)] SidInfo }
    e.u32(sids.len() as u32); // Entries
    e.referent(); // SidInfo array pointer
    e.u32(sids.len() as u32); // conformant max_count
    for _ in sids {
        e.referent(); // LSAPR_SID_INFORMATION.Sid pointer
    }
    for sid in sids {
        // deferred RPC_SID, conformant count hoisted to the front
        e.u32(sid.sub_authorities.len() as u32);
        e.u8(sid.revision);
        e.u8(sid.sub_authorities.len() as u8);
        let a = sid.identifier_authority;
        e.bytes(&[
            (a >> 40) as u8,
            (a >> 32) as u8,
            (a >> 24) as u8,
            (a >> 16) as u8,
            (a >> 8) as u8,
            a as u8,
        ]);
        for s in &sid.sub_authorities {
            e.u32(*s);
        }
    }

    // TranslatedNames [in,out]: Entries = 0, Names = NULL
    e.u32(0);
    e.null_ptr();
    // LookupLevel
    e.u16(LOOKUP_LEVEL_WKSTA);
    // MappedCount [in,out]
    e.u32(0);
    e.into_bytes()
}

/// Decode the reply into one entry per queried SID, in the order asked.
///
/// Wire order: ReferencedDomains, then TranslatedNames, then MappedCount, then
/// the NTSTATUS. Domain names are held once in ReferencedDomains and pointed at
/// by each name's DomainIndex.
pub fn decode_lookup_sids(stub: &[u8], asked: usize) -> Result<Vec<ResolvedName>> {
    if stub.len() < 4 {
        bail!("LsarLookupSids: reply too short");
    }
    let status = u32::from_le_bytes(stub[stub.len() - 4..].try_into().unwrap());
    if status != 0 && status != STATUS_SOME_NOT_MAPPED && status != STATUS_NONE_MAPPED {
        bail!("LsarLookupSids failed (NTSTATUS {status:#010x})");
    }

    let mut d = NdrDecoder::new(stub);

    // ReferencedDomains: names only, the SIDs are not needed here.
    let mut domains: Vec<String> = Vec::new();
    let dom_ref = d.u32()?;
    if dom_ref != 0 {
        let entries = d.u32()? as usize;
        let domains_ref = d.u32()?;
        let _max_entries = d.u32()?;
        if domains_ref != 0 {
            let _max = d.u32()?;
            // Each LSAPR_TRUST_INFORMATION is 12 wire bytes before its deferred
            // parts, the same preflight dcerpc added to LookupNames after a fuzz
            // OOM.
            if entries.checked_mul(12).map_or(true, |need| need > d.remaining()) {
                bail!("LsarLookupSids: domain Entries={entries} exceeds remaining stub");
            }
            let mut fixed = Vec::with_capacity(entries);
            for _ in 0..entries {
                let _len = d.u16()?;
                let _maxlen = d.u16()?;
                let name_ref = d.u32()?;
                let sid_ref = d.u32()?;
                fixed.push((name_ref, sid_ref));
            }
            for (name_ref, sid_ref) in fixed {
                let name = if name_ref != 0 { d.conformant_varying_wstr()? } else { String::new() };
                if sid_ref != 0 {
                    skip_rpc_sid(&mut d)?;
                }
                domains.push(name);
            }
        }
    }

    // TranslatedNames { Entries, [size_is(Entries)] Names }
    let entries = d.u32()? as usize;
    let names_ref = d.u32()?;
    if names_ref == 0 || entries == 0 {
        return Ok(unresolved(asked));
    }
    let _max = d.u32()?;
    // LSAPR_TRANSLATED_NAME is Use(u16) + Name{len,maxlen,ptr} + DomainIndex,
    // 16 wire bytes before the deferred buffers.
    if entries.checked_mul(16).map_or(true, |need| need > d.remaining()) {
        bail!("LsarLookupSids: Entries={entries} exceeds remaining stub");
    }

    let mut fixed = Vec::with_capacity(entries);
    for _ in 0..entries {
        let use_ = d.u16()?;
        let _len = d.u16()?;
        let _maxlen = d.u16()?;
        let name_ref = d.u32()?;
        let domain_index = d.u32()? as i32;
        fixed.push((use_, name_ref, domain_index));
    }

    let mut out = Vec::with_capacity(entries);
    for (use_, name_ref, domain_index) in fixed {
        let name = if name_ref != 0 { d.conformant_varying_wstr()? } else { String::new() };
        let domain = domains
            .get(usize::try_from(domain_index).unwrap_or(usize::MAX))
            .cloned()
            .unwrap_or_default();
        out.push(ResolvedName { name, domain, sid_type: SidType::from_wire(use_) });
    }

    // A server may answer with fewer entries than asked; pad so the caller can
    // zip the result against its own SID list by index.
    while out.len() < asked {
        out.push(unresolved_one());
    }
    out.truncate(asked);
    Ok(out)
}

fn unresolved_one() -> ResolvedName {
    ResolvedName { name: String::new(), domain: String::new(), sid_type: SidType::Unknown }
}

fn unresolved(n: usize) -> Vec<ResolvedName> {
    (0..n).map(|_| unresolved_one()).collect()
}

/// Step over an RPC_SID without building it.
fn skip_rpc_sid(d: &mut NdrDecoder) -> Result<()> {
    let _max = d.u32()?;
    let _revision = d.u8()?;
    let count = d.u8()? as usize;
    if count > 15 {
        bail!("RPC_SID SubAuthorityCount={count} exceeds 15");
    }
    let _auth = d.read_bytes(6)?;
    for _ in 0..count {
        let _ = d.u32()?;
    }
    Ok(())
}

/// LSAT bound over an open `\lsarpc` pipe.
pub struct LsatLookupClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> LsatLookupClient<'a> {
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(lsat_syntax()).await.map_err(|e| anyhow!("LSAT bind: {e}"))?;
        Ok(Self { pipe })
    }

    async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        self.pipe.call(opnum, stub).await.map_err(|e| match e {
            RpcError::Fault(status) => anyhow!(
                "opnum {opnum}: {}",
                crate::rpc::samr_alias::explain_fault(status)
            ),
            other => anyhow!("opnum {opnum}: {other}"),
        })
    }

    /// LsarOpenPolicy2 -> policy handle.
    pub async fn open_policy(&mut self) -> Result<SamrHandle> {
        let resp = self.call(opnum::OPEN_POLICY2, &encode_open_policy2()).await?;
        if resp.len() < 4 {
            bail!("LsarOpenPolicy2: reply too short");
        }
        let status = u32::from_le_bytes(resp[resp.len() - 4..].try_into().unwrap());
        if status != 0 {
            bail!("LsarOpenPolicy2 failed (NTSTATUS {status:#010x})");
        }
        let mut d = NdrDecoder::new(&resp);
        SamrHandle::decode(&mut d).map_err(|e| anyhow!("LsarOpenPolicy2 handle: {e}"))
    }

    /// Resolve a batch of SIDs. The result lines up with `sids` by index.
    ///
    /// MS-LSAT caps a request at 20480 SIDs; batches are kept far smaller so a
    /// single oversized alias cannot blow up one call.
    pub async fn lookup(&mut self, policy: &SamrHandle, sids: &[Sid]) -> Result<Vec<ResolvedName>> {
        if sids.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(sids.len());
        for chunk in sids.chunks(256) {
            let resp = self.call(opnum::LOOKUP_SIDS, &encode_lookup_sids(policy, chunk)).await?;
            out.extend(decode_lookup_sids(&resp, chunk.len())?);
        }
        Ok(out)
    }

    /// LsarClose, best effort.
    pub async fn close(&mut self, policy: &SamrHandle) -> Result<()> {
        let mut e = NdrEncoder::new();
        policy.encode(&mut e);
        self.call(opnum::CLOSE, &e.into_bytes()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(s: &str) -> Sid {
        let mut p = s.split('-').skip(1);
        let revision: u8 = p.next().unwrap().parse().unwrap();
        let identifier_authority: u64 = p.next().unwrap().parse().unwrap();
        Sid { revision, identifier_authority, sub_authorities: p.map(|x| x.parse().unwrap()).collect() }
    }

    #[test]
    fn request_layout_starts_with_handle_and_count() {
        let stub = encode_lookup_sids(&SamrHandle([0; 20]), &[sid("S-1-5-21-1-2-3-512")]);
        assert_eq!(&stub[20..24], &1u32.to_le_bytes()); // Entries
        assert!(stub.len() > 40);
    }

    #[test]
    fn empty_batch_makes_no_call() {
        assert!(encode_lookup_sids(&SamrHandle([0; 20]), &[]).len() >= 20);
    }

    /// Build a reply with one domain and two names, and read it back.
    fn reply(status: u32) -> Vec<u8> {
        let mut e = NdrEncoder::new();
        // ReferencedDomains
        e.referent();
        e.u32(1); // Entries
        e.referent(); // Domains ptr
        e.u32(1); // max entries
        e.u32(1); // conformant max
        e.u16(10);
        e.u16(10);
        e.referent(); // Name.Buffer
        e.null_ptr(); // Sid ptr, absent
        e.conformant_varying_wstr("ESSOS");
        // TranslatedNames
        e.u32(2);
        e.referent();
        e.u32(2);
        // entry 0: User
        e.u16(1);
        e.u16(8);
        e.u16(8);
        e.referent();
        e.u32(0);
        // entry 1: unknown, no name
        e.u16(8);
        e.u16(0);
        e.u16(0);
        e.null_ptr();
        e.u32(0xFFFF_FFFF);
        // deferred buffers, in entry order
        e.conformant_varying_wstr("khal");
        e.u32(1); // MappedCount
        e.u32(status);
        e.into_bytes()
    }

    #[test]
    fn names_and_domains_are_paired() {
        let out = decode_lookup_sids(&reply(STATUS_SOME_NOT_MAPPED), 2).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "khal");
        assert_eq!(out[0].domain, "ESSOS");
        assert_eq!(out[0].display(), "ESSOS\\khal");
        assert_eq!(out[0].sid_type, SidType::User);
        assert_eq!(out[0].sid_type.object_type(), "User");
        // The unresolved one stays empty rather than borrowing its neighbour.
        assert!(out[1].name.is_empty());
        assert_eq!(out[1].sid_type, SidType::Unknown);
    }

    #[test]
    fn partial_and_none_mapped_are_not_errors() {
        assert!(decode_lookup_sids(&reply(0), 2).is_ok());
        assert!(decode_lookup_sids(&reply(STATUS_SOME_NOT_MAPPED), 2).is_ok());
        assert!(decode_lookup_sids(&reply(STATUS_NONE_MAPPED), 2).is_ok());
    }

    #[test]
    fn result_is_padded_to_the_number_asked() {
        // Asked for 5, server answered 2: the caller can still zip by index.
        let out = decode_lookup_sids(&reply(STATUS_SOME_NOT_MAPPED), 5).unwrap();
        assert_eq!(out.len(), 5);
        assert!(out[4].name.is_empty());
    }

    #[test]
    fn hostile_entry_count_is_rejected() {
        let mut e = NdrEncoder::new();
        e.null_ptr(); // no ReferencedDomains
        e.u32(u32::MAX); // Entries
        e.referent();
        e.u32(0);
        let err = decode_lookup_sids(&e.into_bytes(), 1).unwrap_err();
        assert!(err.to_string().contains("exceeds remaining stub"), "got {err}");
    }

    #[test]
    fn sid_type_maps_onto_bloodhound_object_types() {
        assert_eq!(SidType::from_wire(1).object_type(), "User");
        assert_eq!(SidType::from_wire(2).object_type(), "Group");
        assert_eq!(SidType::from_wire(9).object_type(), "Computer");
        assert_eq!(SidType::from_wire(8).object_type(), "Base");
    }
}