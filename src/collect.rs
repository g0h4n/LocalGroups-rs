//! The collection flow: scan each host over SAMR, then fold the results
//! into one report.

use crate::args::{Alias, Options};
use crate::rpc::lsat_lookup::LsatLookupClient;
use crate::rpc::samr_alias::{
    SamrAliasClient, is_domain_controller, is_under, sid_to_string,
};
use crate::transport::{self, AuthConfig};
use crate::types::*;
use colored::Colorize;
use log::{debug, error, info, trace, warn};
use std::collections::{BTreeMap, BTreeSet};

/// Scan every target, then build the report.
pub async fn run(opts: &Options, aliases: &[Alias]) -> LocalGroupsReport {
    let total = opts.targets.len();
    let mut all = Vec::new();
    for (i, host) in opts.targets.iter().enumerate() {
        info!("[{}/{}] {}", i + 1, total, host.bold());
        debug!("==================== {host} ====================");
        all.push(
            enumerate_host(
                host,
                &opts.domain,
                &opts.username,
                &opts.auth,
                aliases,
                opts.remove_local,
                opts.no_resolve,
            )
            .await,
        );
    }
    let ok = all.iter().filter(|f| f.collected).count();
    info!("{} of {} host(s) collected, {} failed",
          ok.to_string().bold(), total, total - ok);

    build_report(opts, &all)
}

// Report

/// Turn per-host findings into the JSON report.
fn build_report(opts: &Options, all: &[HostFindings]) -> LocalGroupsReport {
    debug!("Correlating {} host result(s) ...", all.len());
    let mut edges = Vec::new();
    let mut by_principal: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut errors = Vec::new();
    let mut computers = Vec::new();

    for f in all {
        errors.extend(f.errors.iter().cloned());

        let mut groups = Vec::new();
        for a in &f.aliases {
            for sid in &a.members {
                by_principal
                    .entry(sid.clone())
                    .or_default()
                    .insert(f.host.clone());
                edges.push(LocalGroupEdge {
                    principal: sid.clone(),
                    host: f.host.clone(),
                    edge: a.alias.edge,
                    via: a.alias.name,
                });
            }
            groups.push(LocalGroup {
                object_identifier: a.group_sid.clone(),
                results: a
                    .members
                    .iter()
                    .enumerate()
                    .map(|(i, s)| Member {
                        object_identifier: s.clone(),
                        // LSAT is authoritative when it answered; the SID-based
                        // guess is the fallback.
                        object_type: match a.types.get(i).map(String::as_str) {
                            Some(t) if t != "Base" => t.to_string(),
                            _ => object_type_of(s),
                        },
                    })
                    .collect(),
                local_names: a.names.clone(),
                collected: a.collected,
                failure_reason: a.failure.clone(),
            });
        }

        computers.push(ComputerEntry {
            host: f.host.clone(),
            machine_sid: f.machine_sid.clone(),
            is_domain_controller: f.is_dc,
            collected: f.collected,
            failure_reason: f.failure.clone(),
            local_groups: groups,
        });
    }

    debug!("{} edge(s), {} distinct principal(s), {} error(s)",
           edges.len(), by_principal.len(), errors.len());

    LocalGroupsReport {
        domain: opts.domain.clone(),
        hosts_scanned: opts.targets.clone(),
        edge_count: edges.len(),
        edges,
        by_principal: by_principal
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect(),
        computers,
        errors,
    }
}

// Per-host scan

/// SMB session, then the SAMR alias walk.
async fn enumerate_host(
    host: &str,
    domain: &str,
    user: &str,
    auth: &AuthConfig,
    aliases: &[Alias],
    remove_local: bool,
    no_resolve: bool,
) -> HostFindings {
    let mut f = HostFindings::new(host);
    trace!("[{host}] target resolved, starting SMB step");

    // Connect + authenticate + mount IPC$. All of it lives in transport::smb,
    // copied from RustHound-CE, so the three auth paths behave the same there.
    debug!("[{host}] connect + SESSION_SETUP ({}) + IPC$ ...", auth.label());
    let mut smb = match transport::connect_ipc_with(host, domain, user, auth).await {
        Ok(c) => {
            info!("[{host}] Auth validated - {} for {}\\{}",
                  auth.label(), domain.bold(), user.bold());
            c
        }
        Err(e) => {
            let m = format!("{host}: {e}");
            error!("{m}");
            return f.abort(m);
        }
    };

    // \samr pipe + DCE/RPC bind.
    debug!("[{host}] opening \\samr pipe ...");
    let pipe = match transport::smb::open_rpc_pipe(&mut smb, host, "samr").await {
        Ok(p) => p,
        Err(e) => {
            let m = format!("{host} \\samr pipe: {e}");
            warn!("{m}");
            return f.abort(m);
        }
    };
    let mut samr = match SamrAliasClient::bind(&mut smb, pipe).await {
        Ok(c) => c,
        Err(e) => {
            let m = format!("{host} SAMR bind: {e}");
            warn!("{m}");
            return f.abort(m);
        }
    };
    debug!("[{host}] \\samr pipe open, SAMR interface bound");

    // SamrConnect2. A fault here is usually RestrictRemoteSam, not bad creds.
    debug!("[{host}] [SAMR] SamrConnect2 (opnum 57) ...");
    let server = match samr.connect(&format!("\\\\{host}")).await {
        Ok(h) => {
            trace!("[{host}] server handle obtained");
            h
        }
        Err(e) => {
            let m = format!("{host} SamrConnect2: {e}");
            warn!("{m}");
            return f.abort(m);
        }
    };

    // Machine SID. Needed twice: as the local-member filter prefix, and as the
    // prefix of every group ObjectIdentifier. So always fetch it.
    let machine_sid = resolve_machine_sid(&mut samr, &server, host, domain,
                                          remove_local, &mut f).await;

    // SamrOpenDomain on BUILTIN.
    debug!("[{host}] [SAMR] SamrOpenDomain S-1-5-32 (opnum 7) ...");
    let builtin = match samr.open_builtin(&server).await {
        Ok(h) => {
            trace!("[{host}] BUILTIN domain handle obtained");
            h
        }
        Err(e) => {
            let m = format!("{host} SamrOpenDomain(BUILTIN): {e}");
            warn!("{m}");
            return f.abort(m);
        }
    };

    // The host answered SAMR; from here a failure is per-alias, not per-host.
    f.collected = true;

    debug!("[{host}] reading {} alias(es) ...", aliases.len());
    for alias in aliases {
        read_alias(&mut samr, &builtin, *alias, host, domain,
                   machine_sid.as_ref(), remove_local, &mut f).await;
    }

    trace!("[{host}] closing handles");
    let _ = samr.close_handle(&builtin).await;
    let _ = samr.close_handle(&server).await;

    // SAMR is done with the SMB session; release it before LSAT takes it for
    // the second pipe.
    drop(samr);
    if !no_resolve {
        resolve_names(&mut smb, host, &mut f).await;
    }

    let found: usize = f.aliases.iter().map(|a| a.members.len()).sum();
    debug!("[{host}] done, {found} member(s) across {} alias(es)", f.aliases.len());
    f
}

/// Look up the host's own domain SID, and decide whether it is a DC.
/// Returns the SID to filter members against, or None when no filtering applies.
async fn resolve_machine_sid(
    samr: &mut SamrAliasClient<'_>,
    server: &dcerpc::samr::SamrHandle,
    host: &str,
    domain: &str,
    remove_local: bool,
    f: &mut HostFindings,
) -> Option<windows_sddl::sid::Sid> {
    debug!("[{host}] [SAMR] EnumerateDomains + LookupDomain (machine SID) ...");
    match samr.machine_sid(server).await {
        Ok(Some((name, sid))) => {
            let s = sid_to_string(&sid);
            f.machine_sid = Some(s.clone());

            if is_domain_controller(&name, domain) {
                // On a DC this is the domain SID. Filtering on it would drop
                // every domain principal and empty out Administrators.
                info!("[{host}] Domain controller detected (SAMR domain '{}') - \
                       local filtering disabled, all members kept", name.cyan());
                f.is_dc = true;
                None
            } else {
                debug!("[{host}]   local domain '{}' = {}", name.cyan(), s.yellow());
                if !remove_local { None } else { Some(sid) }
            }
        }
        Ok(None) => {
            debug!("[{host}] No non-BUILTIN domain returned; local filter disabled.");
            None
        }
        Err(e) => {
            let m = format!("{host} machine SID lookup: {e} (local members will NOT be filtered)");
            warn!("{m}");
            f.errors.push(m);
            None
        }
    }
}

/// OpenAlias + GetMembersInAlias for one RID, and record the result.
async fn read_alias(
    samr: &mut SamrAliasClient<'_>,
    builtin: &dcerpc::samr::SamrHandle,
    alias: Alias,
    host: &str,
    domain: &str,
    machine_sid: Option<&windows_sddl::sid::Sid>,
    remove_local: bool,
    f: &mut HostFindings,
) {
    debug!("[{host}] [SAMR] SamrOpenAlias RID {} ({}) (opnum 27) ...", alias.rid, alias.name);
    let group_sid = group_object_id(alias.rid, domain, f);
    trace!("[{host}]   group ObjectIdentifier = {}", group_sid.yellow());

    let fail = |f: &mut HostFindings, e: String, gid: String| {
        warn!("[{host}] {} (RID {}) - {e}", alias.name, alias.rid);
        f.aliases.push(AliasFinding {
            alias, group_sid: gid, members: Vec::new(),
            names: Vec::new(), types: Vec::new(),
            local_drops: 0, collected: false, failure: Some(e),
        });
    };

    let handle = match samr.open_alias(builtin, alias.rid).await {
        Ok(h) => h,
        Err(e) => return fail(f, e.to_string(), group_sid),
    };

    debug!("[{host}] [SAMR] SamrGetMembersInAlias (opnum 33) ...");
    let members = match samr.get_members_in_alias(&handle).await {
        Ok(m) => m,
        Err(e) => {
            let _ = samr.close_handle(&handle).await;
            return fail(f, e.to_string(), group_sid);
        }
    };

    // Local accounts have no BloodHound node, so keeping them would create a
    // dangling edge.
    let raw = members.len();
    let mut local_drops = 0usize;
    let kept: Vec<String> = members
        .iter()
        .filter(|m| match (machine_sid, !remove_local) {
            (Some(mach), false) if is_under(m, mach) => {
                local_drops += 1;
                trace!("[{host}]   dropping local member {}", sid_to_string(m));
                false
            }
            _ => true,
        })
        .map(sid_to_string)
        .collect();

    if raw == 0 {
        debug!("[{host}]   alias is empty on this host");
    }
    info!("[{host}] {} (RID {}) - {} member(s) -> {} edge(s){}",
          alias.name.bold(), alias.rid, raw, kept.len(),
          if local_drops > 0 { format!("  ({local_drops} local filtered)") } else { String::new() });
    for s in &kept {
        debug!("[{host}]   member {} -> {}", s.cyan(), alias.edge.yellow());
    }

    let n = kept.len();
    f.aliases.push(AliasFinding {
        alias, group_sid, members: kept,
        names: vec![String::new(); n],
        types: vec!["Base".to_string(); n],
        local_drops, collected: true, failure: None,
    });

    if let Err(e) = samr.close_handle(&handle).await {
        trace!("[{host}] SamrCloseHandle(alias {}): {e}", alias.rid);
    }
}

/// Resolve every member SID on this host to a name, over a second pipe.
///
/// One \lsarpc session per host, one batched LsarLookupSids for all the SIDs
/// the aliases returned. A failure here is never fatal: the SIDs are already
/// collected, names are a convenience.
async fn resolve_names(smb: &mut smb2_client::SmbClient, host: &str, f: &mut HostFindings) {
    let mut wanted: Vec<String> = Vec::new();
    for a in &f.aliases {
        for m in &a.members {
            if !wanted.contains(m) {
                wanted.push(m.clone());
            }
        }
    }
    if wanted.is_empty() {
        return;
    }

    debug!("[{host}] [LSAT] resolving {} SID(s) ...", wanted.len());
    let parsed: Vec<windows_sddl::sid::Sid> = wanted.iter().filter_map(|s| parse_sid(s)).collect();
    if parsed.len() != wanted.len() {
        trace!("[{host}] some SIDs could not be parsed back, skipping those");
    }

    let pipe = match transport::smb::open_rpc_pipe(smb, host, "lsarpc").await {
        Ok(p) => p,
        Err(e) => {
            let m = format!("{host} \\lsarpc pipe: {e}");
            warn!("{m}");
            f.errors.push(m);
            return;
        }
    };
    let mut lsat = match LsatLookupClient::bind(smb, pipe).await {
        Ok(c) => c,
        Err(e) => {
            let m = format!("{host} LSAT bind: {e}");
            warn!("{m}");
            f.errors.push(m);
            return;
        }
    };
    let policy = match lsat.open_policy().await {
        Ok(p) => p,
        Err(e) => {
            let m = format!("{host} LsarOpenPolicy2: {e}");
            warn!("{m}");
            f.errors.push(m);
            return;
        }
    };
    let resolved = match lsat.lookup(&policy, &parsed).await {
        Ok(r) => r,
        Err(e) => {
            let m = format!("{host} LsarLookupSids: {e}");
            warn!("{m}");
            f.errors.push(m);
            return;
        }
    };
    let _ = lsat.close(&policy).await;

    let mut by_sid = std::collections::BTreeMap::new();
    for (s, r) in wanted.iter().zip(resolved.iter()) {
        by_sid.insert(s.clone(), r.clone());
    }

    let mut named = 0usize;
    for a in &mut f.aliases {
        for (i, m) in a.members.iter().enumerate() {
            if let Some(r) = by_sid.get(m) {
                let d = r.display();
                if !d.is_empty() {
                    named += 1;
                }
                a.names[i] = d;
                a.types[i] = r.sid_type.object_type().to_string();
            }
        }
    }
    debug!("[{host}] [LSAT] {named}/{} member(s) named", wanted.len());
}

/// Parse a rendered SID back into its structured form.
fn parse_sid(s: &str) -> Option<windows_sddl::sid::Sid> {
    let mut p = s.strip_prefix("S-")?.split('-');
    let revision: u8 = p.next()?.parse().ok()?;
    let identifier_authority: u64 = p.next()?.parse().ok()?;
    let sub_authorities: Vec<u32> = p.map(|x| x.parse().ok()).collect::<Option<_>>()?;
    Some(windows_sddl::sid::Sid { revision, identifier_authority, sub_authorities })
}

/// The group's ObjectIdentifier, in SharpHound's two forms.
///
/// Member host: `<machine SID>-<rid>`.
/// DC: `<DOMAIN>-S-1-5-32-<rid>`, because the BUILTIN aliases there are the
/// domain's well-known groups. Using the machine form would invent a SID that
/// exists nowhere in AD.
/// ref: LocalGroupProcessor.ResolveGroupName, SharpHoundCommon v4.8.0
fn group_object_id(rid: u32, domain: &str, f: &HostFindings) -> String {
    if f.is_dc {
        format!("{}-S-1-5-32-{rid}", domain.to_uppercase())
    } else {
        match &f.machine_sid {
            Some(m) => format!("{m}-{rid}"),
            None => format!("S-1-5-32-{rid}"),
        }
    }
}
