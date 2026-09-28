//! The --table output: the report rendered for a human instead of JSON.

use crate::args::ALL_ALIASES;
use crate::types::{ComputerEntry, LocalGroupsReport};
use colored::Colorize;
use std::collections::BTreeMap;

/// Print the report as a colored table. Colors switch off on their own when
/// stdout is not a terminal, or when NO_COLOR is set.
pub fn render(report: &LocalGroupsReport) -> String {
    let mut out = String::new();

    let collected = report.computers.iter().filter(|c| c.collected).count();
    out.push_str(&format!(
        "\n{}  {} host(s), {} collected, {} edge(s)\n",
        report.domain.bold().cyan(),
        report.hosts_scanned.len(),
        collected,
        report.edge_count,
    ));

    for c in &report.computers {
        out.push('\n');
        out.push_str(&host_block(c));
    }

    out.push_str(&summary(report));
    out
}

/// The SID prefix shared by most members of this host, if any.
///
/// On a DC that is the domain SID, which also happens to be the machine SID.
/// On a member server the two differ: the machine SID is the host's own SAM,
/// while the members come from the domain. Shortening has to follow the
/// members, not the machine, or a member server shows full SIDs on every line.
fn common_prefix(c: &ComputerEntry) -> Option<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for g in &c.local_groups {
        for m in &g.results {
            if let Some(i) = m.object_identifier.rfind('-') {
                *counts.entry(m.object_identifier[..i].to_string()).or_default() += 1;
            }
        }
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(p, _)| p)
}

/// One host: its header, then a row per alias, then the members.
fn host_block(c: &ComputerEntry) -> String {
    let mut out = String::new();

    let tag = if !c.collected {
        " [FAILED]".red().bold().to_string()
    } else if c.is_domain_controller {
        " [DC]".magenta().bold().to_string()
    } else {
        String::new()
    };
    out.push_str(&format!("{}{}\n", c.host.bold(), tag));

    if let Some(sid) = &c.machine_sid {
        let label = if c.is_domain_controller { "domain SID" } else { "machine SID" };
        out.push_str(&format!("  {label:<12} {}\n", sid.dimmed()));
    }

    if !c.collected {
        let why = c.failure_reason.as_deref().unwrap_or("unknown");
        out.push_str(&format!("  {}\n", first_sentence(why).red()));
        return out;
    }

    let prefix = common_prefix(c);

    // On a member server the members come from a domain the header has not
    // named yet, so name it before shortening anything against it.
    if let Some(p) = &prefix {
        if c.machine_sid.as_deref() != Some(p.as_str()) {
            out.push_str(&format!("  {:<12} {}\n", "members from", p.dimmed()));
        }
    }

    out.push('\n');
    out.push_str(&format!(
        "  {}\n",
        format!("{:<25} {:>4}   {:<12} {:>7}", "BUILTIN group", "RID", "Edge", "Members").bold()
    ));
    out.push_str(&format!("  {}\n", "\u{2500}".repeat(53).dimmed()));

    for g in &c.local_groups {
        let rid = rid_of(&g.object_identifier);
        let (name, edge) = alias_meta(rid);
        let count = g.results.len();

        let cell = format!("{:>7}", if g.collected { count.to_string() } else { "denied".into() });
        let shown = if !g.collected {
            cell.red().to_string()
        } else if count > 0 {
            cell.green().bold().to_string()
        } else {
            cell.dimmed().to_string()
        };

        out.push_str(&format!(
            "  {name:<25} {rid:>4}   {} {shown}\n",
            format!("{edge:<12}").yellow()
        ));

        let last = g.results.len().saturating_sub(1);
        for (i, m) in g.results.iter().enumerate() {
            let id = &m.object_identifier;
            // A name from --resolve beats the well-known table.
            let resolved = g.local_names.get(i).filter(|n| !n.is_empty());
            let short = prefix.as_deref()
                .filter(|p| id.starts_with(*p) && id.len() > p.len())
                .map(|p| id[p.len() + 1..].to_string());
            let label: &str = match resolved {
                Some(n) => n.as_str(),
                None => well_known(id),
            };
            let ident = match &short {
                Some(r) if !label.is_empty() => format!("{r:<8}"),
                Some(r) => r.clone(),
                None => id.clone(),
            };
            let branch = if i == last { "\u{2514}" } else { "\u{251c}" };
            let line = if label.is_empty() {
                format!("    {} {}\n", branch.dimmed(), ident.cyan())
            } else {
                format!("    {} {} {}\n", branch.dimmed(), ident.cyan(), label.dimmed())
            };
            out.push_str(&line);
        }

        if let Some(why) = &g.failure_reason {
            out.push_str(&format!("    {} {}\n",
                "\u{2514}".dimmed(), first_sentence(why).red()));
        }
    }

    out
}

/// Edge totals across the whole run.
fn summary(report: &LocalGroupsReport) -> String {
    let mut out = String::from("\n");
    out.push_str(&format!("{}\n", "Summary".bold().underline()));

    for a in ALL_ALIASES {
        let n = report.edges.iter().filter(|e| e.edge == a.edge).count();
        let value = if n > 0 {
            n.to_string().green().bold().to_string()
        } else {
            "0".dimmed().to_string()
        };
        out.push_str(&format!("  {:<14} {}\n", a.edge, value));
    }

    let principals = report.by_principal.len();
    out.push_str(&format!("  {:<14} {}\n", "principals", principals));

    if !report.errors.is_empty() {
        out.push_str(&format!(
            "  {:<14} {}\n",
            "errors",
            report.errors.len().to_string().red().bold()
        ));
    }
    out
}

/// Trailing RID of an ObjectIdentifier, in either of the two forms.
fn rid_of(object_id: &str) -> u32 {
    object_id.rsplit('-').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Group name and edge for a BUILTIN RID.
fn alias_meta(rid: u32) -> (&'static str, &'static str) {
    ALL_ALIASES
        .iter()
        .find(|a| a.rid == rid)
        .map(|a| (a.name, a.edge))
        .unwrap_or(("unknown", "-"))
}

/// Label a SID when it is well known. Without LDAP this is all the naming we
/// have, and it covers the accounts that actually show up in local admin lists.
fn well_known(sid: &str) -> &'static str {
    match sid {
        "S-1-1-0"  => "Everyone",
        "S-1-5-4"  => "Interactive",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-18" => "SYSTEM",
        "S-1-5-19" => "LOCAL SERVICE",
        "S-1-5-20" => "NETWORK SERVICE",
        _ => match rid_of(sid) {
            500 => "Administrator",
            501 => "Guest",
            502 => "krbtgt",
            512 => "Domain Admins",
            513 => "Domain Users",
            516 => "Domain Controllers",
            518 => "Schema Admins",
            519 => "Enterprise Admins",
            520 => "Group Policy Creator Owners",
            525 => "Protected Users",
            526 => "Key Admins",
            527 => "Enterprise Key Admins",
            544 => "Administrators",
            545 => "Users",
            548 => "Account Operators",
            549 => "Server Operators",
            551 => "Backup Operators",
            555 => "Remote Desktop Users",
            562 => "Distributed COM Users",
            580 => "Remote Management Users",
            _ => "",
        },
    }
}

/// Failure reasons can be a paragraph; the table shows the first sentence.
///
/// A sentence ends at ". ", never at a bare dot: hostnames and IP addresses are
/// full of dots, and splitting on those turned "127.0.0.1: connect refused"
/// into "127".
fn first_sentence(s: &str) -> String {
    let line = s.lines().next().unwrap_or(s).trim();
    let cut = line.find(". ").map(|i| i + 1).unwrap_or(line.len());
    let out = line[..cut].trim_end();
    if out.chars().count() > 140 {
        format!("{}...", out.chars().take(137).collect::<String>())
    } else {
        out.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    // Builders for a report shaped like a real ESSOS.LOCAL run.
    use crate::types::{ComputerEntry, LocalGroup, LocalGroupEdge, Member};
    use std::collections::BTreeMap;

    fn sid(rid: u32) -> String {
        format!("S-1-5-21-3600700137-3291257795-828247845-{rid}")
    }

    fn group(rid: u32, members: &[u32]) -> LocalGroup {
        LocalGroup {
            object_identifier: format!("ESSOS.LOCAL-S-1-5-32-{rid}"),
            results: members.iter().map(|r| Member {
                object_identifier: sid(*r),
                object_type: "Base".into(),
            }).collect(),
            local_names: vec![],
            collected: true,
            failure_reason: None,
        }
    }

    fn sample() -> LocalGroupsReport {
        LocalGroupsReport {
            domain: "ESSOS.LOCAL".into(),
            hosts_scanned: vec!["MEEREEN.ESSOS.LOCAL".into(), "BRAAVOS.ESSOS.LOCAL".into()],
            edge_count: 2,
            edges: vec![
                LocalGroupEdge { principal: sid(512), host: "MEEREEN.ESSOS.LOCAL".into(),
                                 edge: "AdminTo", via: "Administrators" },
                LocalGroupEdge { principal: sid(1106), host: "MEEREEN.ESSOS.LOCAL".into(),
                                 edge: "CanRDP", via: "Remote Desktop Users" },
            ],
            by_principal: BTreeMap::new(),
            computers: vec![
                ComputerEntry {
                    host: "MEEREEN.ESSOS.LOCAL".into(),
                    machine_sid: Some("S-1-5-21-3600700137-3291257795-828247845".into()),
                    is_domain_controller: true,
                    collected: true,
                    failure_reason: None,
                    local_groups: vec![group(544, &[512]), group(555, &[1106]), group(562, &[])],
                },
                ComputerEntry {
                    host: "BRAAVOS.ESSOS.LOCAL".into(),
                    machine_sid: None,
                    is_domain_controller: false,
                    collected: false,
                    failure_reason: Some(
                        "BRAAVOS.ESSOS.LOCAL SamrConnect2: nca_s_fault_access_denied. Use a local admin".into()),
                    local_groups: vec![],
                },
            ],
            errors: vec!["BRAAVOS.ESSOS.LOCAL denied".into()],
        }
    }

    /// Strip ANSI escapes so the assertions read the text, not the color codes.
    fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for c in chars.by_ref() {
                    if c == 'm' { break; }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn render_shows_every_part_of_the_report() {
        let out = plain(&render(&sample()));

        // Header and per-host tags.
        assert!(out.contains("ESSOS.LOCAL  2 host(s), 1 collected, 2 edge(s)"), "{out}");
        assert!(out.contains("MEEREEN.ESSOS.LOCAL [DC]"), "{out}");
        assert!(out.contains("BRAAVOS.ESSOS.LOCAL [FAILED]"), "{out}");

        // A DC reports a domain SID, not a machine SID.
        assert!(out.contains("domain SID   S-1-5-21-3600700137-3291257795-828247845"), "{out}");
        // Members share that prefix here, so no separate "members from" line.
        assert!(!out.contains("members from"), "{out}");

        // One row per alias, RID and edge resolved from the ObjectIdentifier.
        assert!(out.contains("Administrators             544   AdminTo"), "{out}");
        assert!(out.contains("Remote Desktop Users       555   CanRDP"), "{out}");
        assert!(out.contains("Distributed COM Users      562   ExecuteDCOM"), "{out}");

        // Members listed with their well-known label.
        assert!(out.contains("Domain Admins"), "{out}");

        // Failure shown, and not truncated at the first dot of the FQDN.
        assert!(out.contains("BRAAVOS.ESSOS.LOCAL SamrConnect2: nca_s_fault_access_denied."), "{out}");

        // Summary totals.
        assert!(out.contains("AdminTo        1"), "{out}");
        assert!(out.contains("CanRDP         1"), "{out}");
        assert!(out.contains("errors         1"), "{out}");
    }

    #[test]
    fn empty_alias_and_denied_alias_render_differently() {
        let mut r = sample();
        r.computers[0].local_groups[2].collected = false;
        r.computers[0].local_groups[2].failure_reason = Some("STATUS_ACCESS_DENIED".into());
        let out = plain(&render(&r));
        assert!(out.contains("ExecuteDCOM   denied"), "{out}");
        // ... and the alias failure reason is printed under the row.
        assert!(out.contains("STATUS_ACCESS_DENIED"), "{out}");
    }

    /// On a member server the members come from the domain, not from the
    /// host's own SAM, so shortening must follow the members.
    #[test]
    fn member_server_shortens_against_the_domain_not_the_machine() {
        let mut r = sample();
        let c = &mut r.computers[0];
        c.is_domain_controller = false;
        c.machine_sid = Some("S-1-5-21-2369045123-1167655290-1758964606".into());
        let out = plain(&render(&r));
        assert!(out.contains("machine SID  S-1-5-21-2369045123"), "{out}");
        assert!(out.contains("members from S-1-5-21-3600700137"), "{out}");
        // Shortened to the RID even though the machine SID differs.
        assert!(out.contains("512      Domain Admins"), "{out}");
    }

    #[test]
    fn rid_parsed_from_both_object_id_forms() {
        assert_eq!(rid_of("S-1-5-21-1111-2222-3333-544"), 544);
        assert_eq!(rid_of("ESSOS.LOCAL-S-1-5-32-555"), 555);
    }

    #[test]
    fn well_known_rids_are_labelled() {
        assert_eq!(well_known("S-1-5-21-3600700137-3291257795-828247845-512"),
                   "Domain Admins");
        assert_eq!(well_known("S-1-5-18"), "SYSTEM");
        // A plain user RID has no label; the SID is shown on its own.
        assert_eq!(well_known("S-1-5-21-3600700137-3291257795-828247845-1105"), "");
    }

    #[test]
    fn first_sentence_does_not_cut_on_dots_in_addresses() {
        // Regression: splitting on '.' turned this into "127".
        assert_eq!(first_sentence("127.0.0.1: connect: Connection refused (os error 111)"),
                   "127.0.0.1: connect: Connection refused (os error 111)");
        assert_eq!(first_sentence("SamrConnect2 failed. Use a local admin account"),
                   "SamrConnect2 failed.");
        assert_eq!(first_sentence("first line\nsecond line"), "first line");
    }

    #[test]
    fn alias_meta_maps_rid_to_edge() {
        assert_eq!(alias_meta(544), ("Administrators", "AdminTo"));
        assert_eq!(alias_meta(9999), ("unknown", "-"));
    }
}
