//! LocalGroups-rs - enumerate Windows local group membership over SAMR and
//! print it as BloodHound-shaped LocalGroups JSON.
//!
//! Prototype for the `Computer`:`LocalGroups` line of the RustHound-CE
//! roadmap, tracked as RustHound-CE#69:
//! https://github.com/g0h4n/RustHound-CE/issues/69
//!
//! Layout:
//!   args.rs         CLI options
//!   collect.rs      the scan, one host at a time
//!   report.rs       the --table output
//!   types.rs        what we collect and what we print
//!   samr_alias.rs   the two SAMR opnums dcerpc does not ship
//!   transport/      SMB + Kerberos, copied from RustHound-CE
//!
//! Logs go to stderr, the JSON report to stdout.
//!
//! Authorized use only.

mod args;
mod collect;
mod logger;
mod rpc;
mod report;
mod transport;
mod types;

use anyhow::{Context, Result};
use args::{OutputFormat, extract_args};
use colored::Colorize;
use log::{debug, info};

#[tokio::main]
async fn main() -> Result<()> {
    let opts = extract_args();
    logger::init(opts.verbose, opts.quiet);

    let aliases = opts.collection_method.aliases();
    banner(&opts, &aliases);

    debug!("Starting scan of {} target(s)", opts.targets.len());
    let report = collect::run(&opts, &aliases).await;
    info!("Scan complete - {} edge(s) across {} host(s).",
          report.edge_count, report.hosts_scanned.len());

    // stdout defaults to the table, a file defaults to JSON: one is read by a
    // person, the other by a tool. An explicit --table still wins.
    let format = match (&opts.output, opts.format_explicit) {
        (Some(_), false) => OutputFormat::Json,
        _ => opts.format.clone(),
    };

    // A table written to a file would carry ANSI escapes, since `colored` only
    // looks at whether stdout is a terminal, not at where we actually write.
    if opts.output.is_some() && matches!(format, OutputFormat::Table) {
        colored::control::set_override(false);
    }

    // --table renders a table; both JSON modes serialize the same structure.
    let rendered = match format {
        OutputFormat::Table   => report::render(&report),
        OutputFormat::Json    => serde_json::to_string_pretty(&report)
                                     .context("JSON serialization")?,
        OutputFormat::Compact => serde_json::to_string(&report)
                                     .context("JSON serialization")?,
    };
    debug!("Report rendered, {} bytes", rendered.len());

    match &opts.output {
        Some(dir) => {
            let path = output_path(dir, &opts.domain, &format);
            if let Some(parent) = std::path::Path::new(&path).parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&path, &rendered).with_context(|| format!("writing to {path}"))?;
            info!("{} created!", path.bold());
        }
        // Intentionally println!, not log: stdout carries only the report.
        None => println!("{rendered}"),
    }

    Ok(())
}

/// `<dir>/<datetime>_<domain>_localgroups.<ext>`, the RustHound-CE naming
/// scheme. The extension follows the format: a `--table` run holds text, not
/// JSON, and naming it .json would lie to whatever picks the file up next.
/// ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/json/maker/common.rs
fn output_path(dir: &str, domain: &str, format: &OutputFormat) -> String {
    let datetime = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let domain = domain.to_lowercase();
    let ext = match format {
        OutputFormat::Table => "txt",
        _ => "json",
    };
    format!("{}/{datetime}_{domain}_localgroups.{ext}", dir.trim_end_matches('/'))
}

/// Echo the run settings before scanning.
fn banner(opts: &args::Options, aliases: &[args::Alias]) {
    info!("Domain               : {}", opts.domain.bold());
    info!("User                 : {}", opts.username.bold());
    info!("Auth                 : {}", opts.auth.label().bold());
    info!("Targets              : {}", opts.targets.len());
    info!("Method               : {:?}", opts.collection_method);
    info!("Aliases              : {}", aliases.iter()
        .map(|a| format!("{} ({})", a.rid, a.edge))
        .collect::<Vec<_>>().join(", "));
    info!("Local members        : {}", if !opts.remove_local { "kept" } else { "filtered" });
    info!("No LSAT resolution   : {}s", opts.no_resolve);
    info!("Timeout              : {}s", opts.timeout);
    info!("Verbosity            : {:?}", opts.verbose);
}