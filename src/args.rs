//! Parsing arguments
//! Modeled on RustHound-CE's args.rs
//! ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/args.rs
use clap::{Arg, ArgAction, value_parser, Command};

/// Tool version, pulled from Cargo.toml at compile time.
pub const LOCALGROUPS_VERSION: &str = env!("CARGO_PKG_VERSION");

// Collection methods

/// Which BUILTIN aliases to read. One alias, one BloodHound edge.
///
/// | RID | BUILTIN group            | BloodHound edge |
/// |-----|--------------------------|-----------------|
/// | 544 | Administrators           | `AdminTo`       |
/// | 555 | Remote Desktop Users     | `CanRDP`        |
/// | 562 | Distributed COM Users    | `ExecuteDCOM`   |
/// | 580 | Remote Management Users  | `CanPSRemote`   |
#[derive(Clone, Debug)]
pub enum CollectionMethod {
    /// All four aliases (544 + 555 + 562 + 580). Default.
    All,
    /// Only BUILTIN\Administrators (RID 544) -> AdminTo.
    AdminOnly,
    /// Only BUILTIN\Remote Desktop Users (RID 555) -> CanRDP.
    RdpOnly,
    /// Only BUILTIN\Distributed COM Users (RID 562) -> ExecuteDCOM.
    DcomOnly,
    /// Only BUILTIN\Remote Management Users (RID 580) -> CanPSRemote.
    PSRemoteOnly,
}

/// One BUILTIN alias to query: its RID, its display name, its BloodHound edge.
#[derive(Clone, Copy, Debug)]
pub struct Alias {
    pub rid:  u32,
    pub name: &'static str,
    pub edge: &'static str,
}

/// The four aliases SharpHound reads, in its own order (LocalGroupRids).
pub const ALL_ALIASES: &[Alias] = &[
    Alias { rid: 544, name: "Administrators",          edge: "AdminTo"     },
    Alias { rid: 555, name: "Remote Desktop Users",    edge: "CanRDP"      },
    Alias { rid: 562, name: "Distributed COM Users",   edge: "ExecuteDCOM" },
    Alias { rid: 580, name: "Remote Management Users", edge: "CanPSRemote" },
];

impl CollectionMethod {
    /// Expand the selected method into the concrete alias list to query.
    pub fn aliases(&self) -> Vec<Alias> {
        let keep = |rid: u32| ALL_ALIASES.iter().copied().filter(|a| a.rid == rid).collect();
        match self {
            Self::All          => ALL_ALIASES.to_vec(),
            Self::AdminOnly    => keep(544),
            Self::RdpOnly      => keep(555),
            Self::DcomOnly     => keep(562),
            Self::PSRemoteOnly => keep(580),
        }
    }
}

// Output format

#[derive(Clone, Debug)]
pub enum OutputFormat {
    /// Colored table for a human reader. The default.
    Table,
    /// Pretty-printed JSON, with --json.
    Json,
    /// Compact JSON, one line, with --compact.
    Compact,
}

// Options struct

/// All runtime options, built by [`extract_args`].
#[derive(Clone, Debug)]
pub struct Options {
    // Authentication
    /// NetBIOS domain name (e.g. CORP).
    pub domain: String,
    /// Username for SMB auth (e.g. alice or CORP\alice).
    pub username: String,
    /// Password, NT hash, or Kerberos ccache. Resolved once here; the per-host
    /// SmbAuth is derived from it in transport::connect_ipc_with.
    pub auth: crate::transport::AuthConfig,

    // Targets
    /// List of hosts to scan (from -t and/or --targets-file).
    pub targets: Vec<String>,

    // Collection
    /// Which BUILTIN aliases to enumerate.
    pub collection_method: CollectionMethod,
    /// Remove members from the host's own SAM instead of dropping them.
    pub remove_local: bool,
    /// No resolution for member SIDs to names over LSAT default is false.
    pub no_resolve: bool,
    /// TCP connection timeout in seconds.
    pub timeout: u64,

    // Output
    /// Output format. Defaults to the table, JSON on request.
    pub format: OutputFormat,
    /// True when the operator named a format. Lets `-o` default to JSON
    /// without overriding an explicit `--table`.
    pub format_explicit: bool,
    /// Directory to write the JSON file into. None means stdout.
    pub output: Option<String>,

    // Logging
    /// Verbosity: 0 = INFO / 1 = DEBUG / 2+ = TRACE.
    pub verbose: log::LevelFilter,
    /// Silence all [DEBUG] traces (same as -q / --quiet).
    pub quiet: bool,
}

// CLI definition

fn cli() -> Command {
    // Return Command args
    Command::new("localgroups-rs")
    .version(LOCALGROUPS_VERSION)
    .about("Windows local group collector (SAMR BUILTIN aliases) for BloodHound Community Edition.\ng0h4n <https://twitter.com/g0h4n_0>")
    .arg(Arg::new("v")
        .short('v')
        .help("Set the level of verbosity")
        .action(ArgAction::Count),
    )
    .next_help_heading("REQUIRED VALUES")
    .arg(Arg::new("domain")
        .short('d')
        .long("domain")
        .help("Domain name like: DOMAIN.LOCAL")
        .required(true)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("username")
        .short('u')
        .long("username")
        .help("Username for the SMB session, like: user@domain.local")
        .required(true)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("OPTIONAL VALUES")
    .arg(Arg::new("password")
        .short('p')
        .long("password")
        .help("Password for the SMB session")
        .required(false)
        .conflicts_with_all(["hashes", "kerberos"])
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("hashes")
        .short('H')
        .long("hashes")
        .help("NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]")
        .required(false)
        .conflicts_with("kerberos")
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("targets")
        .short('t')
        .long("targets")
        .help("Target host(s), comma-separated FQDN or IP like: DC01.DOMAIN.LOCAL,192.168.1.10")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("targets-file")
        .short('T')
        .long("targets-file")
        .help("File containing one target host per line, '#' lines are ignored")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("kdc")
        .long("kdc")
        .help("KDC to request the cifs/<host> tickets from, only used with --kerberos [default: the domain]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("output")
        .short('o')
        .long("output")
        .help("Output directory where you would like to save the report, named <datetime>_<domain>_localgroups.json (JSON unless --table) [default: stdout]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("timeout")
        .long("timeout")
        .help("TCP connection timeout per host in seconds")
        .required(false)
        .value_parser(value_parser!(u64))
        .default_value("5")
    )
    .next_help_heading("OPTIONAL FLAGS")
    .arg(Arg::new("collectionmethod")
        .short('c')
        .long("collectionmethod")
        .help("Which BUILTIN alias to enumerate. Supported: All (RID 544, 555, 562, 580), AdminOnly (544, AdminTo), RdpOnly (555, CanRDP), DcomOnly (562, ExecuteDCOM), PSRemoteOnly (580, CanPSRemote) (default: All)")
        .required(false)
        .value_name("COLLECTIONMETHOD")
        .value_parser(["All", "AdminOnly", "RdpOnly", "DcomOnly", "PSRemoteOnly"])
        .num_args(0..=1)
        .default_missing_value("All")
    )
    .arg(Arg::new("kerberos")
        .short('k')
        .long("kerberos")
        .help("Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("no-resolve")
        .long("no-resolve")
        .help("No resolution for member SIDs to SamAccountName over LSAT (one extra \\lsarpc call per host)")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("remove-local")
        .long("remove-local")
        .help("Remove the members that live in the target's own SAM, filtered out by default because they have no BloodHound node")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("table")
        .long("table")
        .visible_alias("pretty")
        .help("Print a colored result table [default]")
        .required(false)
        .action(ArgAction::SetTrue)
        .conflicts_with_all(["json", "compact"])
        .global(false)
    )
    .arg(Arg::new("json")
        .long("json")
        .help("Print the JSON report instead of the table")
        .required(false)
        .action(ArgAction::SetTrue)
        .conflicts_with("compact")
        .global(false)
    )
    .arg(Arg::new("compact")
        .long("compact")
        .help("Print the JSON report on a single line")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("quiet")
        .short('q')
        .long("quiet")
        .help("Silence every log line so that stdout carries only the JSON report")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
}

// Hash parsing (mirrors RustHound-CE)

/// Parse an NT hash into 16 bytes. Accepted formats:
///   NTHASH                 : 32 hex chars
///   :NTHASH                : colon prefix, LM part empty
///   LMHASH:NTHASH          : full pair, LM part ignored
///
/// ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/ldap.rs
pub fn parse_nt_hash(input: &str) -> Result<[u8; 16], String> {
    let clean = input.trim();
    // Strip the LM part if present (right side of ':' is the NT hash).
    let nt = match clean.split_once(':') {
        Some((_lm, nt)) => nt,
        None             => clean,
    };
    if nt.len() != 32 || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "Invalid NT hash '{}': expected exactly 32 hex characters.\n  \
             Accepted formats: NTHASH | :NTHASH | LMHASH:NTHASH",
            nt
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, pair) in nt.as_bytes().chunks(2).enumerate() {
        // Safety: both bytes are guaranteed ASCII hex by the check above.
        bytes[i] = u8::from_str_radix(
            std::str::from_utf8(pair).unwrap(), 16
        ).unwrap();
    }
    Ok(bytes)
}

// Public entry point

/// Parse the command line. Exits with usage on error.
pub fn extract_args() -> Options {
    let matches = cli().get_matches();

    // Targets (merge -t and --targets-file)
    let mut targets: Vec<String> = matches
        .get_one::<String>("targets")
        .map(|s| {
            s.split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect()
        })
        .unwrap_or_default();

    if let Some(path) = matches.get_one::<String>("targets-file") {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let h = line.trim();
                    if !h.is_empty() && !h.starts_with('#') {
                        targets.push(h.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("[!] Cannot read targets-file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    }

    // De-dup while preserving order.
    let mut seen = std::collections::BTreeSet::new();
    targets.retain(|h| seen.insert(h.clone()));

    if targets.is_empty() {
        eprintln!(
            "[!] No targets specified. Use -t <HOST> or --targets-file <FILE>.\n\
             Run with --help for usage."
        );
        std::process::exit(1);
    }

    // Authentication: exactly one of --password / --hashes / --kerberos
    let domain     = matches.get_one::<String>("domain").unwrap().clone();
    let password   = matches.get_one::<String>("password").cloned().unwrap_or_default();
    let hashes_raw = matches.get_one::<String>("hashes").cloned();
    let kerberos   = matches.get_flag("kerberos");

    let chosen = [!password.is_empty(), hashes_raw.is_some(), kerberos]
        .iter()
        .filter(|b| **b)
        .count();

    if chosen == 0 {
        eprintln!(
            "[!] No credentials provided.\n  \
             Use -p <PASSWORD>, -H <NTHASH> (pass-the-hash), or -k (Kerberos ccache).\n  \
             Run with --help for usage."
        );
        std::process::exit(1);
    }
    // chosen > 1 is unreachable: clap rejects it via conflicts_with_all.

    // clap's requires() cannot express this: --kerberos is a SetTrue flag, so
    // it always has a value and the requirement is always satisfied.
    if matches.contains_id("kdc") && matches.get_one::<String>("kdc").is_some() && !kerberos {
        eprintln!("[!] --kdc only applies to Kerberos authentication, add -k.");
        std::process::exit(1);
    }

    let auth = if kerberos {
        // Pass-the-ticket: the TGT comes from the ccache in KRB5CCNAME, and a
        // cifs/<host> service ticket is built per target at connect time.
        // ref: https://github.com/g0h4n/RustHound-CE/blob/main/src/transport/kerberos.rs
        let ccache = match std::env::var("KRB5CCNAME") {
            Ok(v) if !v.trim().is_empty() => v,
            _ => {
                eprintln!(
                    "[!] --kerberos requires KRB5CCNAME to point at an MIT ccache.\n  \
                     Example: export KRB5CCNAME=/tmp/alice.ccache"
                );
                std::process::exit(1);
            }
        };
        // FILE: prefixes are handled downstream; only existence is checked here
        // so the operator fails fast instead of once per host.
        let path = ccache.strip_prefix("FILE:").unwrap_or(&ccache);
        if !std::path::Path::new(path).exists() {
            eprintln!("[!] ccache '{path}' (from KRB5CCNAME) does not exist.");
            std::process::exit(1);
        }
        // No --kdc given: the domain name resolves to a DC on any joined or
        // DNS-pointed host, which is the usual case.
        let kdc = matches.get_one::<String>("kdc").cloned().unwrap_or_else(|| domain.clone());
        crate::transport::AuthConfig::Kerberos { ccache, kdc }
    } else if let Some(h) = &hashes_raw {
        match parse_nt_hash(h) {
            Ok(bytes) => crate::transport::AuthConfig::Hash(bytes),
            Err(e)    => { eprintln!("[!] {e}"); std::process::exit(1); }
        }
    } else {
        crate::transport::AuthConfig::Password(password)
    };

    // Collection method
    let collection_method =
        match matches.get_one::<String>("collectionmethod").map(|s| s.as_str()).unwrap_or("All") {
            "AdminOnly"    => CollectionMethod::AdminOnly,
            "RdpOnly"      => CollectionMethod::RdpOnly,
            "DcomOnly"     => CollectionMethod::DcomOnly,
            "PSRemoteOnly" => CollectionMethod::PSRemoteOnly,
            _              => CollectionMethod::All,
        };

    // Verbosity
    let verbose = match matches.get_count("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    Options {
        domain,
        username: matches.get_one::<String>("username").unwrap().clone(),
        auth,
        targets,
        collection_method,
        remove_local: matches.get_flag("remove-local"),
        no_resolve: matches.get_flag("no-resolve"),
        timeout: *matches.get_one::<u64>("timeout").unwrap_or(&5),
        // The table is the default; JSON is asked for explicitly.
        format: if matches.get_flag("compact") {
            OutputFormat::Compact
        } else if matches.get_flag("json") {
            OutputFormat::Json
        } else {
            OutputFormat::Table
        },
        format_explicit: matches.get_flag("table")
            || matches.get_flag("json")
            || matches.get_flag("compact"),
        output: matches.get_one::<String>("output").cloned(),
        verbose,
        quiet: matches.get_flag("quiet"),
    }
}