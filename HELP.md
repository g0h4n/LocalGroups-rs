<hr />

- [How to compile it?](#how-to-compile-it)
  - [Using Cargo](#using-cargo)
  - [Required dependencies](#required-dependencies)
- [Authentication](#authentication)
  - [Password bind](#password-bind)
  - [Pass-the-hash](#pass-the-hash)
  - [Kerberos pass-the-ticket](#kerberos-pass-the-ticket)
- [Options](#options)
- [Collection methods](#collection-methods)
- [Privileges required](#privileges-required)
- [Output](#output)
- [Verbosity](#verbosity)
- [Troubleshooting](#troubleshooting)

<hr />

# How to compile it?

## Using Cargo

```bash
cargo build --release
# Binary: ./target/release/localgroups-rs
./target/release/localgroups-rs -h
```

```bash
cargo test
```

The tests need no Domain Controller: the NDR decoders are exercised against
synthesized `SAMPR_PSID_ARRAY_OUT` replies, including a hostile one that claims
`Count = u32::MAX` on a truncated stub.

## Required dependencies

A recent Rust toolchain (edition 2021, Rust >= 1.85 for the current crate
ecosystem). No system libraries are required: SMB2, DCE/RPC, NDR and Kerberos
are all pure Rust. In particular there is **no system GSSAPI dependency**, the
ccache is parsed in-crate and the AP-REQ built with `picky-krb`.

<hr />

# Authentication

The three paths are mutually exclusive: pick exactly one of `-p`, `-H`, `-k`.
They behave identically to RustHound-CE because `src/transport/` is the same code.

## Password bind

```bash
localgroups-rs -d ESSOS.LOCAL -u daenerys.targaryen -p 'P@ssw0rd!' -t MEEREEN.ESSOS.LOCAL
```

NTLMv2 SESSION_SETUP. The password is only used to compute the NTLMv2 response;
it never crosses the wire in clear.

## Pass-the-hash

```bash
localgroups-rs -d ESSOS.LOCAL -u daenerys.targaryen -H :34534854d33b398b66684072224bb47a -t BRAAVOS.ESSOS.LOCAL
```

The raw NT hash is plugged into the NTLMv2 `authenticate_hash()` step. Three
input forms are accepted, as in RustHound-CE:

```text
NTHASH                  32 hex chars
:NTHASH                 colon prefix, LM part empty
LMHASH:NTHASH           full pair, the LM part is ignored
```

## Kerberos pass-the-ticket

```bash
export KRB5CCNAME=/tmp/daenerys.targaryen.ccache
localgroups-rs -d ESSOS.LOCAL -u daenerys.targaryen -k -t MEEREEN.ESSOS.LOCAL

# Pin a specific KDC when the domain name does not resolve locally
localgroups-rs -d ESSOS.LOCAL -u daenerys.targaryen -k --kdc 192.168.56.12 -t MEEREEN.ESSOS.LOCAL
```

The TGT is read from the MIT ccache in `KRB5CCNAME`, a `cifs/<host>` service
ticket is requested, and a SPNEGO AP-REQ plus the 16-byte SMB session key are
handed to `SmbClient::login_kerberos`.

Two consequences worth knowing:

- The AP-REQ is bound to one host's SPN, so **Kerberos material is rebuilt for
  every target** in the scope. A wide sweep means one TGS-REQ per host.
- Targets must be named by the **FQDN the SPN uses**, not by IP.
  `-t 192.168.56.12 -k` will fail to map to a `cifs/` SPN.

Only lengths, etypes, realm and SPN are logged. Session keys, subkeys and ticket
bytes never are, at any verbosity.

<hr />

# Options

```text
Windows local group collector (SAMR BUILTIN aliases) for BloodHound Community Edition.
g0h4n <https://twitter.com/g0h4n_0>

Usage: localgroups-rs [OPTIONS] --domain <domain> --username <username>

Options:
  -v...          Set the level of verbosity
  -h, --help     Print help
  -V, --version  Print version

REQUIRED VALUES:
  -d, --domain <domain>      Domain name like: DOMAIN.LOCAL
  -u, --username <username>  Username for the SMB session, like: user@domain.local

OPTIONAL VALUES:
  -p, --password <password>          Password for the SMB session
  -H, --hashes <hashes>              NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]
  -t, --targets <targets>            Target host(s), comma-separated FQDN or IP like: DC01.DOMAIN.LOCAL,192.168.1.10
  -T, --targets-file <targets-file>  File containing one target host per line, '#' lines are ignored
      --kdc <kdc>                    KDC to request the cifs/<host> tickets from, only used with --kerberos [default: the domain]
  -o, --output <output>              Output directory where you would like to save the report, named <datetime>_<domain>_localgroups.json (JSON unless --table) [default: stdout]
      --timeout <timeout>            TCP connection timeout per host in seconds [default: 5]

OPTIONAL FLAGS:
  -c, --collectionmethod [<COLLECTIONMETHOD>]
          Which BUILTIN alias to enumerate. Supported: All (RID 544, 555, 562, 580), AdminOnly (544, AdminTo), RdpOnly (555, CanRDP), DcomOnly (562, ExecuteDCOM), PSRemoteOnly (580, CanPSRemote) (default: All) [possible values: All, AdminOnly, RdpOnly, DcomOnly, PSRemoteOnly]
  -k, --kerberos
          Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.
      --no-resolve
          No resolution for member SIDs to SamAccountName over LSAT (one extra \lsarpc call per host)
      --include-local
          Keep the members that live in the target's own SAM, filtered out by default because they have no BloodHound node
      --table
          Print a colored result table [default] [alias: --pretty]
      --json
          Print the JSON report instead of the table
      --compact
          Print the JSON report on a single line
  -q, --quiet
          Silence every log line so that stdout carries only the JSON report

```

`-t` and `-T` are merged; duplicates are removed and order is preserved.

`-p`, `-H` and `-k` are declared as conflicting in clap, so passing two of them
is rejected with a usage error rather than silently preferring one. `--kdc`
without `-k` is rejected too, by an explicit check: clap's `requires()` cannot
express it, because a boolean flag always carries a value.

With `-o`, the file is named the way RustHound-CE names its own, so the two sit
side by side in the same loot directory:

```text
<dir>/<YYYYMMDDHHMMSS>_<domain>_localgroups.json
/tmp/loot/20260928112823_essos.local_localgroups.json
```

The directory is created if it does not exist. Without `-o` the report goes to
stdout, which stays the pipe-friendly default.

<hr />

# Collection methods

| `-c` value | RID | BUILTIN group | Edge |
|---|---|---|---|
| `AdminOnly` | 544 | Administrators | `AdminTo` |
| `RdpOnly` | 555 | Remote Desktop Users | `CanRDP` |
| `DcomOnly` | 562 | Distributed COM Users | `ExecuteDCOM` |
| `PSRemoteOnly` | 580 | Remote Management Users | `CanPSRemote` |
| `All` (default) | all four | | |

`AdminOnly` is the cheapest sweep on a wide scope: one `SamrOpenAlias` plus one
`SamrGetMembersInAlias` per host on top of the session setup.

The per-host call sequence is:

```text
TCP 445 -> NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT IPC$      transport/smb.rs
  open \samr pipe -> DCE/RPC bind
    SamrConnect2                        opnum 57
    SamrEnumerateDomains + LookupDomain opnum  6 / 5    machine SID
    SamrOpenDomain S-1-5-32             opnum  7        BUILTIN
    SamrOpenAlias <rid>                 opnum 27        samr_alias.rs
    SamrGetMembersInAlias               opnum 33        samr_alias.rs
    SamrCloseHandle                     opnum  1
```

<hr />

# Privileges required

See also the privilege notes in the upstream tracking issue,
[RustHound-CE#69](https://github.com/g0h4n/RustHound-CE/issues/69).

Remote SAM access is governed by `RestrictRemoteSam`
(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSam`). Since
Windows 10 1607 / Server 2016 its default security descriptor grants access to
**local Administrators only on non-DCs**, and to **Everyone on domain
controllers**. Before those versions nothing is restricted by default. The
setting was back-ported to Server 2008 R2 by the March 2017 updates, so an older
OS does not guarantee access.

In practice:

- **Domain controller**: a plain domain user works. This is how SharpHound
  collects DC admins without being an admin.
- **Member server or workstation, 1607 / 2016 and later**: local admin on the
  target is required.
- **Member host, older and unhardened**: a plain domain user usually works.

Nothing is fatal. A host refused at `SamrConnect2` is reported with
`"Collected": false` and a `FailureReason`, an alias refused at `SamrOpenAlias`
is reported the same way at alias level, and the scan continues.

<hr />

# Output

Local members are filtered by default. A member whose SID sits under the
target's own machine SID is a purely local account with no node in BloodHound,
so emitting it would create a dangling edge. The machine SID is learned from
SAMR itself (`SamrEnumerateDomains` then `SamrLookupDomainInSamServer` on the
non-BUILTIN domain), so no LDAP and no LSA round trip is needed. Pass
`--include-local` to keep them, which is what you want when auditing local admin
hygiene rather than building a graph.

The prefix test compares sub-authority arrays, not rendered strings, so
`S-1-5-21-1-2-30-500` is never mistaken for a child of `S-1-5-21-1-2-3`.

On a **domain controller** the filter is disabled automatically: SAMR's
non-BUILTIN domain is the AD domain there, so its SID is the domain SID, and
filtering on it would drop every domain principal. `is_domain_controller` in the
JSON says which case applied.

The group `ObjectIdentifier` takes one of two forms, as in SharpHound:

```text
member host:  <machine SID>-<rid>          S-1-5-21-1111-2222-3333-544
DC:           <DOMAIN>-S-1-5-32-<rid>      ESSOS.LOCAL-S-1-5-32-544
```

On a DC the BUILTIN aliases are the domain's well-known groups, not
machine-local ones, so they are emitted as the domain-scoped well-known
principal. Using the machine form there would invent a SID that exists nowhere
in AD.

```json
{
  "domain": "ESSOS.LOCAL",
  "hosts_scanned": ["MEEREEN.ESSOS.LOCAL"],
  "edge_count": 1,
  "edges": [
    { "principal": "S-1-5-21-3600700137-3291257795-828247845-512",
      "host": "MEEREEN.ESSOS.LOCAL", "edge": "AdminTo", "via": "Administrators" }
  ],
  "by_principal": {
    "S-1-5-21-3600700137-3291257795-828247845-512": ["MEEREEN.ESSOS.LOCAL"]
  },
  "computers": [
    {
      "host": "MEEREEN.ESSOS.LOCAL",
      "machine_sid": "S-1-5-21-3600700137-3291257795-828247845",
      "is_domain_controller": true,
      "Collected": true,
      "FailureReason": null,
      "LocalGroups": [
        {
          "ObjectIdentifier": "ESSOS.LOCAL-S-1-5-32-544",
          "Results": [
            { "ObjectIdentifier": "S-1-5-21-3600700137-3291257795-828247845-512",
              "ObjectType": "Base" }
          ],
          "LocalNames": [],
          "Collected": true,
          "FailureReason": null
        }
      ]
    }
  ]
}
```

`ObjectType` is a best-effort guess from the SID alone. Well-known SIDs are
labelled; a domain SID comes back as `Base`, because telling User from Group
from Computer needs LDAP. RustHound-CE resolves that against the graph at merge
time, so the gap closes on the port.

`LocalNames` is always empty for now: resolving the names of non-domain members
needs LSAT `LsarLookupSids`, which `dcerpc` does not expose yet (it ships
`LsarLookupNames`, which resolves the other direction). Not a blocker, BloodHound
keys on `ObjectIdentifier`.

<hr />

# Verbosity

Logs go to stderr, the JSON report to stdout, so the two never mix in a pipe.

```text
(none)  INFO   per-host progress, per-alias results, final tally
-v      DEBUG  RPC sequence, correlation counts, report size
-vv     TRACE  handles, computed group ids,each individual member kept or dropped
-q      OFF    nothing on stderr at all
```

<hr />

# Troubleshooting

- **`nca_s_fault_access_denied` at `SamrConnect2` (RPC fault `0x00000005`)**,
  the call was refused before SAMR ran. On a member host this is the normal
  outcome for a plain domain user since Win10 1607 / Server 2016: use an account
  that is local admin on the target, or collect that host from GPO instead. The
  host is reported with `"Collected": false` and a `FailureReason`.
- **`ACCESS_DENIED` on every alias, every host**, likely `RestrictRemoteSam`
  rather than credentials. Confirm with an account that is local admin on one
  target.
- **`STATUS_OBJECT_NAME_NOT_FOUND` on RID 580**, normal, Remote Management Users
  does not exist on some older or Core builds. The other aliases are unaffected.
- **`\samr pipe: ...` on connect**, IPC$ mounted but the pipe was refused.
  Usually a host-based firewall or a hardened DC.
- **Kerberos: `no TGT (krbtgt) found in ccache`**, `KRB5CCNAME` points at a
  ccache holding only service tickets. Re-run `kinit` or re-export the TGT.
- **Kerberos: ticket request fails for an IP target**, SPNs are built as
  `cifs/<host>`, so targets must be FQDNs. Use `-t MEEREEN.ESSOS.LOCAL`, not
  `-t 192.168.56.12`.
- **Kerberos: KDC unreachable**, the default KDC is the `--domain` value. Pin a
  DC explicitly with `--kdc`.
- **`Count=... exceeds remaining stub`**, a truncated or malformed
  `GetMembersInAlias` reply was rejected on purpose. Re-run with `-vv` and open
  an issue with the trace if it is reproducible.