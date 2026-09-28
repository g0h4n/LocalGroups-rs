# Roadmap

What LocalGroups-rs does today, and what is left. The target is parity with SharpHound's [`LocalGroupProcessor`](https://github.com/SpecterOps/SharpHoundCommon/blob/v4.8.0/src/CommonLib/Processors/LocalGroupProcessor.cs) in pure Rust, so the collection can move into [RustHound-CE#69](https://github.com/g0h4n/RustHound-CE/issues/69).

## Done

- [x] `SamrOpenAlias` (27) and `SamrGetMembersInAlias` (33), the two opnums `dcerpc` does not ship :white_check_mark:
- [x] The four SharpHound aliases: 544 `AdminTo`, 555 `CanRDP`, 562 `ExecuteDCOM`, 580 `CanPSRemote` :white_check_mark:
- [x] Machine SID from SAMR, no LDAP and no LSA needed :white_check_mark:
- [x] Local members filtered, DC detected so the filter never runs against the domain SID :white_check_mark:
- [x] Group `ObjectIdentifier` in both SharpHound forms, machine and DC :white_check_mark:
- [x] Three auth paths: password, pass-the-hash, Kerberos ccache :white_check_mark:
- [x] BloodHound `LocalGroup` output shape, `Collected` / `FailureReason` per host and per alias :white_check_mark:
- [x] Validated against a live domain controller :white_check_mark:
- [x] `dcerpc`: add LSAT `LsarLookupSids`, resolution for member SIDs to SamAccountName over LSAT :white_check_mark:

## Next

- [ ] Type `ObjectType` from well-known RIDs instead of returning `Base` for every domain SID :red_circle:
- [ ] `SamrEnumerateAliasesInDomain` (15) for non-BUILTIN local groups :red_circle:

## Upstream

- [ ] `dcerpc`: make `samr::{encode_sid, decode_sid}` public, deleting the copy in `samr_alias.rs` :red_circle: