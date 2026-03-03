<p align="center">
  <h1 align="center"><b>sopa</b></h1>
  <p align="center"><i>A practical client for ADWS in Golang.</i></p>
  <p align="center">
    <img src="https://img.shields.io/github/v/release/Macmod/sopa" alt="GitHub Release">
    <img src="https://img.shields.io/github/go-mod/go-version/Macmod/sopa" alt="Go Version">
    <img src="https://img.shields.io/github/languages/code-size/Macmod/sopa" alt="Code Size">
    <img src="https://img.shields.io/github/license/Macmod/sopa" alt="License">
    <img src="https://img.shields.io/github/actions/workflow/status/Macmod/sopa/release.yml" alt="Build Status">
    <a href="https://goreportcard.com/report/github.com/Macmod/sopa"><img src="https://goreportcard.com/badge/github.com/Macmod/sopa" alt="Go Report Card"></a>
    <img src="https://img.shields.io/github/downloads/Macmod/sopa/total" alt="GitHub Downloads">
    <a href="https://twitter.com/MacmodSec"><img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/MacmodSec?style=for-the-badge&logo=X&color=blue"></a>
  </p>
</p>

Sopa implements the ADWS protocol stack ([MS-NNS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nns) + [MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf) + SOAP), exposing the following command-line features:
- **Object search & retrieval**
  - `query` — runs LDAP-filter searches via WS-Enumeration `Enumerate` + `Pull` loop with attribute projection, scope control (Base/OneLevel/Subtree), and pagination
  - `get` — fetches a single object by DN via WS-Transfer `Get`
- **Object lifecycle**
  - `create` — creates objects via WS-Transfer `ResourceFactory` (built-in types: user, computer, group, OU, container; or custom objects from a YAML template via IMDA `AddRequest`)
  - `delete` — removes an object by DN via WS-Transfer `Delete`
- **Attribute editing**
  - `attr` — adds, replaces, or removes individual attribute values on an existing object via WS-Transfer `Put`
- **Account management**
  - `set-password` — sets an account password via MS-ADCAP `SetPassword`
  - `change-password` — changes an account password (requires the old password) via MS-ADCAP `ChangePassword`
- **ADCAP custom actions**
  - `translate-name` — converts between DN and canonical name formats via `TranslateName`
  - `groups` — lists group memberships or authorization groups of a principal via `GetADPrincipalGroupMembership` / `GetADPrincipalAuthorizationGroup`
  - `members` — enumerates group members (optionally recursive) via `GetADGroupMember`
  - `optfeature` — toggles optional AD features (e.g. Recycle Bin) via `ChangeOptionalFeature`
  - `info` — retrieves topology metadata (version, domain, forest, DC list) via `GetVersion`, `GetADDomain`, `GetADForest`, `GetADDomainControllers`
- **Service metadata**
  - `mex` — fetches ADWS service endpoint metadata via an unauthenticated WS-MetadataExchange request

# Installation

```bash
$ go install github.com/Macmod/sopa/cmd/sopa@latest
```

# Usage

```bash
# Auth flags (-u, -p, -d, -k, -H, -c, ...) are omitted for brevity — see Authentication section.

# Search objects by LDAP filter
$ sopa [auth_flags] query --dc <DC> --filter '(objectClass=*)'

# Fetch a single object by DN
$ sopa [auth_flags] get --dc <DC> --dn '<DN>'

# Delete an object by DN
$ sopa [auth_flags] delete --dc <DC> --dn '<DN>'

# Edit attribute values
$ sopa [auth_flags] attr add     --dc <DC> --dn '<DN>' --attr <ATTR> --value <VALUE>
$ sopa [auth_flags] attr replace --dc <DC> --dn '<DN>' --attr <ATTR> --value <VALUE>
$ sopa [auth_flags] attr delete  --dc <DC> --dn '<DN>' --attr <ATTR>

# Create objects
$ sopa [auth_flags] create user      --dc <DC> --name <CN> --pass <INITIAL_PASS>
$ sopa [auth_flags] create computer  --dc <DC> --name <CN>
$ sopa [auth_flags] create group     --dc <DC> --name <CN> --type GlobalSecurity
$ sopa [auth_flags] create ou        --dc <DC> --name <CN>
$ sopa [auth_flags] create container --dc <DC> --name <CN>
$ sopa [auth_flags] create custom    --dc <DC> --template <TEMPLATE.yaml>

# Set / change account passwords (MS-ADCAP)
$ sopa [auth_flags] set-password    --dc <DC> --dn '<DN>' --new <NEW_PASS>
$ sopa [auth_flags] change-password --dc <DC> --dn '<DN>' --old <OLD_PASS> --new <NEW_PASS>

# Translate DN <-> canonical name (MS-ADCAP)
# (this call is mostly useless but kept for completeness 😄)
$ sopa [auth_flags] translate-name --dc <DC> --offered DistinguishedName --desired CanonicalName '<DN>'

# Principal group memberships (MS-ADCAP)
$ sopa [auth_flags] groups --dc <DC> --dn '<DN>' --membership --authz

# Group members (MS-ADCAP)
$ sopa [auth_flags] members --dc <DC> --dn '<GROUP_DN>' --recursive

# Toggle optional AD feature, e.g. Recycle Bin (MS-ADCAP)
$ sopa [auth_flags] optfeature --dc <DC> --feature-id <FEATURE_GUID> --enable

# Topology info (MS-ADCAP)
$ sopa [auth_flags] info version --dc <DC>
$ sopa [auth_flags] info domain  --dc <DC>
$ sopa [auth_flags] info forest  --dc <DC>
$ sopa [auth_flags] info dcs     --dc <DC>

# ADWS service endpoint metadata (unauthenticated - auth flags not needed)
$ sopa mex --dc <DC>
```

## Interactive shell

Run `sopa` without a subcommand to open an interactive shell. It reuses a single connection for all commands and provides tab-completion.

```bash
$ sopa --dc <DC> -u <USER> -p <PASS> -d <DOMAIN>

sopa v1.1.0
Connected  dc.corp.local  domain=corp.local  user=Administrator
Type 'help' for commands or 'exit' to quit.

[corp.local]> query --filter '(objectClass=user)' --attrs sAMAccountName
[corp.local]> get --dn 'CN=Administrator,CN=Users,DC=corp,DC=local'
[corp.local]> exit
```

Use `exit`, `quit`, or Ctrl-D to leave the shell.

## Custom objects creation

Example template: [examples/custom-create.example.yaml](examples/custom-create.example.yaml)

Template schema (YAML):

- `parentDN` (string, required): container DN
- `rdn` (string, required): relative DN for the new object (e.g. `CN=Foo`)
- `attributes` (list, required): each item has:
	- `name` (string, required): attribute name (`cn` or `addata:cn`)
	- `type` (string, optional): `string|int|bool|base64|hex` (or explicit `xsd:*`), default `string`
	- either `value` (string) or `values` (list of strings)

Notes:
- Do not include `ad:relativeDistinguishedName` or `ad:container-hierarchy-parent` in the template (they are injected automatically).
- `hex` values are converted to `xsd:base64Binary`.
- To set an empty string explicitly, use `value: ""`.

## DC discovery & DNS

`--dc` accepts a **FQDN**, an **IP address**, or can be **omitted**.
Because the DC's hostname is sometimes not available from the network's default DNS, it is strongly recommended to always pass `--dns <DC-IP>` so that sopa uses the DC's own DNS server for all lookups:

```bash
# Option 1: let sopa resolve everything through the DC's DNS
$ sopa query --dns 192.168.1.10 -d corp.local -u user -p pass --filter '(objectClass=user)'
```

When `--dc` is omitted and `--domain` is provided, sopa discovers a DC
automatically by querying SRV records:

```
_ldap._tcp.<domain>        (tried first)
_kerberos._tcp.<domain>    (fallback)
```

The target of the highest-priority record is used. This requires that the
DNS server pointed to by `--dns` can answer those SRV queries — the DC's own
integrated DNS server (when present) should be capable of that.

```bash
# Option 2: provide DC explicitly without Kerberos
$ sopa info version --dc 192.168.1.10 --domain corp.local -u user -p pass
```

When an IP is provided for `--dc` and Kerberos is in use, the IP is resolved to an FQDN via a **reverse PTR lookup** so that the Kerberos SPN / KDC address are correct.
This PTR lookup also goes through `--dns`, so a correctly configured reverse
zone on the DC is required:

```bash
# Option 3: IP input + Kerberos: PTR lookup resolves 192.168.1.10 -> dc.corp.local
$ sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

When Kerberos is not in use, there is no PTR lookup — the raw IP is used throughout.

All DNS operations in the stack - DC discovery, PTR resolution, ADWS TCP dial,
and Kerberos KDC connections - use the same resolver built from `--dns` /
`--dns-tcp`.

| Flag | Description |
|------|-------------|
| `--dns <host[:port]>` | Custom DNS server for all lookups (SRV, PTR, forward). Defaults to port 53. |
| `--dns-tcp` | Force DNS queries over TCP instead of UDP. Useful when UDP is blocked or SRV responses are large. |
| `--dns-timeout <duration>` | Timeout for DNS operations (default 10s). |
| `--tcp-timeout <duration>` | Timeout for TCP dial and ADWS protocol operations (default 30s). |

# Authentication

`sopa` supports the following credential modes:

```bash
# Password
$ sopa --dc <DC> -d <DOMAIN> -u <USER> -p <PASS> <subcommand> [...]

# NT hash
$ sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> <subcommand> [...]

# AES session key (Kerberos is implied)
# 32 hex chars = AES-128, 64 hex chars = AES-256
$ sopa --dc <DC> -d <DOMAIN> -u <USER> --aes-key <HEX_KEY> <subcommand> [...]

# Kerberos ccache (Kerberos is implied)
$ sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE_PATH> <subcommand> [...]

# PFX certificate (Kerberos is implied / via PKINIT)
$ sopa --dc <DC> -d <DOMAIN> -u <USER> --pfx <CERT.pfx> --pfx-password <PFX_PASS> <subcommand> [...]

# PEM certificate (Kerberos is implied / via PKINIT)
$ sopa --dc <DC> -d <DOMAIN> -u <USER> --cert <CERT.pem> --key <KEY.pem> <subcommand> [...]
```

# Contributing

Contributions are welcome by [opening an issue](https://github.com/Macmod/sopa/issues) or [submitting a pull request](https://github.com/Macmod/sopa/pulls).

# Other ADWS tools

The idea to write this tool came from a wave of ADWS-focused tools, mainly for evasion purposes. In theory all that can be done with these can also be done with `sopa`, but if you want to perform more complex/specific actions, check them out too:

* [wh0amitz/SharpADWS](https://github.com/wh0amitz/SharpADWS)
* [logangoins/SOAPy](https://github.com/logangoins/SOAPy)
* [FalconForceTeam/SOAPHound](https://github.com/FalconForceTeam/SOAPHound)
* [mverschu/adwsdomaindump](https://github.com/mverschu/adwsdomaindump)

# SOCKS support

SOCKS is currently not implemented. Use a solution like [OkamiW/proxy-ns](https://github.com/OkamiW/proxy-ns) if needed for your use case.

# Acknowledgements

* Big thanks to [oiweiwei](https://github.com/oiweiwei) for [go-msrpc](https://github.com/oiweiwei/go-msrpc), as his `ssp` package implemented the authentication flow with GSSAPI seamlessly.

# References

- [MS-NNS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nns) - .NET NegotiateStream Protocol
- [MS-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf) - .NET Message Framing Protocol
- [MS-ADDM](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-addm) - Active Directory Web Services: Data Model and Common Elements
- [MS-WSDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsds) - WS-Enumeration: Directory Services Protocol Extensions
- [MS-WSTIM](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-wstim) - WS-Transfer: Identity Management Operations for Directory Access Extensions
- [MS-ADCAP](https://learn.microsoft.com/zh-cn/openspecs/windows_protocols/ms-adcap) - Active Directory Web Services Custom Action Protocol
- [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts) - Active Directory Technical Specification

# License

The MIT License (MIT)

Copyright (c) 2023 Artur Henrique Marzano Gonzaga

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

