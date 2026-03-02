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
$ sopa query --dc <DC> --filter '(objectClass=*)'

# Fetch a single object by DN
$ sopa get --dc <DC> --dn '<DN>'

# Delete an object by DN
$ sopa delete --dc <DC> --dn '<DN>'

# Edit attribute values
$ sopa attr add     --dc <DC> --dn '<DN>' --attr <ATTR> --value <VALUE>
$ sopa attr replace --dc <DC> --dn '<DN>' --attr <ATTR> --value <VALUE>
$ sopa attr delete  --dc <DC> --dn '<DN>' --attr <ATTR>

# Create objects
$ sopa create user      --dc <DC> --name <CN> --pass <INITIAL_PASS>
$ sopa create computer  --dc <DC> --name <CN>
$ sopa create group     --dc <DC> --name <CN> --type GlobalSecurity
$ sopa create ou        --dc <DC> --name <CN>
$ sopa create container --dc <DC> --name <CN>
$ sopa create custom    --dc <DC> --template <TEMPLATE.yaml>

# Set / change account passwords (MS-ADCAP)
$ sopa set-password    --dc <DC_FQDN> --dn '<DN>' --new <NEW_PASS>
$ sopa change-password --dc <DC_FQDN> --dn '<DN>' --old <OLD_PASS> --new <NEW_PASS>

# Translate DN <-> canonical name (MS-ADCAP)
$ sopa translate-name --dc <DC_FQDN> --offered DistinguishedName --desired CanonicalName '<DN>'

# Principal group memberships (MS-ADCAP)
$ sopa groups --dc <DC_FQDN> --dn '<DN>' --membership --authz

# Group members (MS-ADCAP)
$ sopa members --dc <DC_FQDN> --dn '<GROUP_DN>' --recursive

# Toggle optional AD feature, e.g. Recycle Bin (MS-ADCAP)
$ sopa optfeature --dc <DC_FQDN> --feature-id <FEATURE_GUID> --enable

# Topology info (MS-ADCAP)
$ sopa info version --dc <DC_FQDN>
$ sopa info domain  --dc <DC_FQDN>
$ sopa info forest  --dc <DC_FQDN>
$ sopa info dcs     --dc <DC_FQDN>

# ADWS service endpoint metadata (unauthenticated)
$ sopa mex --dc <DC>
```

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

# Authentication

`sopa` supports the following credential modes:

```bash
# Password
$ sopa <action> --dc <DC> -u <USER> -p <PASS> -d <DOMAIN> ...

# NT hash
$ sopa <action> --dc <DC> -u <USER> -H <NT_HASH> -d <DOMAIN> ...

# AES session key (DC must be FQDN; Kerberos is implied)
# 32 hex chars = AES-128, 64 hex chars = AES-256
$ sopa <action> --dc <DC_FQDN> -u <USER> --aes-key <HEX_KEY> -d <DOMAIN> ...

# Kerberos ccache (DC must be FQDN; Kerberos is implied)
$ sopa <action> --dc <DC_FQDN> -u <USER> -c <CCACHE_PATH> -d <DOMAIN> ...

# PFX certificate
$ sopa <action> --dc <DC_FQDN> -u <USER> --pfx <CERT.pfx> --pfx-password <PFX_PASS> -d <DOMAIN> ...

# PEM certificate
$ sopa <action> --dc <DC_FQDN> -u <USER> --cert <CERT.pem> --key <KEY.pem> -d <DOMAIN> ...
```

# Contributing

Contributions are welcome by [opening an issue](https://github.com/Macmod/sopa/issues) or [submitting a pull request](https://github.com/Macmod/sopa/pulls).

# Other ADWS tools

The idea to write this tool came from a wave of ADWS-focused tools, mainly for evasion purposes. In theory all that can be done with these can also be done with `sopa`, but if you want to perform more complex/specific actions, check them out too:

* [wh0amitz/SharpADWS](https://github.com/wh0amitz/SharpADWS)
* [logangoins/SOAPy](https://github.com/logangoins/SOAPy)
* [FalconForceTeam/SOAPHound](https://github.com/FalconForceTeam/SOAPHound)
* [mverschu/adwsdomaindump](https://github.com/mverschu/adwsdomaindump)

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

