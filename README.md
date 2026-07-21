# NetPipe

Network Infrastructure Configuration Parser and Security Auditor

**NetPipe** is a modern Go rewrite of [nipper-ng](https://gitlab.com/kalilinux/packages/nipper-ng) — the classic network config security auditing tool. It parses saved device configurations from 16+ platforms and generates security audit reports.

## Features

- **20 device types** supported — Cisco IOS, NX-OS, IOS-XE, IOS-XR, PIX/ASA/FWSM, NMP/CatOS, CSS, Juniper ScreenOS & Junos, Palo Alto PAN-OS, Fortinet FortiOS, CheckPoint FW-1, SonicWall, Arista EOS, F5 BIG-IP, Nortel Passport
- **Auto-detect** device type from config content (no need to specify `--ios-router`)
- **Security audit** — password strength, SNMP, ACLs, SSH, Telnet, HTTP, logging, NTP, routing protocols, AAA, banners, and general hardening
- **Cisco Type 7** password decoder
- **John the Ripper** export for Type 5 hashes
- **6 output formats**: HTML (dark theme), JSON, XML, LaTeX, plain text, CSV
- **Single binary** — zero runtime dependencies

## Install

```bash
go install github.com/Cazo-Net/netpipe/cmd/netpipe@latest
```

Or build from source:

```bash
git clone https://github.com/Cazo-Net/netpipe.git
cd netpipe
go build -o netpipe ./cmd/netpipe/
```

## Quick Start

```bash
# Process a Cisco IOS config with auto-detect
netpipe --input=router.conf --output=report.html

# Explicit device type
netpipe --ios-router --input=router.conf --json

# Stream from stdin
cat switch.conf | netpipe --ios-switch --text

# Auto-detect + JSON for machine processing
netpipe --auto-detect --input=firewall.conf --output=audit.json --json
```

## Usage

```
netpipe [options] [input-file]

Device Types:
  --ios-router / --ios-switch / --ios-catalyst    Cisco IOS
  --nxos                                           Cisco NX-OS
  --ios-xe / --ios-xr                              Cisco IOS-XE / XR
  --pix / --asa / --fwsm                           Cisco PIX/ASA/FWSM
  --screenos                                       Juniper ScreenOS
  --junos                                          Juniper Junos
  --panos                                          Palo Alto PAN-OS
  --fortios                                        Fortinet FortiOS
  --eos                                            Arista EOS
  --bigip                                          F5 BIG-IP
  --fw1                                            CheckPoint Firewall-1
  --sonicos                                        SonicWall SonicOS
  --passport                                       Nortel Passport
  --nmp / --catos                                  Cisco NMP/CatOS
  --css                                            Cisco CSS

Output Formats:
  --html       HTML (default, dark theme)
  --json       Machine-readable JSON
  --xml        XML (compatible with nipper)
  --text       Plain text
  --latex      LaTeX document
  --csv        CSV findings export

Audit Options:
  --no-audit           Skip security audit
  --no-passwords       Suppress passwords from output
  --john=<file>        Export Type 5 hashes for John
  --dictionary=<file>  Custom dictionary for password checks
  --pass-length=<n>    Minimum password length (default: 8)

ACL Audit:
  --deny-log / --no-deny-log         Check deny-all+log rule
  --any-source / --no-any-source     Flag any-source rules
  --log-rules / --no-log-rules       Check rule logging
```

## Architecture

```
cmd/netpipe/          Entry point
internal/
  model/              Data structures for all device configs
  parser/             Parser registry + DeviceParser interface
  audit/              Security audit engine
  report/             Report generators (HTML, JSON, XML, text, LaTeX, CSV)
  config/             CLI flag parsing
  util/               Crypto, password checking, IP utilities
devices/              One package per device type
  ios/                Cisco IOS (Router/Switch/Catalyst)
  nxos/               Cisco NX-OS
  iosxe/              Cisco IOS-XE
  iosxr/              Cisco IOS-XR
  pixasa/             Cisco PIX/ASA/FWSM
  screenos/           Juniper ScreenOS
  junos/              Juniper Junos
  panos/              Palo Alto PAN-OS
  fortios/            Fortinet FortiOS
  eos/                Arista EOS
  bigip/              F5 BIG-IP
  fw1/                CheckPoint Firewall-1
  css/                Cisco CSS
  nmp/                Cisco NMP/CatOS
  passport/           Nortel Passport
  sonicos/            SonicWall SonicOS
```

## Adding a New Device Type

1. Create `devices/mydevice/parser.go`
2. Implement the `DeviceParser` interface
3. Register via `init()`: `parser.Register("mydevice", &MyParser{})`
4. Import the package in `pkg/netpipe.go`

## License

MIT — based on nipper-ng (GPL v3) by Ian Ventura-Whiting.
