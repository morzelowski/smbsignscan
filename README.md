# smbsignscan (stealthy SMB signing sniffer)

▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
▐░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▌
▐░█▀▀░█▄█░█▀▄░█▀▀░▀█▀░█▀▀░█▀█░█▀▀░█▀▀░█▀█░█▀█░▌
▐░▀▀█░█░█░█▀▄░▀▀█░░█░░█░█░█░█░▀▀█░█░░░█▀█░█░█░▌
▐░▀▀▀░▀░▀░▀▀░░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀░▀░▌
▐░By░M0U░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▌
▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌

Tiny Python tool that politely pokes SMB and asks, “Do you require signing?”
It’s shy: one packet by default, two if you get fancy. Your SIEM may not even notice it showed up with flowers.

## Why
- Stealth: single SMB2 NEGOTIATE request, no auth, minimal bytes.
- No deps: pure Python, one file, works on stock Kali/Ubuntu/Windows Python.
- Flexible input: single host, comma list, CIDR, or file.
- DNS override: point lookups at your DC without touching system resolvers.
- SMBv1 aware: distinguishes SMBv1 vs SMBv2/3 and reads their signing flags.

## Quick Start
- Python 3.8+
- Run from repo root:

```
python3 smbsign_check.py 192.168.1.10
```

Example multi-target runs:
```
# Comma list
python3 smbsign_check.py 10.0.0.5,10.0.0.6

# CIDR
python3 smbsign_check.py 10.0.0.0/24 --show-service

# Hosts file (lines can be host/IP, commas, or CIDRs)
python3 smbsign_check.py -f hosts.txt --dns 10.0.0.10
```

Make it a ninja:
```
# Sleep between targets for reduced burstiness
python3 smbsign_check.py 10.0.0.0/24 --sleep 30

# Ask the server to sign (second probe) and show service type
python3 smbsign_check.py 10.0.0.5 --probe-policy --show-service

# Force legacy SMBv1 signing probe (skip SMB2/3)
python3 smbsign_check.py 10.0.0.5 --force-smb1
```

## What It Says
- SMB signing: REQUIRED — server enforces signing
- SMB signing: SUPPORTED but NOT required — will sign if asked, not enforced
- SMB signing: DISABLED — no signing support advertised
- DISABLED/REFUSED — server rejected a client that requested signing at negotiate (rare on SMB2+ Windows)

Service banner (when `--show-service`):
- SMBv2/3 detected on TCP/445
- SMBv1 detected on TCP/445
- TCP/445 open but not SMB (non-SMB service)
- SMB unreachable (closed/filtered)

## Options
```
usage: smbsign_check.py [targets] [options]

positional targets:
  host(s)              single host/IP, comma list, or CIDR
                       e.g., 10.0.0.5,10.0.0.6 or 10.0.0.0/24

input:
  -f, --file FILE      hosts file (one per line; supports commas and CIDR)
  --max-hosts N        safety cap for expanded targets (default 65536)

network:
  -p, --port N         SMB port (default 445)
  --dns IP             use this DNS server (e.g., DC IP) to resolve names
  --dns-port N         DNS server port (default 53)

timing:
  -t, --timeout S      per-socket timeout (DNS + SMB)
  --sleep S            seconds to sleep between targets (multi-target)

reporting:
  --show-service       print SMB service presence/version hints
  --probe-policy       send a second NEGOTIATE with client-requires-signing and show result
  --force-smb1         force SMBv1 signing probe (skip SMBv2/3)
```

Notes on timeout
- Applies per operation: DNS query, TCP connect, and each SMB recv.
- Service check caps at min(timeout, 2s) to stay snappy. Tell us if you want full `-t` instead.

## Packets Per Target (Stealth Budget)
- Default: 1 request (SMB2 NEGOTIATE only).
- With `--probe-policy`: +1 request only if the server does NOT already require signing.
- With `--show-service`: +1 request for a minimal banner probe.
- SMB1-only hosts: SMB2 attempt fails → SMB1 fallback may add 1 request.
- With `--force-smb1`: 1 request (SMB1 NEGOTIATE only).

## A Touch of Truth (SMB quirks)
- Windows SMB2/3 typically advertises signing capability even if local policy “Enable/Require” is off.
  - You may see “SUPPORTED but NOT required” on many members/workgroup machines.
  - Domain Controllers usually return “REQUIRED”.
- Proving enforcement beyond negotiation generally requires an authenticated session and a signed request.
  This tool avoids auth to keep traffic tiny.

## How It Stays Stealthy
- SMB2/3: crafts a minimal NEGOTIATE (dialects up to 3.0.2) and parses `SecurityMode`.
- No 3.1.1 negotiate contexts, no session setup, no tree connect.
- Optional second probe only if you pass `--probe-policy`.
- DNS is a single UDP query when `--dns` is specified, otherwise your OS resolver.

## Example Output
```
Target: fileserver.corp.local -> 10.0.0.42
Service: SMBv2/3 detected on TCP/445
SMB signing: SUPPORTED but NOT required
Probe (client requires signing): accepted, status=0x00000000, server flags=ENABLED
```

## Legal/Respectful Use
Only scan networks and systems you own or are explicitly authorized to test.
The authors take no responsibility for misuse. Be a considerate network neighbor.

## FAQ
- Q: Why not just use Nmap/Impacket?
  A: Those are great, but noisy! This is a tiny, dependency‑free, one‑shot probe you can drop anywhere.

- Q: Can it verify that all traffic is actually signed?
  A: Not without authentication. That would require session keys and signed requests. Possible, but no longer “one packet”.

- Q: Why SMB1 support?
  A: Some networks still have legacy devices. SMB1 advertises signing flags differently; we detect and report those too.

## Credits
Built for red/blue teams that like answers with the fewest packets possible. Speaks fluent `\xfeSMB`.
