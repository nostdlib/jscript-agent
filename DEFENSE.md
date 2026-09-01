# DEFENSE.md — Detection & Analysis Guide

Defender-oriented companion to [`src/jscript-agent.js`](src/jscript-agent.js). Everything below is
derived from the source at commit `ca38264`; line references point into that file. The goal is
that a responder who has only network captures, or only host telemetry, or only a suspicious file
on disk can each get to a confident verdict from their own vantage point.

## 1. Behavior summary

The agent is a single ES3 JScript function (`runAgent`, [src/jscript-agent.js:1](src/jscript-agent.js#L1))
intended to run inside `mshta.exe` in deployment (a "master" wrapper sets `H_URL` and calls it) or
`cscript.exe` for verification. In steady state it:

1. Reads the beacon endpoint from the `H_URL` environment variable ([:137](src/jscript-agent.js#L137)).
2. Builds an identity header set once — hostname, username, OS version/build, CPU arch, and a UUID
   taken from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` ([:46-81](src/jscript-agent.js#L46-L81)).
3. Long-poll POSTs the relay in a loop via `MSXML2.ServerXMLHTTP` ([:142-167](src/jscript-agent.js#L142-L167)).
4. Dispatches one of three command opcodes: `0x0A` Exit, `0x0B` Upgrade — in-process payload
   execution via `BinaryFormatter` insecure deserialization ([:90-134](src/jscript-agent.js#L90-L134)) —
   and anything else returns u32 `2`.

The agent itself writes nothing to disk and creates no processes — persistence and window
management live in the host master, not this file.

## 2. Network-side indicators

These apply to plaintext HTTP or traffic visible at a TLS-terminating proxy.

**Identity headers.** Every request carries the full `X-Agent-*` set, always in this order, with
several constant values ([:67-81](src/jscript-agent.js#L67-L81)):

| Header | Value |
|---|---|
| `X-Agent-Api-Version` | always `1` |
| `X-Agent-Uuid` | target's `MachineGuid` (one per machine) |
| `X-Agent-Hostname` / `X-Agent-Username` | from the environment — leaks host + user identity on every request |
| `X-Agent-Platform` | always `Windows` |
| `X-Agent-Name-Id` | always `1` |
| `X-Agent-Capabilities` | always `0800000000000000` |
| `X-Agent-Arch`, `X-Agent-Process-Arch`, `X-Agent-Os-Version`, `X-Agent-Build`, `X-Agent-Commit`, `X-Agent-Bitness` | per-host, empty `X-Agent-Commit` |

This header set is the single highest-confidence signature — ordinary software does not send
`X-Agent-*` headers, and the constants pin it tightly.

**Body shape.** Both directions are optional-whitespace-stripped, lowercase, even-length hex
([bytesToHex :15-19](src/jscript-agent.js#L15-L19), [:162](src/jscript-agent.js#L162)); bodies match
`^([0-9a-f]{2})*$`. Request bodies are almost always empty or exactly 8 hex chars (a u32 reply);
Upgrade command *responses* are large (the base64 payload hex-doubles, so response ≫ request is
the asymmetric fingerprint of a payload push).

**Cadence.** The relay holds each request 20–30 s; the agent re-POSTs immediately on an empty
answer and its receive timeout is 45 s ([:148](src/jscript-agent.js#L148), [:163](src/jscript-agent.js#L163)).
Idle steady state ≈ 120–180 POSTs/hour to a single URL, each connection occupied ~20–30 s —
near-continuous single-destination occupancy from one process.

**Proxy bypass.** `xhr.setProxy(1, '', '')` ([:147](src/jscript-agent.js#L147)) forces a *direct*
connection (MSXML option 1), deliberately ignoring any configured proxy. On forced-proxy networks
this shows up as direct egress attempts from `mshta.exe`.

**No second-stage fetch.** The Upgrade payload rides the same in-band beacon POST (the README's
"no payload download"). There is no follow-on URL to catch — host-side detection and the relay
endpoint are the only choke points.

Suricata (adjust sid/rev to local policy):

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"jscript-agent C2 beacon identity header set"; flow:established,to_server; http.method; content:"POST"; http.header; content:"X-Agent-Api-Version|3a 20|1"; fast_pattern; content:"X-Agent-Capabilities|3a 20|0800000000000000"; classtype:trojan-activity; sid:2206001; rev:1;)
```

If the relay runs on a Workers domain, egress destination inventory (`*.<workers-host>` / the
specific relay hostname) is a useful pivot, though not conclusive on its own.

## 3. Host-side indicators

**Process tree (Sysmon EID 1 / process telemetry).**
- `mshta.exe` (64-bit) spawning `%WINDIR%\SysWOW64\mshta.exe` — the master's x86 re-host step
  (README "Host contract"). mshta→mshta across the WOW64 boundary is not legitimate application
  behavior.
- `cscript.exe`/`wscript.exe`/`mshta.exe` with a `.js`/`.hta` path argument is worth review on
  user workstations; the agent's verification path is cscript, so don't exclude it.
- Script hosts spawning network-capable helpers (`powershell.exe`, `curl.exe`,
  `certutil.exe -urlcache`, `bitsadmin.exe`) — see §6: this is the classic escalation when a
  pure-JScript tool outgrows its HTTP-only ceiling.

**Module loads (Sysmon EID 7).** `mshta.exe` / `cscript.exe` loading `clr.dll` / `mscorwks.dll` /
`mscorlib.ni.dll` — the CLR is hosted via COM the moment any `System.*` object is created
([:36-45](src/jscript-agent.js#L36-L45)), and the Upgrade arm depends on it. A script host with a
hosted CLR is a strong anomaly unless the box legitimately runs script-driven .NET tooling.

**AMSI content (Win10+).** The JScript engine inside mshta/cscript feeds script source to AMSI.
Unobfuscated copies of this file match on any of: `X-Agent-Capabilities`,
`System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`, `COMPLUS_Version`, `H_URL`,
`WbemScripting.SWbemLocator` + `MSXML2.ServerXMLHTTP` together. (Per SECURITY.md scope, evasion
quality is the consuming C2's concern — treat obfuscated variants as expected.)

**Registry (EID 10 if configured for reads).** Read of
`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` by a script host ([:48](src/jscript-agent.js#L48)).

**WMI.** `SELECT Version, BuildNumber FROM Win32_OperatingSystem` and
`SELECT Architecture FROM Win32_Processor` issued from mshta/cscript ([:57-61](src/jscript-agent.js#L57-L61)) —
host inventory from a script host is itself a signal, independent of the C2.

**Process environment (forensics).** The live process env block should contain `H_URL`
([:137](src/jscript-agent.js#L137)) and, after an Upgrade, `COMPLUS_Version` = `v2.0.50727`
(Win7 / build 7600–7601) or `v4.0.30319` ([:64-66](src/jscript-agent.js#L64-L66), [:106](src/jscript-agent.js#L106)).
These are per-process and invisible to default telemetry — grab them from a memory dump or
`Get-Process ... | % { $_.StartInfo.EnvironmentVariables }`-style collection before the process dies.

**File on disk (YARA).** The agent/master is text, so static matching is trivial:

```
rule JScript_Agent_Beacon
{
    strings:
        $http = "MSXML2.ServerXMLHTTP" ascii
        $hdr  = "X-Agent-Capabilities" ascii
        $fmt  = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter" ascii
        $env  = "COMPLUS_Version" ascii
        $url  = "H_URL" ascii
    condition:
        all of them
}
```

## 4. MITRE ATT&CK mapping

| Technique | Where |
|---|---|
| T1059.007 JavaScript / JScript | The whole implant; runs under mshta (deploy) / cscript (verify) |
| T1218.005 mshta | Host master runs a polyglot under mshta incl. the SysWOW64 x86 re-host |
| T1071.001 Web Protocols | HTTP(S) long-poll beacon via ServerXMLHTTP (WinHTTP-backed) |
| T1132.001 Data Encoding: Hex | Both command and reply bodies are hex strings |
| T1012 Query Registry | `MachineGuid` read for `X-Agent-Uuid` |
| T1082 System Information Discovery | WMI OS-version and CPU-arch queries |
| T1041 Exfiltration Over C2 Channel | Command replies returned in beacon POST bodies |
| T1620 Reflective Code Loading (nearest fit) | Upgrade arm: in-memory `BinaryFormatter` gadget execution, no file written |
| T1547.x Autostart Execution | On-logon re-delivery — implemented by the master, not this file |

## 5. Forensic triage checklist (suspected host)

1. Running `mshta.exe`/`cscript.exe` with an active single-destination HTTPS session → capture its
   command line, parent chain, and network connections for that PID.
2. Dump the process environment: `H_URL` names the relay; `COMPLUS_Version` proves an Upgrade ran.
3. Pull Sysmon/EDR history for that PID: CLR module loads, `MachineGuid` read, WMI queries.
4. Search proxy/TLS-inspection logs for `X-Agent-*` headers — `X-Agent-Uuid` is the `MachineGuid`,
   so one query inventories every beaconing host in the environment and ties captures to hosts.
5. Hunt the master file (YARA above) and the master's persistence (Run keys, scheduled tasks,
   Startup folder) — persistence is the master's job, so agent presence implies master artifacts.

## 6. Why the beacon is HTTP-only — the JScript network ceiling (educational)

Useful mental model for defenders assessing what a pure-JScript implant *cannot* do, and what its
next escalation step must look like:

- **The language has no I/O at all.** JScript 5.8 (ES3) inside WSH/mshta exposes no networking,
  filesystem, or process primitives in the language itself — every capability is COM automation
  through `ActiveXObject`. Even `JSON` is absent, which is why this protocol speaks hex.
- **No `XMLHttpRequest`.** That is a browser/DOM host object; WSH does not provide it. The stock
  HTTP channels are the MSXML family (`MSXML2.ServerXMLHTTP`, used here) and
  `WinHttp.WinHttpRequest.5.1` — both backed by WinHTTP, which has its own proxy settings
  (not IE's), which is why the agent explicitly pins direct egress.
- **No raw TCP/UDP.** There is no intrinsic socket API, and the only scriptable in-box socket
  wrapper — the VB6-era Winsock control (`MSWinsock.Winsock`, `mswinsck.ocx`) — is 32-bit-only,
  deprecated, and not shipped or registered on modern Windows. Practically unavailable.
- **No sockets via the CLR either.** The `System.*` objects this agent uses work because a subset
  of mscorlib classes happens to be COM-visible; `System.Net.Sockets.*` is not, so .NET-via-COM
  grants file, crypto, and serialization — not sockets. (It does grant the deserialization
  execution path this agent's Upgrade arm uses.)
- **Consequence:** a pure-JScript implant's realistic C2 surface on a stock box is HTTP(S) via the
  MSXML/WinHTTP objects — exactly what this repo is — or dropping to a helper process
  (PowerShell, curl, certutil…), which trades away stealth for visible process-creation telemetry.

**Escalation watch-list** — each item is "the implant outgrew JScript" and worth an alert on its
own: `WinHttp.WinHttpRequest` activation from script hosts; any appearance/registration of
`mswinsck.ocx`; script hosts spawning network-capable helpers; CLR load inside a script host.

## 7. Fingerprint checklist — verify in *your* environment

Two details are implementation-dependent rather than fixed by the source; capture a live beacon
before relying on them: the exact `User-Agent` (the agent sets none itself, so expect the stock
or absent WinHTTP UA) and whether MSXML adds a `Content-Type` on string `send()` bodies (the
agent never sets one). Both are stable per-OS, so one capture pins them for rule-writing.
