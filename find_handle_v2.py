"""Find MCU flash handle - add handle tracking"""
import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"
os.system("taskkill /f /im iCarsoft_MSDIAG_PCClientKits.exe >nul 2>&1")
time.sleep(1)

pid = frida.spawn(UPDATER)
s = frida.attach(pid)

HOOK = """
var k32 = Process.findModuleByName('kernel32.dll');
var wf = k32.findExportByName('WriteFile');
var cfw = k32.findExportByName('CreateFileW');
var handlePaths = {};
var handleCounts = {};
var totalBlocks = 0;

// Track file paths for handles
Interceptor.attach(cfw, {
    onEnter: function(a) {
        this.path = a[0].readUtf16String();
    },
    onLeave: function(r) {
        var h = r.toInt32();
        if (h > 0 && this.path) {
            handlePaths[h] = this.path;
        }
    }
});

// Log all writes with handle info
Interceptor.attach(wf, {
    onEnter: function(a) {
        this.h = a[0].toInt32();
        this.sz = a[2].toInt32();
        this.buf = a[1];
    },
    onLeave: function(r) {
        var h = this.h, sz = this.sz;
        handleCounts[h] = (handleCounts[h] || 0) + 1;

        if (sz >= 1000) {
            totalBlocks++;
            var path = handlePaths[h] || 'UNKNOWN';
            // Read first bytes for identification
            var head = '';
            try {
                var bytes = this.buf.readByteArray(Math.min(sz, 8));
                var arr = new Uint8Array(bytes);
                for (var i = 0; i < Math.min(arr.length, 8); i++)
                    head += ('0' + arr[i].toString(16)).slice(-2);
            } catch(e) { head = 'ERR'; }

            // Is this an ARM vector table? (SP in SRAM range 0x2000xxxx)
            var isVec = (sz === 16384 || sz > 100000) &&
                        head.length >= 8 &&
                        head.substring(4,8) === '0020';  // SP high bytes = 0x2000

            var marker = '';
            if (sz >= 1000000) marker = ' [ZIP]';
            else if (sz === 16384) marker = ' [16K]';
            else if (sz === 4096) marker = ' [SYSCTL?]';

            if (totalBlocks <= 30 || marker !== ' [16K]' || totalBlocks % 50 === 0) {
                console.log('W:' + totalBlocks + ' h=0x' + h.toString(16) + ' sz=' + sz + marker + ' ' + head + ' ' + path.substring(0,60));
            }
        }
    }
});

console.log('FH2_OK');
"""

sc = s.create_script(HOOK)
sc.on('message', lambda m, d: print(m.get('payload', '')) if m['type'] == 'send' else None)
sc.load()
frida.resume(pid)

dl_dir = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\DownLoadSoftList"
if os.path.exists(dl_dir):
    for f in os.listdir(dl_dir):
        if f.endswith('.zip'):
            try: os.remove(os.path.join(dl_dir, f))
            except: pass

print("\n>>> V20CRPRO_SYSTEM herunterladen! <<<\n")
try:
    while True: time.sleep(1)
except KeyboardInterrupt:
    print("\nBeendet.")
