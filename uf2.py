"""Ultra Flasher V2 - fixes FuncCfg scanning for BMW-style records"""
import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"

HOOK = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var cfw = k32.findExportByName('CreateFileW');
var wf = k32.findExportByName('WriteFile');
var handles = {};
var stats = {funcCfg:0, funcCfgBMW:0, flash:0, devinfo:0, uap:0};
var currentBn = '';

Interceptor.attach(cfw, {
    onEnter: function(a) {
        var p = a[0].readUtf16String();
        if (p && p.indexOf('E:') >= 0) this.path = p;
    },
    onLeave: function(r) {
        if (this.path) {
            handles[r.toInt32()] = this.path;
            var bn = this.path.split('\\').pop();
            if (bn && (bn.indexOf('FuncCfg') >= 0 || bn.indexOf('.bin') >= 0 && bn.indexOf('UAP') >= 0 || bn.indexOf('devinfo') >= 0)) {
                currentBn = bn;
                console.log('FILE:' + bn);
            }
        }
    }
});

Interceptor.attach(wf, {
    onEnter: function(a) {
        this.h = a[0].toInt32(); this.sz = a[2].toInt32(); this.buf = a[1];
        this.path = handles[this.h] || '';
    },
    onLeave: function(r) {
        var sz = this.sz, buf = this.buf, path = this.path, bn = currentBn;
        if (sz < 8) return;

        try {
            // ===== PATCH: FuncCfg.bin - Add coding entries =====
            if (bn && bn.indexOf('FuncCfg') >= 0) {
                var maxCheck = Math.min(sz, 12288); // first 12KB
                var bytes = buf.readByteArray(maxCheck);
                var arr = new Uint8Array(bytes);

                // Simple pattern scan: find ".Zhi" or ".Phi" and change to ".Chi"
                // Pattern: [any][Z/P][h][i] where h=0x68, i=0x69
                for (var i = 0; i < arr.length - 4; i++) {
                    if (arr[i+2] === 0x68 && arr[i+3] === 0x69) { // "hi" tail
                        var cat = arr[i+1];
                        if (cat === 0x5A || cat === 0x50) { // Z or P
                            buf.add(i+1).writeByteArray([0x43]); // -> C
                            stats.funcCfgBMW++;
                            if (stats.funcCfgBMW <= 8) console.log('BMW:'+stats.funcCfgBMW+':Z/P->C@'+i);
                            i += 3; // skip rest of this slot
                        }
                    }
                    // BENZ pattern: XOR 0x2F encoded "CU" = 0x6C 0x7A
                    if (arr[i] === 0x6C && arr[i+1] === 0x7A) {
                        // Found CU marker. Check byte before for function type
                        var prefix = (i > 0) ? arr[i-1] : 0;
                        if (prefix !== 0x00) { // not empty
                            buf.add(i-1).writeByteArray([0x09]); // & (XOR 0x2F)
                            stats.funcCfg++;
                            if (stats.funcCfg <= 8) console.log('BENZ:'+stats.funcCfg+':->&CU@'+(i-1));
                        }
                    }
                }
            }

            // ===== PATCH: Flash blocks (UAP headers) =====
            if (sz >= 16384) {
                var bytes = buf.readByteArray(Math.min(sz, 256));
                var arr = new Uint8Array(bytes);
                for (var i = 0; i < Math.min(arr.length - 8, 250); i++) {
                    if (arr[i] === 0x92 && arr[i+1] === 0x95 && arr[i+2] === 0x97 && arr[i+3] === 0x96) {
                        var poff = i + 32;
                        if (poff < sz) {
                            buf.add(poff).writeByteArray([0x4D,0x4F,0x44,0x21]);
                            stats.flash++;
                            if (stats.flash <= 3) console.log('FLASH:' + stats.flash + ' MOD! at ' + poff);
                        }
                        break;
                    }
                }
            }

            // ===== PATCH: devinfo.txt version =====
            if (bn && bn.indexOf('devinfo') >= 0) {
                var bytes = buf.readByteArray(Math.min(sz, 256));
                var arr = new Uint8Array(bytes);
                var txt = '';
                for (var i = 0; i < arr.length; i++)
                    if (arr[i] >= 32 && arr[i] < 127) txt += String.fromCharCode(arr[i]);
                var idx = txt.indexOf('V23.02');
                if (idx >= 0) {
                    buf.add(idx).writeByteArray([0x56,0x32,0x33,0x2E,0x30,0x34]);
                    stats.devinfo++;
                    console.log('DEVINFO: V23.02->V23.04');
                }
            }

            // ===== PATCH: UAP E: files =====
            if (bn && bn.indexOf('UAP') >= 0 && sz >= 64) {
                buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]);
                stats.uap++;
            }

        } catch(e) {}
    }
});

console.log('UF2_READY');
"""

def main():
    print("=" * 60)
    print("CR Pro ULTRA FLASHER V2")
    print("FuncCfg: BMW(.Zhi->.Chi) + BENZ(FCU->&CU)")
    print("=" * 60)

    os.system("taskkill /f /im iCarsoft_MSDIAG_PCClientKits.exe >nul 2>&1")
    time.sleep(1)

    dl_dir = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\DownLoadSoftList"
    if os.path.exists(dl_dir):
        for f in os.listdir(dl_dir):
            if f.endswith('.zip'):
                try: os.remove(os.path.join(dl_dir, f))
                except: pass

    pid = frida.spawn(UPDATER)
    session = frida.attach(pid)
    script = session.create_script(HOOK)

    def on_msg(message, data):
        if message['type'] == 'send': print(f"  {message['payload']}")
        elif message['type'] == 'error': print(f"  ERR: {message.get('description', message)}")

    script.on('message', on_msg)
    script.load()
    frida.resume(pid)

    print("\n>>> V20CRPRO_SYSTEM herunterladen! <<<\n")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nBeendet.")

if __name__ == "__main__":
    main()
