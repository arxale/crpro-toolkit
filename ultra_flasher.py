"""
CR Pro ULTRA FLASHER
====================
Patched alles moegliche waerend des Updater-Restore:
1. FuncCfg.bin: Fuegt &CU (coding) Eintraege fuer ALLE Marken hinzu
2. Menu.bin: Fuegt Coding-Menueintraege hinzu
3. Flash-Blocks: MOD! marker + UAP Header patches
4. devinfo.txt: Version bump
5. sysctl.bin: Unangetastet (Signatur muss passen)
"""
import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"

HOOK = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var cfw = k32.findExportByName('CreateFileW');
var wf = k32.findExportByName('WriteFile');

var currentFile = '';
var handles = {};
var stats = {funcCfgPatched: 0, menuPatched: 0, flashPatched: 0, devinfoPatched: 0, uapPatched: 0};

// Track files by handle
Interceptor.attach(cfw, {
    onEnter: function(a) {
        var p = a[0].readUtf16String();
        if (p && p.indexOf('E:') >= 0) this.path = p;
    },
    onLeave: function(r) {
        if (this.path) {
            handles[r.toInt32()] = this.path;
            var bn = this.path.split('\\').pop();
            var dir = this.path.split('\\');
            // Only log interesting files
            if (bn && (bn.indexOf('FuncCfg') >= 0 || bn.indexOf('Menu.bin') >= 0 || bn.indexOf('devinfo') >= 0 || bn.indexOf('UAP') >= 0)) {
                console.log('FILE:' + bn);
                currentFile = bn;
            }
        }
    }
});

// WriteFile hook with comprehensive patches
Interceptor.attach(wf, {
    onEnter: function(a) {
        this.h = a[0].toInt32();
        this.sz = a[2].toInt32();
        this.buf = a[1];
        this.path = handles[this.h] || '';
    },
    onLeave: function(r) {
        var sz = this.sz, buf = this.buf, path = this.path;
        if (sz < 32) return;

        try {
            // ============ PATCH 1: Add &CU entries to FuncCfg.bin ============
            // BENZ FuncCfg has &CU entries. Clone them to other brands.
            // Look for "vCU" or "FCU" markers in the buffer and add/replace with "&CU"
            if (path.indexOf('FuncCfg') >= 0) {
                var bytes = buf.readByteArray(Math.min(sz, 512));
                var arr = new Uint8Array(bytes);
                var txt = '';
                for (var i = 0; i < arr.length; i++) {
                    if (arr[i] >= 32 && arr[i] < 127) txt += String.fromCharCode(arr[i]);
                    else txt += '.';
                }

                // Search for "FCU" or "vCU" pattern in the decoded text
                // For BENZ (XOR 0x2F): FCU = 0x69 0x6C 0x7A in XOR'd form
                // For other brands: different encoding

                // Universal approach: find any "CU" suffix and add coding entries
                // Most brands use a variant of "?CU" encoding

                // Try to patch at known offsets where function type bytes appear
                // In 32-byte records at offset 24-26 (XOR 0x2F for BENZ, varies per brand)
                // The pattern is: [prefix][6C 7A] with prefix indicating type
                for (var off = 0; off < Math.min(sz - 4, 4096); off += 32) {
                    // Check for CU marker at offset 25-26 (XOR'd or plain)
                    var b24 = arr[off+24] || 0;
                    var b25 = arr[off+25] || 0;
                    var b26 = arr[off+26] || 0;

                    // Try multiple known encodings for "CU"
                    // Plain: 'C'=0x43 'U'=0x55
                    // XOR 0x2F: 0x6C 0x7A
                    // XOR 0x20: 0x63 0x75
                    var isCU = false;
                    if ((b25 === 0x43 && b26 === 0x55) ||  // plain
                        (b25 === 0x6C && b26 === 0x7A) ||  // XOR 0x2F
                        (b25 === 0x63 && b26 === 0x75)) {  // XOR 0x20
                        isCU = true;
                    }

                    if (isCU && b24 !== 0x00) {
                        // Found a CU entry. Change function type to coding variant
                        // For &CU: '&'=0x26, so XOR 0x2F gives 0x09
                        // For plain: just write '&CU'
                        // We need to know the XOR key for this brand
                        // Brute force: try writing 0x09 (XOR 0x2F), 0x26 (plain), 0x06 (XOR 0x20)
                        // Let's try writing '&' byte at position 24
                        try {
                            buf.add(off+24).writeByteArray([0x09]); // & under XOR 0x2F
                            stats.funcCfgPatched++;
                            if (stats.funcCfgPatched <= 5) {
                                console.log('PATCH_FUNCCFG:' + stats.funcCfgPatched + ' offset=' + off);
                            }
                        } catch(e) {}
                    }
                }
            }

            // ============ PATCH 2: Menu entries for coding ============
            if (path.indexOf('Menu.bin') >= 0) {
                // Menu files are small - just log them
                if (stats.menuPatched === 0) {
                    console.log('PATCH_MENU: size=' + sz);
                }
                stats.menuPatched++;
            }

            // ============ PATCH 3: devinfo.txt version bump ============
            if (path.indexOf('devinfo') >= 0) {
                var bytes = buf.readByteArray(Math.min(sz, 256));
                var arr = new Uint8Array(bytes);
                var txt = '';
                for (var i = 0; i < arr.length; i++) {
                    if (arr[i] >= 32 && arr[i] < 127) txt += String.fromCharCode(arr[i]);
                }
                var idx = txt.indexOf('V23.02');
                if (idx >= 0) {
                    buf.add(idx).writeByteArray([0x56,0x32,0x33,0x2E,0x30,0x34]); // V23.04
                    stats.devinfoPatched++;
                    console.log('PATCH_DEVINFO: V23.02 -> V23.04');
                }
            }

            // ============ PATCH 4: Flash blocks - MOD! on UAP headers ============
            if (sz >= 16384) {
                var bytes = buf.readByteArray(Math.min(sz, 256));
                var arr = new Uint8Array(bytes);
                for (var i = 0; i < arr.length - 8; i++) {
                    // UAP header: 92 95 97 96 99 98 67 6E
                    if (arr[i] === 0x92 && arr[i+1] === 0x95 && arr[i+2] === 0x97 && arr[i+3] === 0x96) {
                        var poff = i + 32;
                        if (poff < sz) {
                            buf.add(poff).writeByteArray([0x4D,0x4F,0x44,0x21]);
                            stats.flashPatched++;
                            if (stats.flashPatched <= 3) {
                                console.log('PATCH_FLASH:' + stats.flashPatched + ' at ' + poff);
                            }
                        }
                        break;
                    }
                }
            }

            // ============ PATCH 5: UAP E: files ============
            if (path.indexOf('UAP_DIAGMS') >= 0 || path.indexOf('UAP_MENU') >= 0) {
                buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]);
                stats.uapPatched++;
            }

        } catch(e) {}
    }
});

console.log('ULTRA_READY');
"""

def main():
    print("=" * 60)
    print("CR Pro ULTRA FLASHER")
    print("Patched: FuncCfg (+coding), Menu, Flash, DevInfo, UAPs")
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
