import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"

HOOK_JS = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var currentFile = '';
var patchCount = 0;
var flashBlocks = 0;

var cfw = k32.findExportByName('CreateFileW');
Interceptor.attach(cfw, {
    onEnter: function(a) {
        var p = a[0].readUtf16String();
        if (p && p.indexOf('E:') >= 0 && p.indexOf('UAP') >= 0) {
            currentFile = p;
            console.log('FILE:' + p.split('\\').pop());
        }
    }
});

var wf = k32.findExportByName('WriteFile');
Interceptor.attach(wf, {
    onEnter: function(a) {
        this.sz = a[2].toInt32();
        this.buf = a[1];
    },
    onLeave: function(r) {
        // Patch E: file writes
        if (this.sz >= 1000 && currentFile.indexOf('UAP_DIAGMS') >= 0) {
            try { this.buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]); patchCount++;
                if (patchCount <= 3) console.log('PATCH_E_DIAGMS:' + patchCount); } catch(e) {}
        }
        if (this.sz >= 1000 && currentFile.indexOf('UAP_MENU') >= 0) {
            try { this.buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]);
                console.log('PATCH_E_MENU'); } catch(e) {}
        }

        // Scan 16KB flash blocks for UAP headers and patch them too
        if (this.sz >= 16384) {
            flashBlocks++;
            try {
                // Read first 64 bytes of the block to scan for UAP header
                var bytes = this.buf.readByteArray(Math.min(this.sz, 128));
                var arr = new Uint8Array(bytes);
                // UAP header signature: 92 95 97 96 99 98 67 6E (first 8 bytes of UAP_DIAGMS/MENU etc)
                // Search for this pattern in first 64 bytes
                for (var i = 0; i < arr.length - 16; i++) {
                    // Check for UAP signature (92 95 97 96 99 98 67 6E at relative offset in block)
                    if (arr[i] === 0x92 && arr[i+1] === 0x95 && arr[i+2] === 0x97 && arr[i+3] === 0x96 &&
                        arr[i+4] === 0x99 && arr[i+5] === 0x98 && arr[i+6] === 0x67 && arr[i+7] === 0x6E) {
                        // UAP header found at offset i in this block!
                        // Patch MOD! at byte 32 relative to UAP start
                        var patchOff = i + 32;
                        if (patchOff < this.sz) {
                            this.buf.add(patchOff).writeByteArray([0x4D,0x4F,0x44,0x21]);
                            console.log('PATCH_FLASH_UAP:' + flashBlocks + ':' + patchOff);
                        }
                        break;
                    }
                    // Also check for family B header (MENU/OBDSYS): different prefix
                    if (arr[i] === 0x00 && arr[i+1] === 0xCF && arr[i+2] === 0x0C && arr[i+3] === 0x00) {
                        // This might be UAP_MENU or UAP_OBDSYS header
                        var patchOff2 = i + 32;
                        if (patchOff2 < this.sz) {
                            this.buf.add(patchOff2).writeByteArray([0x4D,0x4F,0x44,0x21]);
                            console.log('PATCH_FLASH_UAP2:' + flashBlocks + ':' + patchOff2);
                        }
                        break;
                    }
                }
            } catch(e) {}
            if (flashBlocks <= 3 || flashBlocks % 100 === 0) console.log('FLASH:' + flashBlocks);
        }
    }
});

console.log('MP3_READY');
"""

def main():
    print("CR Pro Memory Patch v3 (FLASH blocks too!)")
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
    script = session.create_script(HOOK_JS)

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
        print("Beendet.")

if __name__ == "__main__":
    main()
