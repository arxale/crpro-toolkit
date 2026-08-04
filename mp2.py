import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"

HOOK_JS = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var currentFile = '';
var patchCount = 0;
var flashBlocks = 0;

// SINGLE hook for CreateFileW
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

// SINGLE hook for WriteFile - handles BOTH E: patches AND 16KB flash blocks
var wf = k32.findExportByName('WriteFile');
Interceptor.attach(wf, {
    onEnter: function(a) {
        this.sz = a[2].toInt32();
        this.buf = a[1];
    },
    onLeave: function(r) {
        // E: file patches
        if (this.sz >= 1000 && currentFile.indexOf('UAP_DIAGMS') >= 0) {
            try {
                this.buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]);
                patchCount++;
                if (patchCount <= 5) console.log('PATCH_DIAGMS:' + patchCount);
            } catch(e) {}
        }
        if (this.sz >= 1000 && currentFile.indexOf('UAP_MENU') >= 0) {
            try {
                this.buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]);
                console.log('PATCH_MENU');
            } catch(e) {}
        }
        // 16KB flash blocks
        if (this.sz >= 16384) {
            flashBlocks++;
            if (flashBlocks <= 5 || flashBlocks % 100 === 0) console.log('FLASH:' + flashBlocks + ':' + this.sz);
        }
    }
});

console.log('MP2_READY');
"""

def main():
    print("CR Pro Memory Patch v2")
    os.system("taskkill /f /im iCarsoft_MSDIAG_PCClientKits.exe >nul 2>&1")
    time.sleep(1)

    # Clear cache so updater re-downloads
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
