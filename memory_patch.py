import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"

HOOK_JS = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var wininetMod = Process.findModuleByName('WININET.dll');

// Hook InternetReadFile - patch firmware bytes IN MEMORY after download
// The data comes STRAIGHT from Aliyun (no proxy). We modify it before minizip sees it.
var irf = Module.findExportByName('WININET.dll', 'InternetReadFile');
var patchApplied = false;
var totalRead = 0;

if (irf) Interceptor.attach(irf, {
    onEnter: function(a) {
        this.buf = a[1];
        this.size = a[2];
    },
    onLeave: function(retval) {
        if (retval.toInt32() <= 0) return;
        var bytesRead = retval.toInt32();
        totalRead += bytesRead;

        // Search for UAP file headers in the ZIP stream
        // UAP_DIAGMS.BIN header bytes: 92 95 97 96 99 98 67 6E (XOR obfuscation)
        // Actually the ZIP stores filenames in plaintext. Look for "UAP_DIAGMS.BIN" or "UAP_MENU.BIN"
        // But in compressed data, the filename appears once in the local header.
        // We need to find the COMPRESSED data for UAP files and patch it BEFORE inflation.

        // The approach: detect the ZIP entry for UAP files and patch the inflated data
        // after minizip extracts it. Minizip uses zlib inflate, not a separate hook.

        // SIMPLER APPROACH: The updater reads the full ZIP into memory first,
        // then calls unzOpen with memory buffer. We can scan the buffer for UAP filenames
        // and patch the FILEDATA portion. But we need to also fix CRC-32.

        // EVEN SIMPLER: Wait for WriteFile calls to E: and patch there.
        // We already proved this works with patch_on_write.py (196 patches)!

        console.log('READ:' + bytesRead + ' total=' + totalRead);
    }
});

// WriteFile hook - patch UAP data when written to E:
var wf = k32.findExportByName('WriteFile');
var cfw = k32.findExportByName('CreateFileW');
var currentFile = '';
var patchCount = 0;

Interceptor.attach(cfw, {
    onEnter: function(a) {
        var p = a[0].readUtf16String();
        if (p && p.indexOf('E:') >= 0 && p.indexOf('UAP') >= 0) {
            currentFile = p;
            console.log('FILE:' + p.split('\\').pop());
        }
    }
});

Interceptor.attach(wf, {
    onEnter: function(a) {
        this.h = a[0]; this.buf = a[1]; this.sz = a[2].toInt32();
    },
    onLeave: function(r) {
        if (this.sz >= 1000 && currentFile.indexOf('UAP_DIAGMS') >= 0) {
            try {
                this.buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]);
                patchCount++;
                if (patchCount <= 10) console.log('PATCH_DIAGMS:' + patchCount);
            } catch(e) {}
        }
        if (this.sz >= 1000 && currentFile.indexOf('UAP_MENU') >= 0) {
            try {
                this.buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]);
                console.log('PATCH_MENU');
            } catch(e) {}
        }
    }
});

// Also monitor the big 16KB blocks (firmware flash writes)
var bc = 0;
Interceptor.attach(wf, {
    onEnter: function(a) { this.sz = a[2].toInt32(); },
    onLeave: function(r) {
        if (this.sz >= 16384) {
            bc++;
            if (bc <= 5 || bc % 100 === 0) console.log('FLASH_BLOCK:' + bc);
        }
    }
});

console.log('MEMORY_PATCH_READY');
"""

def main():
    print("CR Pro Memory Patch (no proxy!)")
    os.system("taskkill /f /im iCarsoft_MSDIAG_PCClientKits.exe >nul 2>&1")
    time.sleep(1)

    # DON'T delete cache this time - let updater use whatever it has
    # DON'T start any local server - download comes from Aliyun directly

    pid = frida.spawn(UPDATER)
    session = frida.attach(pid)
    script = session.create_script(HOOK_JS)

    def on_msg(message, data):
        if message['type'] == 'send': print(f"  {message['payload']}")
        elif message['type'] == 'error': print(f"  ERR: {message.get('description', message)}")

    script.on('message', on_msg)
    script.load()
    frida.resume(pid)

    print("\n>>> V20CRPRO_SYSTEM herunterladen! <<<")
    print("(Download direkt von Aliyun, KEIN Proxy)")
    print("Frida patcht UAP-Daten im Speicher!\n")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("Beendet.")

if __name__ == "__main__":
    main()
