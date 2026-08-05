"""Find MCU flash writes - capture ALL WriteFile calls, no size filter"""
import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"

HOOK = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var wf = k32.findExportByName('WriteFile');
var ntwf = Module.findExportByName('ntdll.dll', 'NtWriteFile');
var totalWrites = 0;
var handles = {};
var handleCounts = {};

Interceptor.attach(wf, {
    onEnter: function(a) {
        this.h = a[0].toInt32();
        this.sz = a[2].toInt32();
        this.buf = a[1];
    },
    onLeave: function(r) {
        totalWrites++;
        var h = this.h, sz = this.sz;
        handleCounts[h] = (handleCounts[h] || 0) + 1;

        // Show ALL writes >= 64 bytes with handle info
        if (sz >= 64 && sz <= 1000000) {
            // Read first few bytes for identification
            try {
                var head = this.buf.readByteArray(Math.min(sz, 32));
                var arr = new Uint8Array(head);
                var hex = '';
                for (var i = 0; i < Math.min(arr.length, 16); i++)
                    hex += ('0' + arr[i].toString(16)).slice(-2);

                // Check if this could be a firmware block
                var isFirmware = false;
                // ARM vector table: SP in 0x2000xxxx range, then address in 0x08xxxxxx
                if (arr[0] === 0x00 && arr[1] === 0x00 && (arr[2] & 0xF0) === 0x00 && arr[3] === 0x20) {
                    isFirmware = true;
                }
                // UAP header
                if (arr[0] === 0x92 && arr[1] === 0x95 && arr[2] === 0x97 && arr[3] === 0x96) {
                    isFirmware = true;
                }
                // Another firmware marker: 0xFF filled with some code
                if (arr[0] === 0xFF && arr[1] === 0xFF && arr[2] === 0xFF && arr[3] === 0xFF &&
                    (arr[4] !== 0xFF || arr[5] !== 0xFF)) {
                    isFirmware = true;
                }

                var marker = isFirmware ? ' *** FIRMWARE ***' : '';
                if (totalWrites <= 50 || isFirmware || sz >= 16384) {
                    console.log('W:' + totalWrites + ' h=0x' + h.toString(16) + ' sz=' + sz + ' ' + hex + marker);
                }
            } catch(e) {}
        }
    }
});

console.log('FINDER_READY');
"""

def main():
    print("CR Pro MCU Write Finder - capturing ALL WriteFile calls")
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
