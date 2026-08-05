"""Capture flash block headers for Ghidra analysis - lightweight, no channel flood"""
import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_firmware.bin")

HOOK = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var wf = k32.findExportByName('WriteFile');
var blockNum = 0;
var outFile = null;

// Open output file using kernel32
var CreateFileW = new NativeFunction(k32.findExportByName('CreateFileW'), 'int',
    ['pointer', 'int', 'int', 'pointer', 'int', 'int', 'int']);
var WriteFile = new NativeFunction(k32.findExportByName('WriteFile'), 'int',
    ['int', 'pointer', 'int', 'pointer', 'pointer']);
var CloseHandle = new NativeFunction(k32.findExportByName('CloseHandle'), 'int', ['int']);

var outPath = Memory.allocUtf16String('__OUTPUT__');
var GENERIC_WRITE = 0x40000000;
var CREATE_ALWAYS = 2;
var FILE_ATTRIBUTE_NORMAL = 0x80;

outFile = CreateFileW(outPath, GENERIC_WRITE, 0, ptr(0), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
if (outFile === -1 || outFile === 0xFFFFFFFF) {
    console.log('FILE_CREATE_FAILED:' + outPath.readUtf16String());
} else {
    console.log('FILE_OPENED_0x' + outFile.toString(16));
}

// Capture full 16KB flash blocks
Interceptor.attach(wf, {
    onEnter: function(a) {
        this.sz = a[2].toInt32();
        this.buf = a[1];
    },
    onLeave: function(r) {
        if (this.sz >= 16384 && outFile > 0) {
            blockNum++;
            // Write block size + data directly to output file
            var sizeBuf = Memory.alloc(4);
            sizeBuf.writeU32(this.sz);
            var bytesWritten = Memory.alloc(4);
            WriteFile(outFile, sizeBuf, 4, bytesWritten, ptr(0));

            // Write the actual data
            WriteFile(outFile, this.buf, this.sz, bytesWritten, ptr(0));

            if (blockNum <= 5 || blockNum % 50 === 0) {
                console.log('SAVED:' + blockNum + ':' + this.sz);
            }
        }
    }
});

console.log('GHIDRA_CAPTURE_READY');
""".replace('__OUTPUT__', OUTPUT.replace('\\', '\\\\'))

def main():
    print("CR Pro Ghidra Firmware Capture")
    print(f"Output: {OUTPUT}")

    os.system("taskkill /f /im iCarsoft_MSDIAG_PCClientKits.exe >nul 2>&1")
    time.sleep(1)

    dl_dir = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\DownLoadSoftList"
    if os.path.exists(dl_dir):
        for f in os.listdir(dl_dir):
            if f.endswith('.zip'):
                try: os.remove(os.path.join(dl_dir, f))
                except: pass

    if os.path.exists(OUTPUT):
        os.remove(OUTPUT)

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
        if os.path.exists(OUTPUT):
            sz = os.path.getsize(OUTPUT)
            print(f"\nCaptured: {OUTPUT} ({sz:,} bytes)")
            if sz > 0:
                # Read first few blocks for quick analysis
                with open(OUTPUT, 'rb') as f:
                    data = f.read()
                # Parse: [4-byte size][data] repeated
                off = 0
                blocks = 0
                while off + 4 <= len(data):
                    blk_sz = int.from_bytes(data[off:off+4], 'little')
                    off += 4
                    if off + blk_sz <= len(data):
                        blocks += 1
                        off += blk_sz
                print(f"  Blocks: {blocks}")
                # Show first block header
                off = 4
                if off + 64 <= len(data):
                    blk_sz = int.from_bytes(data[0:4], 'little')
                    print(f"  Block 0 size: {blk_sz}")
                    print(f"  First 64 bytes: {data[off:off+64].hex()}")
        else:
            print("\nNo data captured.")

if __name__ == "__main__":
    main()
