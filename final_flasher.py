"""
CR Pro FINAL FLASHER
====================
Mode 1 (Frida): Patches UAP data during updater Restore
Mode 2 (Standalone): Writes firmware directly to discovered device handle
"""
import frida, sys, os, time, ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"

DEVICE_PATHS = [
    r"\\.\PhysicalDrive2",
    r"\\.\PhysicalDrive0",
    r"\\.\PhysicalDrive1",
    r"\\.\E:",
    r"\\.\GLOBALROOT\Device\HarddiskVolume2",
    r"\\.\GLOBALROOT\Device\HarddiskVolume3",
    r"\\.\GLOBALROOT\Device\HarddiskVolume4",
]

def find_flash_device():
    """Probe all device paths to find the one that works for flashing"""
    print("\n[PROBE] Searching for flash device...")
    for path in DEVICE_PATHS:
        h = kernel32.CreateFileW(path, 0xC0000000, 3, None, 3, 0x20000000, None)
        if h == wintypes.HANDLE(-1).value:
            continue
        # Test: write a small FF block and check for ACK
        buf = ctypes.create_string_buffer(bytes([0xFF] * 512), 512)
        written = wintypes.DWORD(0)
        ok = kernel32.WriteFile(h, buf, 512, ctypes.byref(written), None)
        if ok and written.value == 512:
            # Try reading an ACK
            ack = ctypes.create_string_buffer(1)
            ack_read = wintypes.DWORD(0)
            read_ok = kernel32.ReadFile(h, ack, 1, ctypes.byref(ack_read), None)
            print(f"  {path}: WRITE_OK READ={'OK' if read_ok else 'NONE'} ACK={ack.raw[0]:02X if read_ok else '?'}")
            if read_ok:
                print(f"\n[FOUND] Flash device: {path}")
                kernel32.CloseHandle(h)
                return path
        kernel32.CloseHandle(h)
    print("[WARN] No ACK-capable device found. Will try PhysicalDrive2 anyway.")
    return r"\\.\PhysicalDrive2"

HOOK_PATCHER = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var currentFile = '';
var ePatchCount = 0;
var flashBlockNum = 0;
var flashDeviceHandle = null;

// Track which handle is the flash device
var cfw = k32.findExportByName('CreateFileW');
Interceptor.attach(cfw, {
    onEnter: function(a) {
        var p = a[0].readUtf16String();
        if (p && p.indexOf('E:') >= 0 && p.indexOf('UAP') >= 0) {
            currentFile = p;
            console.log('FILE:' + p.split('\\').pop());
        }
        if (p && (p.indexOf('PhysicalDrive') >= 0 || p.indexOf('\\\\.\\USB') >= 0)) {
            console.log('DEVICE_OPEN:' + p);
        }
    },
    onLeave: function(r) {
        var h = r.toInt32();
        if (currentFile && h > 0) {
            // Track the handle used for UAP files
        }
    }
});

// WriteFile hook: patch UAP data in both E: files AND flash blocks
var wf = k32.findExportByName('WriteFile');
Interceptor.attach(wf, {
    onEnter: function(a) {
        this.h = a[0].toInt32();
        this.sz = a[2].toInt32();
        this.buf = a[1];
    },
    onLeave: function(r) {
        // E: file patches for UAP files
        if (this.sz >= 1000 && currentFile.indexOf('UAP_DIAGMS') >= 0) {
            try { this.buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]); ePatchCount++;
                if (ePatchCount <= 3) console.log('PATCH_E:' + ePatchCount); } catch(e) {}
        }
        if (this.sz >= 1000 && currentFile.indexOf('UAP_MENU') >= 0) {
            try { this.buf.add(32).writeByteArray([0x4D,0x4F,0x44,0x21]); } catch(e) {}
        }

        // Flash block: scan for UAP header at any offset and patch MOD!
        if (this.sz >= 16384) {
            flashBlockNum++;
            try {
                var bytes = this.buf.readByteArray(Math.min(this.sz, 256));
                var arr = new Uint8Array(bytes);
                for (var i = 0; i < arr.length - 16; i++) {
                    if (arr[i] === 0x92 && arr[i+1] === 0x95 && arr[i+2] === 0x97 && arr[i+3] === 0x96) {
                        var poff = i + 32;
                        if (poff < this.sz) {
                            this.buf.add(poff).writeByteArray([0x4D,0x4F,0x44,0x21]);
                            console.log('PATCH_FLASH:block=' + flashBlockNum + ' offset=' + poff);
                        }
                        break;
                    }
                }
            } catch(e) {}
            if (flashBlockNum <= 3 || flashBlockNum % 100 === 0) console.log('FLASH:' + flashBlockNum + ':' + this.sz);
        }
    }
});

console.log('FLASHER_READY');
"""

def mode_frida():
    """Run Frida hook to patch during updater restore"""
    print("=" * 55)
    print("CR Pro FLASHER - Mode: FRIDA PATCH")
    print("=" * 55)

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
    script = session.create_script(HOOK_PATCHER)

    def on_msg(message, data):
        if message['type'] == 'send': print(f"  {message['payload']}")
        elif message['type'] == 'error': print(f"  ERR: {message.get('description', message)}")

    script.on('message', on_msg)
    script.load()
    frida.resume(pid)

    print("\n>>> V20CRPRO_SYSTEM herunterladen! <<<")
    print("(Download von Aliyun, Frida patcht live)\n")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nBeendet. USB abziehen, Geraet neu starten!")

def mode_standalone(firmware_path):
    """Write firmware directly to device"""
    print("=" * 55)
    print("CR Pro FLASHER - Mode: STANDALONE")
    print("=" * 55)

    if not os.path.exists(firmware_path):
        print(f"ERROR: {firmware_path} not found!")
        return

    # Patch MOD! markers into UAP headers before flashing
    UAP_PATTERN = bytes([0x92, 0x95, 0x97, 0x96, 0x99, 0x98, 0x67, 0x6E])
    idx = 0
    patched = 0
    fw = bytearray(fw)
    while True:
        idx = fw.find(UAP_PATTERN, idx)
        if idx < 0: break
        poff = idx + 32
        if poff + 4 <= len(fw):
            fw[poff:poff+4] = b'MOD!'
            patched += 1
            print(f"[PATCH] UAP header at 0x{idx:X}, MOD! at 0x{poff:X}")
        idx += 8
    if patched == 0:
        print("[PATCH] No UAP headers found - firmware may be encrypted")
    fw = bytes(fw)

    # Find flash device
    dev_path = find_flash_device()

    # Open device
    h = kernel32.CreateFileW(dev_path, 0xC0000000, 3, None, 3, 0x20000000, None)
    if h == wintypes.HANDLE(-1).value:
        print(f"ERROR: Cannot open {dev_path}")
        return

    print(f"[OPEN] {dev_path}")

    # Send firmware in 16KB blocks
    BLOCK = 16384
    offset = 0
    block_num = 0

    while offset < len(fw):
        chunk_size = min(BLOCK, len(fw) - offset)
        buf = ctypes.create_string_buffer(fw[offset:offset+chunk_size], chunk_size)
        written = wintypes.DWORD(0)

        ok = kernel32.WriteFile(h, buf, chunk_size, ctypes.byref(written), None)
        if not ok or written.value != chunk_size:
            print(f"  BLOCK {block_num}: FAILED")
            break

        # Read ACK
        ack = ctypes.create_string_buffer(1)
        ack_read = wintypes.DWORD(0)
        kernel32.ReadFile(h, ack, 1, ctypes.byref(ack_read), None)

        offset += chunk_size
        block_num += 1
        if block_num % 20 == 0:
            pct = 100.0 * offset / len(fw)
            print(f"  Block {block_num}: {offset:>10,}/{len(fw):,} bytes ({pct:.1f}%)")

    kernel32.CloseHandle(h)
    print(f"\n[DONE] {block_num} blocks, {offset:,} bytes")
    print("USB abziehen, Geraet neu starten!")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode_standalone(sys.argv[1])
    else:
        mode_frida()
