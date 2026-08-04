"""Capture COMPLETE flash blocks for Ghidra analysis"""
import frida, sys, os, time

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captured_firmware.bin")

HOOK = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var wf = k32.findExportByName('WriteFile');
var blockNum = 0;
var allBlocks = [];

Interceptor.attach(wf, {
    onEnter: function(a) {
        this.sz = a[2].toInt32();
        this.buf = a[1];
    },
    onLeave: function(r) {
        // Capture 16KB blocks (firmware flash data)
        if (this.sz === 16384 || this.sz > 1000) {
            blockNum++;
            try {
                var data = this.buf.readByteArray(this.sz);
                var hex = '';
                var arr = new Uint8Array(data);
                for (var i = 0; i < arr.length; i++) {
                    hex += ('0' + arr[i].toString(16)).slice(-2);
                }
                // Send block data to Python side
                send({type: 'block', num: blockNum, size: this.sz, hex: hex});
            } catch(e) {
                send({type: 'block_err', num: blockNum, err: e.toString()});
            }
        }
    }
});

console.log('CAPTURE_READY');
"""

def main():
    print("CR Pro Full Firmware Capture")
    print(f"Output: {OUTPUT}")

    # Clean up
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

    blocks_received = 0
    all_blocks = []  # list of (num, bytes)

    pid = frida.spawn(UPDATER)
    session = frida.attach(pid)
    script = session.create_script(HOOK)

    def on_msg(message, data):
        nonlocal blocks_received, all_blocks
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict) and payload.get('type') == 'block':
                num = payload['num']
                size = payload['size']
                hex_str = payload['hex']
                raw = bytes.fromhex(hex_str)
                all_blocks.append((num, raw))
                blocks_received += 1
                if blocks_received % 50 == 0:
                    total = sum(len(b) for _, b in all_blocks)
                    print(f"  Block {num}: {size}B | Total: {len(all_blocks)} blocks, {total:,} bytes")
            elif isinstance(payload, dict) and payload.get('type') == 'block_err':
                print(f"  Block {payload['num']}: ERROR {payload['err']}")
        elif message['type'] == 'error':
            print(f"  ERR: {message.get('description', message)}")

    script.on('message', on_msg)
    script.load()
    frida.resume(pid)

    print("\n>>> V20CRPRO_SYSTEM herunterladen! <<<\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nSaving captured firmware...")
        # Sort by block number and concatenate
        all_blocks.sort(key=lambda x: x[0])
        total_data = b''
        for num, data in all_blocks:
            total_data += data
        with open(OUTPUT, 'wb') as f:
            f.write(total_data)
        print(f"Saved: {OUTPUT}")
        print(f"Blocks: {len(all_blocks)}, Total: {len(total_data):,} bytes")
        print("Ready for Ghidra analysis!")

if __name__ == "__main__":
    main()
