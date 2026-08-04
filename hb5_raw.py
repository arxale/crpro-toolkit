import frida, sys, os, time, socket, threading

UPDATER = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"
LOCAL_PORT = 9191
MOD_ZIP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modified_firmware.zip")

def raw_server():
    """Serve MOD_ZIP via raw TCP — no http.server overhead"""
    data = None
    if os.path.exists(MOD_ZIP):
        with open(MOD_ZIP, 'rb') as f:
            data = f.read()
    if not data:
        print("[SERVER] ZIP not found!")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', LOCAL_PORT))
    sock.listen(5)
    print(f"[SERVER] Raw TCP on :{LOCAL_PORT}, {len(data)} bytes ready")

    while True:
        try:
            conn, addr = sock.accept()
            # Read request until double CRLF
            req = b''
            while b'\r\n\r\n' not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                req += chunk
                if len(req) > 65536:
                    break

            # Check if Range request
            range_start = 0
            range_end = len(data) - 1
            req_str = req.decode('latin-1', errors='replace')
            if 'Range: bytes=' in req_str:
                range_part = req_str.split('Range: bytes=')[1].split('\r\n')[0]
                parts = range_part.split('-')
                range_start = int(parts[0]) if parts[0] else 0
                range_end = int(parts[1]) if len(parts) > 1 and parts[1] else len(data) - 1

            chunk_data = data[range_start:range_end + 1]
            chunk_len = len(chunk_data)

            # Build HTTP response manually
            if range_start > 0 or range_end < len(data) - 1:
                resp = (
                    f"HTTP/1.1 206 Partial Content\r\n"
                    f"Content-Type: application/zip\r\n"
                    f"Content-Range: bytes {range_start}-{range_end}/{len(data)}\r\n"
                    f"Content-Length: {chunk_len}\r\n"
                    f"Accept-Ranges: bytes\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode('ascii')
            else:
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/zip\r\n"
                    f"Content-Length: {chunk_len}\r\n"
                    f"Accept-Ranges: bytes\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode('ascii')

            conn.sendall(resp)
            conn.sendall(chunk_data)
            conn.shutdown(socket.SHUT_WR)
            # Read any pending data
            try:
                while conn.recv(4096): pass
            except: pass
            conn.close()
            print(f"[SERVED] {chunk_len} bytes (range={range_start}-{range_end})")
        except Exception as e:
            print(f"[SERVER-ERR] {e}")
            try: conn.close()
            except: pass

HOOK_JS = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var wininetMod = Process.findModuleByName('WININET.dll');

if (wininetMod) {
    var iouw = wininetMod.findExportByName('InternetOpenUrlW');
    if (iouw) Interceptor.attach(iouw, {
        onEnter: function(a) {
            var url = a[1].readUtf16String();
            if (url && url.indexOf('V20CRPRO_SYSTEM.zip') >= 0) {
                console.log('REDIRECT');
                a[1] = Memory.allocUtf16String('http://127.0.0.1:__PORT__/firmware.zip');
            }
        }
    });
}

var wf = k32.findExportByName('WriteFile');
var bc = 0;
Interceptor.attach(wf, {
    onEnter: function(a) { this.sz = a[2].toInt32(); },
    onLeave: function(r) {
        if (this.sz >= 16384) {
            bc++;
            if (bc <= 5 || bc % 100 === 0) console.log('BLOCK:' + bc);
        }
    }
});

console.log('RAW_READY');
""".replace('__PORT__', str(LOCAL_PORT))

def main():
    print("CR Pro RAW TCP Server")
    print(f"ZIP exists: {os.path.exists(MOD_ZIP)}")
    if os.path.exists(MOD_ZIP):
        print(f"ZIP size: {os.path.getsize(MOD_ZIP)}")

    t = threading.Thread(target=raw_server, daemon=True)
    t.start()
    time.sleep(0.5)

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

    def on_message(message, data):
        if message['type'] == 'send': print(f"[HOOK] {message['payload']}")
        elif message['type'] == 'error': print(f"[ERROR] {message.get('description', message)}")

    script.on('message', on_message)
    script.load()
    frida.resume(pid)

    print("\n>>> V20CRPRO_SYSTEM herunterladen! <<<\n")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("Beendet.")

if __name__ == "__main__":
    main()
