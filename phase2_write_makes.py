#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phase2_write_makes.py — schreibt die gepatchten BMW/BENZ-Daten direkt auf die
gemountete Karte (E: im Upgrade-Modus). Läuft separat NACH attack.py,
damit der System-Flash-Trigger (sysctl.bin) erhalten bleibt.
"""
import os, sys, shutil

CARD = "E:"
EXTRA = "extra"          # Verzeichnis mit MSDIAG/MAKES/... (aus extra.zip entpackt)

def md5_file(p):
    import hashlib
    h = hashlib.md5()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    print("=" * 62)
    print("[PHASE2] Schreibe gepatchte BMW/BENZ-Daten direkt auf die Karte")
    print("=" * 62)

    # 1. Karte gemountet?
    if not os.path.isdir(CARD + "\\"):
        print(f"[FAIL] {CARD}: nicht gemountet. Gerät im Upgrade-Modus?")
        return 1
    print(f"[OK] Karte {CARD} ist gemountet")

    # 2. extra-Quelle finden (extra/ oder MSDIAG/ direkt daneben)
    src = None
    cands = [EXTRA,
             os.path.join(os.path.dirname(os.path.abspath(__file__)), "extra"),
             os.path.join(os.path.dirname(os.path.abspath(__file__)), "MSDIAG", "MAKES")]
    for c in cands:
        if os.path.isdir(os.path.join(c, "MSDIAG", "MAKES")):
            src = c
            break
    if not src:
        print("[FAIL] extra/ mit MSDIAG/MAKES nicht gefunden (extra.zip entpacken!)")
        return 1
    print(f"[OK] Quelle: {src}")

    # 3. Ziele: BMW, BENZ (Versionen aus Quelle nehmen)
    makes_src = os.path.join(src, "MSDIAG", "MAKES")
    makes_dst = os.path.join(CARD, "MSDIAG", "MAKES")
    if not os.path.isdir(makes_dst):
        print(f"[FAIL] {makes_dst} existiert nicht auf der Karte")
        return 1

    written = 0
    for brand in ("BMW", "BENZ"):
        bsrc = os.path.join(makes_src, brand)
        if not os.path.isdir(bsrc):
            print(f"[WARN] {brand}: nicht in Quelle — übersprungen")
            continue
        ver = sorted(os.listdir(bsrc))[0]
        vsrc = os.path.join(bsrc, ver)
        vdst = os.path.join(makes_dst, brand, ver)
        os.makedirs(vdst, exist_ok=True)

        # Backup des bestehenden FuncCfg (falls vorhanden)
        dst_func = os.path.join(vdst, "FuncCfg.bin")
        if os.path.isfile(dst_func):
            try:
                shutil.copy2(dst_func, dst_func + ".bak")
                print(f"[BACKUP] {brand}/{ver}/FuncCfg.bin -> FuncCfg.bin.bak")
            except Exception as e:
                print(f"[WARN] backup fehlgeschlagen: {e}")

        for fn in ("FuncCfg.bin", "Menu.bin", "ScanCfg.bin", "SetLink.bin", "license.dat"):
            s = os.path.join(vsrc, fn)
            if not os.path.isfile(s):
                continue
            d = os.path.join(vdst, fn)
            shutil.copy2(s, d)
            size = os.path.getsize(d)
            print(f"[WROTE] {brand}/{ver}/{fn} ({size:,} B)")

        # Verifikation: FuncCfg-Patch-Slots zählen
        if os.path.isfile(dst_func):
            data = open(dst_func, "rb").read()
            if brand == "BMW":
                n = 0
                for i in range(len(data) - 3):
                    if data[i+2] == 0x68 and data[i+3] == 0x69 and data[i+1] in (0x5A, 0x50):
                        n += 1
                print(f"[VERIFY] {brand}: verbleibende .Zhi/.Phi-Slots: {n} (sollte 0 sein)")
            else:
                n = 0
                for i in range(1, len(data) - 2):
                    if data[i] == 0x6C and data[i+1] == 0x7A and data[i-1] not in (0x00, 0xFF, 0x09):
                        n += 1
                print(f"[VERIFY] {brand}: ungepatchte CU-Slots: {n} (sollte 0 sein)")
            written += 1

    # 4. sysctl-Trigger prüfen
    sysctl = os.path.join(CARD, "MSDIAG", "SYSTEM", "FIRMWARE", "sysctl.bin")
    if os.path.isfile(sysctl):
        m = md5_file(sysctl)
        print(f"[TRIGGER] sysctl.bin auf Karte: md5={m}")
        if m == "d241db949e000122b95de14e578e0fca":
            print("[TRIGGER] == Geräte-Original (gut — Flash-Trigger intakt)")
        else:
            print("[TRIGGER] != Original! (Achtung: unbekannter Inhalt)")
    else:
        print("[TRIGGER] sysctl.bin fehlt auf der Karte!")

    print(f"\n[PHASE2] {written} Marken-Sätze geschrieben.")
    print("NEXT: USB abziehen, Gerät neu starten. Bootloader flasht die Karte.")
    return 0 if written else 1

if __name__ == "__main__":
    sys.exit(main())
