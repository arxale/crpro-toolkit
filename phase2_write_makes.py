#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phase2_write_makes.py — patcht NUR die FuncCfg.bin der Marken direkt auf der
gemounteten Karte (E: im Upgrade-Modus).

WICHTIG: license.dat, Menu.bin, ScanCfg.bin, SetLink.bin werden NICHT angefasst —
die kommen vom Updater (gerätegebunden, pro Update neu erzeugt). Eine Kopie aus
einem alten Dump macht den Lizenzcheck des Geräts kaputt
("Vehicle database does not have License file!").

Ablauf nach dem Fehler:
  1. Gerät im Upgrade-Modus an PC (E: gemountet)
  2. Im Updater BMW + BENZ ERNEUT herunterladen  -> erzeugt gültige license.dat
     (überschreibt dabei FuncCfg mit Original — Patches weg)
  3. Dieses Skript ausführen                       -> patcht FuncCfg wieder
  4. USB abziehen, Gerät neu starten
"""
import argparse
import hashlib
import os
import shutil
import sys

CARD = "E:"


def md5_file(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def count_bmw_slots(data):
    n = 0
    for i in range(len(data) - 3):
        if data[i+2] == 0x68 and data[i+3] == 0x69 and data[i+1] in (0x5A, 0x50):
            n += 1
    return n


def count_benz_slots(data):
    n = 0
    for i in range(1, len(data) - 2):
        if data[i] == 0x6C and data[i+1] == 0x7A and data[i-1] not in (0x00, 0xFF, 0x09):
            n += 1
    return n


def patch_bmw(data):
    data = bytearray(data)
    n = 0
    for i in range(len(data) - 3):
        if data[i+2] == 0x68 and data[i+3] == 0x69 and data[i+1] in (0x5A, 0x50):
            data[i+1] = 0x43
            n += 1
    return bytes(data), n


def patch_benz(data):
    data = bytearray(data)
    n = 0
    for i in range(1, len(data) - 2):
        if data[i] == 0x6C and data[i+1] == 0x7A and data[i-1] not in (0x00, 0xFF):
            data[i-1] = 0x09
            n += 1
    return bytes(data), n


def find_source():
    cands = [os.path.join("extra", "MSDIAG", "MAKES"),
             os.path.join(os.path.dirname(os.path.abspath(__file__)), "extra", "MSDIAG", "MAKES"),
             os.path.join(os.path.dirname(os.path.abspath(__file__)), "MSDIAG", "MAKES")]
    for c in cands:
        if os.path.isdir(c):
            return c
    return None


def main():
    ap = argparse.ArgumentParser(description="Patch FuncCfg.bin on the mounted card (BMW/BENZ coding)")
    ap.add_argument("--card", default=CARD, help="card drive (default E:)")
    ap.add_argument("--check", action="store_true",
                    help="only list what's on the card (no writes): VDBs, FuncCfg, license, Menu")
    ap.add_argument("--full", action="store_true",
                    help="DANGER: also write Menu/ScanCfg/SetLink/license from the dump "
                         "(only if you know they match the current updater state)")
    args = ap.parse_args()

    card = args.card
    print("=" * 62)
    print("[PHASE2] Patche FuncCfg.bin (BMW/BENZ) auf der Karte")
    print("=" * 62)

    if not os.path.isdir(card + "\\"):
        print(f"[FAIL] {card}: nicht gemountet. Gerät im Upgrade-Modus?")
        return 1
    print(f"[OK] Karte {card} ist gemountet")

    makes_src = find_source()
    if not makes_src:
        print("[FAIL] extra/MSDIAG/MAKES nicht gefunden (extra.zip entpacken!)")
        return 1
    print(f"[OK] Patch-Quelle: {makes_src}")

    makes_dst = os.path.join(card, "MSDIAG", "MAKES")
    if not os.path.isdir(makes_dst):
        print(f"[FAIL] {makes_dst} existiert nicht auf der Karte")
        return 1

    # --- CHECK MODE: inventory of the card (no writes) ---
    if args.check:
        print("\n[CHECK] Inventar der Karte (MSDIAG/MAKES):")
        for brand in sorted(os.listdir(makes_dst)):
            bpath = os.path.join(makes_dst, brand)
            if not os.path.isdir(bpath):
                continue
            for ver in sorted(os.listdir(bpath)):
                vpath = os.path.join(bpath, ver)
                if not os.path.isdir(vpath):
                    continue
                print(f"\n  [{brand}/{ver}]")
                for f in sorted(os.listdir(vpath)):
                    fp = os.path.join(vpath, f)
                    if os.path.isfile(fp):
                        sz = os.path.getsize(fp)
                        mark = ""
                        if f.lower() == "license.dat":
                            m = md5_file(fp)
                            mark = f"  md5={m[:16]}..."
                        if f.lower() == "funcfg.bin":
                            try:
                                d = open(fp, "rb").read()
                                if brand == "BMW":
                                    c = count_bmw_slots(d)
                                else:
                                    c = count_benz_slots(d)
                                mark = f"  ungepatchte Slots: {c}"
                            except Exception:
                                pass
                        print(f"    {f:<20} {sz:>12,} B{mark}")
        print("\n[CHECK] Ende. Fehlt BMW_DE.vdb o.ä.? -> im Updater Marke mit Sprache DE erneut herunterladen.")
        return 0

    # cleanup stray .bak files from the previous phase2 run
    for root, dirs, files in os.walk(makes_dst):
        for f in files:
            if f.lower().endswith(".bak"):
                try:
                    os.remove(os.path.join(root, f))
                    print(f"[CLEAN] entfernt {os.path.join(root, f)}")
                except OSError as e:
                    print(f"[WARN] {e}")

    patched = 0
    for brand in ("BMW", "BENZ"):
        bsrc = os.path.join(makes_src, brand)
        if not os.path.isdir(bsrc):
            print(f"[WARN] {brand}: nicht in Quelle — übersprungen")
            continue
        ver = sorted(os.listdir(bsrc))[0]
        vdst = os.path.join(makes_dst, brand, ver)
        if not os.path.isdir(vdst):
            print(f"[FAIL] {brand}/{ver}: Zielordner fehlt auf Karte — Updater-Update vorher ausführen!")
            continue

        # --- FuncCfg.bin: patchen ---
        src_func = os.path.join(bsrc, ver, "FuncCfg.bin")
        dst_func = os.path.join(vdst, "FuncCfg.bin")
        if os.path.isfile(src_func) and os.path.isfile(dst_func):
            src_data = open(src_func, "rb").read()
            if brand == "BMW":
                data, n = patch_bmw(src_data)
                cnt = count_bmw_slots(data)
            else:
                data, n = patch_benz(src_data)
                cnt = count_benz_slots(data)
            open(dst_func, "wb").write(data)
            print(f"[WROTE] {brand}/{ver}/FuncCfg.bin (gepatcht: {n:,} Slots, "
                  f"verbleibende ungepatchte: {cnt})")
            patched += 1
        else:
            print(f"[WARN] {brand}: FuncCfg.bin fehlt (Quelle oder Ziel) — übersprungen")

        # --- license.dat: NUR prüfen, nicht schreiben ---
        lic = os.path.join(vdst, "license.dat")
        if os.path.isfile(lic):
            m = md5_file(lic)
            print(f"[LICENSE] {brand}/{ver}/license.dat vorhanden (md5={m[:16]}...)"
                  f"{' — frisch vom Updater erzeugt (gut)' if not args.full else ' — WARN: --full überschreibt!'}")
        else:
            print(f"[LICENSE] {brand}/{ver}/license.dat FEHLT auf der Karte! "
                  f"Erst im Updater die Marke erneut herunterladen.")

        # --- --full: DANGER, nur auf eigene Gefahr ---
        if args.full:
            for fn in ("Menu.bin", "ScanCfg.bin", "SetLink.bin", "license.dat"):
                s = os.path.join(bsrc, ver, fn)
                if os.path.isfile(s):
                    shutil.copy2(s, os.path.join(vdst, fn))
                    print(f"[--FULL] überschrieben {brand}/{ver}/{fn}")

    # sysctl-Trigger prüfen
    sysctl = os.path.join(card, "MSDIAG", "SYSTEM", "FIRMWARE", "sysctl.bin")
    if os.path.isfile(sysctl):
        m = md5_file(sysctl)
        print(f"[TRIGGER] sysctl.bin md5={m}")
        print("[TRIGGER] == Geräte-Original (gut)" if m == "d241db949e000122b95de14e578e0fca"
              else "[TRIGGER] != Original! (Achtung)")
    else:
        print("[TRIGGER] sysctl.bin fehlt auf der Karte!")

    print(f"\n[PHASE2] {patched} FuncCfg-Binärdateien gepatcht.")
    if patched == 0:
        print("[PHASE2] Nichts gepatcht. Prüfe Quelle + dass der Updater die Marken zuerst geschrieben hat.")
        return 1
    print("NEXT: USB abziehen, Gerät neu starten. Bootloader flasht die gepatchte FuncCfg.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
