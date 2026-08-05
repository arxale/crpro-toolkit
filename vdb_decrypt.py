#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vdb_decrypt.py — Entschlüsselt iCarsoft VDB-Datenbanken (XOR 0x49) und sucht
nach Begriffen.

FUND (2026-08-05): Die VDBs sind NICHT XOR 0x1E verschlüsselt (bisherige
Annahme), sondern XOR 0x49 — nur der Klartext-Header (Datum/Sprache/Version)
bleibt unverschlüsselt. Verifiziert an BMW_DE.vdb: XOR 0x49 liefert perfektes
Deutsch ("mitteltemperatursensor (0% bedeutet min., 100% bedeutet max.)").

Nutzung:
  python vdb_decrypt.py <datei.vdb> [begriff1 begriff2 ...]
    - ohne Begriffe: zeigt Struktur + lange Text-Sequenzen
    - mit Begriffen: sucht im entschlüsselten Inhalt (ASCII + UTF-16)
"""
import re
import sys

KEY = 0x49


def decrypt(data):
    return bytes(b ^ KEY for b in data)


def printable(b):
    return 32 <= b < 127


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    terms = sys.argv[2:]
    data = open(path, "rb").read()
    dec = decrypt(data)
    print(f"Datei: {path} ({len(data):,} B), XOR {KEY:#04x} dekodiert")

    if not terms:
        # Struktur: lange ASCII-Läufe lokalisieren
        runs = []
        start = None
        for i, b in enumerate(dec):
            ok = printable(b) or b in (0x00, 0x1E, 0x1F)
            if ok and start is None:
                start = i
            elif not ok and start is not None:
                if i - start > 30:
                    runs.append((start, i))
                start = None
        print(f"Text-Bereiche: {len(runs)}")
        for s, e in runs[:30]:
            sample = ''.join(chr(b) if printable(b) else '.' for b in dec[s:e])
            print(f"  {s:>10} - {e:>10}: {sample[:80]}")
        return 0

    for t in terms:
        n_ascii = len(re.findall(t.encode('utf-8', errors='ignore'), dec))
        n_utf16 = len(re.findall(t.encode('utf-16-le', errors='ignore'), dec))
        print(f"\n=== {t}: ASCII {n_ascii}, UTF-16 {n_utf16} ===")
        if n_ascii + n_utf16 == 0:
            continue
        for enc_name, enc in [('ASCII', t.encode('utf-8', errors='ignore')),
                              ('UTF16', t.encode('utf-16-le', errors='ignore'))]:
            for m in list(re.finditer(enc, dec))[:5]:
                i = m.start()
                ctx = ''.join(chr(b) if printable(b) else '.' for b in dec[max(0, i - 50):i + 70])
                print(f"  [{enc_name}] @{i}: {ctx}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
