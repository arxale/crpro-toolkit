"""
FuncCfg Patcher V2 - CLONES existing entries instead of changing function types
Adds MORE ECU entries using EXISTING function types (Z, P, v, F)
The firmware already knows how to handle these types!
"""
import os, struct

E = "E:"
MAKES = os.path.join(E, "MSDIAG", "MAKES")

def patch_bmw(path):
    """BMW: Clone existing records to add more ECU entries with same function types"""
    if not os.path.exists(path): return 0
    data = bytearray(open(path, 'rb').read())

    # BMW format: 36-byte records (9 slots x 4 bytes), tail=0x69
    # Find a complete record (9 consecutive slots with 0x69 tail)
    records = []
    i = 0
    while i < len(data) - 36:
        # Check if we have 9 slots with tail 0x69
        valid = True
        for s in range(9):
            if i + s*4 + 3 >= len(data) or data[i + s*4 + 3] != 0x69:
                valid = False
                break
        if valid:
            records.append(i)
            i += 36
        else:
            i += 4

    if len(records) < 2: return 0

    # Take the LAST valid record and CLONE it 5 times (adding 5 new ECU entries)
    last = records[-1]
    template = bytes(data[last:last+36])

    # Append 5 clones to the end of the record area
    insert_pos = last + 36
    clones = template * 5
    new_data = bytes(data[:insert_pos]) + clones + bytes(data[insert_pos:])
    data = bytearray(new_data)

    # Also add ONE record with a different letter prefix (next in alphabet)
    # The letter is in slot 0, byte 1 (e.g., "e.bi" -> "f.bi")
    last_letter = data[last+1]  # letter from last record
    if 97 <= last_letter <= 122:  # a-z
        new_letter = last_letter + 1
        if new_letter <= 122:
            for j in range(5):
                off = insert_pos + j * 36
                data[off+1] = new_letter + j  # sequential letters
                # Also update slot 1 (paired letter)
                data[off+5] = 0x30 + j  # G0, G1, G2...

    open(path, 'wb').write(data)
    print(f"  BMW: {len(records)} records, added 5 clones + new entries")
    return 5

def patch_benz(path):
    """BENZ: Clone existing &CU records to add more coding entries"""
    if not os.path.exists(path): return 0
    data = bytearray(open(path, 'rb').read())

    # BENZ format: 7-8 slot records, XOR 0x2F, tail=0x0F
    # Find &CU entries
    cu_offsets = []
    for i in range(len(data) - 32):
        # Look for XOR'd "CU" pattern: 0x6C 0x7A
        if data[i] == 0x6C and data[i+1] == 0x7A:
            # Found CU marker. Check prefix byte for function type
            prefix = data[i-1] if i > 0 else 0
            if prefix == 0x09:  # & XOR 0x2F
                cu_offsets.append(i-1)  # start of function type

    if len(cu_offsets) < 2: return 0

    # Clone the first &CU record 3 times
    # Find the record boundaries (previous record ends at 0x00 0x00 0x00 0x00)
    first_cu = cu_offsets[0]
    # Go back to find record start
    rec_start = first_cu
    while rec_start > 0:
        if data[rec_start-4:rec_start] == b'\x00\x00\x00\x00':
            break
        rec_start -= 4
    # Go forward to find record end
    rec_end = first_cu + 8  # start from CU marker
    while rec_end < len(data) - 4:
        if data[rec_end:rec_end+4] == b'\x00\x00\x00\x00':
            rec_end += 4
            break
        rec_end += 4

    rec_len = rec_end - rec_start
    if rec_len < 24 or rec_len > 64:
        print(f"  BENZ: record length {rec_len} unexpected, skipping")
        return 0

    template = bytes(data[rec_start:rec_end])
    # Find end of record table (sequence of 0x00)
    table_end = rec_end
    while table_end < len(data) - 4 and data[table_end:table_end+4] == b'\x00\x00\x00\x00':
        table_end += 4

    # Insert clones after the record table
    clones = template * 3
    new_data = bytes(data[:table_end]) + clones + bytes(data[table_end:])
    data = bytearray(new_data)

    open(path, 'wb').write(data)
    print(f"  BENZ: {len(cu_offsets)} &CU entries, added 3 clones")
    return 3

def patch_generic(path, brand):
    """Generic: Clone existing records"""
    if not os.path.exists(path): return 0
    data = bytearray(open(path, 'rb').read())

    # Find patterns of 0x0F tail (BENZ-style XOR)
    tails_0f = 0
    for i in range(3, min(len(data), 100000), 4):
        if data[i] == 0x0F:
            tails_0f += 1

    # Find patterns of 0x69 tail (BMW-style plaintext)
    tails_69 = 0
    for i in range(3, min(len(data), 100000), 4):
        if data[i] == 0x69:
            tails_69 += 1

    print(f"  {brand}: 0x0F={tails_0f} 0x69={tails_69} slots")
    return 0  # No modifications for unknown formats yet

def main():
    print("=== FuncCfg V2 - Clone Records ===\n")
    if not os.path.exists(MAKES):
        print("ERROR: E: nicht gemountet! Gerät im Upgrade Mode?")
        return

    total = 0
    for brand_dir in sorted(os.listdir(MAKES)):
        brand_path = os.path.join(MAKES, brand_dir)
        if not os.path.isdir(brand_path): continue
        if brand_dir.startswith('RESET'): continue
        if brand_dir == 'OBD': continue

        for ver_dir in sorted(os.listdir(brand_path)):
            ver_path = os.path.join(brand_path, ver_dir)
            if not os.path.isdir(ver_path): continue
            funcfg = os.path.join(ver_path, 'FuncCfg.bin')
            if not os.path.exists(funcfg): continue

            if brand_dir in ('BMW', 'MINI'):
                n = patch_bmw(funcfg)
            elif brand_dir == 'BENZ':
                n = patch_benz(funcfg)
            else:
                n = patch_generic(funcfg, brand_dir)
            total += n
            break

    print(f"\nTotal clones added: {total}")

if __name__ == "__main__":
    main()
