"""Patch FuncCfg.bin files directly on E: to add coding (&CU) entries"""
import os, struct

E = "E:"
MAKES = os.path.join(E, "MSDIAG", "MAKES")

def patch_bmw_funcfg(path):
    """BMW FuncCfg: change .Zhi/.Phi to .Chi (coding)"""
    if not os.path.exists(path): return 0
    
    data = bytearray(open(path, 'rb').read())
    patches = 0
    
    # Find ".Zhi" or ".Phi" patterns: [any][Z/P][h][i]
    for i in range(len(data) - 3):
        if data[i+2] == 0x68 and data[i+3] == 0x69:  # h, i
            cat = data[i+1]
            if cat in (0x5A, 0x50):  # Z or P
                data[i+1] = 0x43  # -> C
                patches += 1
    
    if patches > 0:
        open(path, 'wb').write(data)
        print(f"  BMW: {patches} .Zhi/.Phi -> .Chi")
    return patches

def patch_benz_funcfg(path):
    """BENZ FuncCfg: XOR 0x2F encoded. Change FCU/vCU to &CU"""
    if not os.path.exists(path): return 0
    
    data = bytearray(open(path, 'rb').read())
    patches = 0
    
    # Find "CU" pattern XOR 0x2F = 0x6C 0x7A
    for i in range(1, len(data) - 2):
        if data[i] == 0x6C and data[i+1] == 0x7A:  # CU^0x2F
            prefix = data[i-1]
            if prefix not in (0x00, 0xFF):  # Not empty
                data[i-1] = 0x09  # & ^ 0x2F
                patches += 1
    
    if patches > 0:
        open(path, 'wb').write(data)
        print(f"  BENZ: {patches} -> &CU")
    return patches

def patch_generic_funcfg(path, brand):
    """Generic FuncCfg patch - try multiple encodings"""
    if not os.path.exists(path): return 0
    
    data = bytearray(open(path, 'rb').read())
    patches = 0
    
    # Try XOR 0x2F (most common)
    for i in range(1, len(data) - 2):
        if data[i] == 0x6C and data[i+1] == 0x7A:
            data[i-1] = 0x09
            patches += 1
    
    # Try plaintext "vCU" / "FCU" (some brands)
    for i in range(len(data) - 3):
        if data[i:i+3] in (b'vCU', b'FCU'):
            data[i:i+3] = b'&CU'
            patches += 1
    
    if patches > 0:
        open(path, 'wb').write(data)
        print(f"  {brand}: {patches} patches")
    return patches

def main():
    print("=== FuncCfg Patcher ===\n")
    if not os.path.exists(MAKES):
        print("ERROR: E: nicht gemountet! Gerät im Upgrade Mode?")
        return
    
    total = 0
    for brand_dir in sorted(os.listdir(MAKES)):
        brand_path = os.path.join(MAKES, brand_dir)
        if not os.path.isdir(brand_path): continue
        if brand_dir.startswith('RESET'): continue  # Skip reset-only brands
        if brand_dir == 'OBD': continue  # Skip OBD
        
        # Find version directory
        for ver_dir in sorted(os.listdir(brand_path)):
            ver_path = os.path.join(brand_path, ver_dir)
            if not os.path.isdir(ver_path): continue
            
            funcfg = os.path.join(ver_path, 'FuncCfg.bin')
            if not os.path.exists(funcfg): continue
            
            if brand_dir == 'BMW' or brand_dir == 'MINI':
                n = patch_bmw_funcfg(funcfg)
            elif brand_dir == 'BENZ':
                n = patch_benz_funcfg(funcfg)
            else:
                n = patch_generic_funcfg(funcfg, brand_dir)
            total += n
            break  # Only first version dir
    
    print(f"\nTotal patches: {total}")

if __name__ == "__main__":
    main()
