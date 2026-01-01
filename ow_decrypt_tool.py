"""
Overwatch Pointer Decryption Tool
Run inside Windows VM to read and decrypt Overwatch memory

Usage:
    python ow_decrypt_tool.py <C_CONSTANT>
    
Example:
    python ow_decrypt_tool.py 0xb37673a668217138

Get C from host with GDB:
    - Hit breakpoint on thunk
    - C = RCX ^ RAX (encrypted XOR decrypted)
"""

import ctypes
import ctypes.wintypes as wt
import struct
import sys
import time

# Windows API
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Offsets (Windows 11 24H2/25H2)
OFFSETS = {
    'entity_admin': 0x37EE2A0,
    'view_matrix': 0x400A2C8,
    'xor_byte': 0x3256851,
}

# Entity offsets
ENTITY = {
    'component_ptr': 0x28,      # Encrypted
    'entity_id': 0x60,
    'rotation': 0x170,          # float[4] quaternion
    'position': 0x280,          # float[4] X,Y,Z,W
    'position2': 0x2c0,         # float[4] interpolated
    'health': 0x3c8,            # float
}

class OverwatchReader:
    def __init__(self, C: int):
        self.C = C
        self.pid = None
        self.handle = None
        self.base = None
        
    def decrypt(self, encrypted: int) -> int:
        """Decrypt pointer using session constant C"""
        return self.C ^ encrypted
    
    def find_process(self) -> bool:
        """Find Overwatch.exe PID"""
        # EnumProcesses
        arr = (ctypes.c_ulong * 1024)()
        size = ctypes.c_ulong()
        psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(size))
        
        for i in range(size.value // 4):
            pid = arr[i]
            if pid == 0:
                continue
            h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if h:
                name = (ctypes.c_char * 260)()
                if psapi.GetModuleBaseNameA(h, None, name, 260):
                    if b'Overwatch' in name.value:
                        self.pid = pid
                        kernel32.CloseHandle(h)
                        print(f"[+] Found Overwatch.exe PID: {pid}")
                        return True
                kernel32.CloseHandle(h)
        return False
    
    def attach(self) -> bool:
        """Attach to Overwatch process"""
        if not self.find_process():
            print("[-] Overwatch.exe not found!")
            return False
            
        self.handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, self.pid)
        if not self.handle:
            print(f"[-] Failed to open process: {ctypes.get_last_error()}")
            return False
        
        # Get base address
        modules = (ctypes.c_void_p * 1024)()
        needed = ctypes.c_ulong()
        if psapi.EnumProcessModules(self.handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            self.base = modules[0]
            print(f"[+] Base address: 0x{self.base:x}")
            return True
        return False
    
    def read_bytes(self, addr: int, size: int) -> bytes:
        """Read bytes from process memory"""
        buf = (ctypes.c_char * size)()
        read = ctypes.c_size_t()
        if kernel32.ReadProcessMemory(self.handle, addr, buf, size, ctypes.byref(read)):
            return bytes(buf)
        return b'\x00' * size
    
    def read_u64(self, addr: int) -> int:
        """Read 64-bit unsigned int"""
        data = self.read_bytes(addr, 8)
        return struct.unpack('<Q', data)[0]
    
    def read_u32(self, addr: int) -> int:
        """Read 32-bit unsigned int"""
        data = self.read_bytes(addr, 4)
        return struct.unpack('<I', data)[0]
    
    def read_float(self, addr: int) -> float:
        """Read float"""
        data = self.read_bytes(addr, 4)
        return struct.unpack('<f', data)[0]
    
    def read_vec3(self, addr: int) -> tuple:
        """Read 3 floats (X, Y, Z)"""
        data = self.read_bytes(addr, 12)
        return struct.unpack('<fff', data)
    
    def get_entity_admin(self) -> int:
        """Get entity_admin pointer"""
        addr = self.base + OFFSETS['entity_admin']
        return self.read_u64(addr)
    
    def get_entity_list(self) -> int:
        """Get entity list from entity_admin"""
        admin = self.get_entity_admin()
        if admin == 0:
            return 0
        # First pointer in entity_admin is the entity table
        return self.read_u64(admin)
    
    def read_entity(self, slot: int) -> dict:
        """Read entity from slot (each slot is 16 bytes: ptr + flags)"""
        entity_list = self.get_entity_list()
        if entity_list == 0:
            return None
            
        slot_addr = entity_list + (slot * 16)
        entity_ptr = self.read_u64(slot_addr)
        
        if entity_ptr == 0:
            return None
        
        # Read entity data
        entity_id = self.read_u64(entity_ptr + ENTITY['entity_id'])
        
        # Check if valid entity (has 0x0a50 prefix)
        if (entity_id >> 48) != 0x0a50:
            return None
        
        pos = self.read_vec3(entity_ptr + ENTITY['position'])
        health = self.read_float(entity_ptr + ENTITY['health'])
        
        # Read encrypted component pointer
        enc_comp = self.read_u64(entity_ptr + ENTITY['component_ptr'])
        dec_comp = self.decrypt(enc_comp) if enc_comp != 0 else 0
        
        return {
            'ptr': entity_ptr,
            'id': entity_id,
            'pos': pos,
            'health': health,
            'enc_component': enc_comp,
            'dec_component': dec_comp,
        }
    
    def scan_entities(self, max_slots: int = 128):
        """Scan entity slots and print valid entities"""
        print(f"\n[*] Scanning {max_slots} entity slots...")
        print("-" * 80)
        
        found = 0
        for i in range(max_slots):
            ent = self.read_entity(i)
            if ent:
                found += 1
                x, y, z = ent['pos']
                print(f"[{i:3}] ID=0x{ent['id']:016x} HP={ent['health']:6.1f} Pos=({x:8.1f}, {y:8.1f}, {z:8.1f})")
                if ent['enc_component']:
                    print(f"      Component: 0x{ent['enc_component']:016x} -> 0x{ent['dec_component']:016x}")
        
        print("-" * 80)
        print(f"[+] Found {found} entities")
    
    def monitor_health(self, slot: int = 0, interval: float = 0.5):
        """Monitor health of entity in slot"""
        print(f"\n[*] Monitoring slot {slot} (Ctrl+C to stop)...")
        try:
            while True:
                ent = self.read_entity(slot)
                if ent:
                    x, y, z = ent['pos']
                    print(f"\rHP: {ent['health']:6.1f} | Pos: ({x:7.1f}, {y:7.1f}, {z:7.1f})", end='', flush=True)
                else:
                    print(f"\rSlot {slot} empty", end='', flush=True)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Stopped")
    
    def test_decrypt(self):
        """Test decryption by reading known encrypted pointers"""
        print("\n[*] Testing decryption...")
        
        # Read entity_admin and try to decrypt pointers
        admin = self.get_entity_admin()
        print(f"entity_admin: 0x{admin:x}")
        
        entity_list = self.get_entity_list()
        print(f"entity_list:  0x{entity_list:x}")
        
        if entity_list:
            # Read first entity
            ent_ptr = self.read_u64(entity_list)
            print(f"entity[0]:    0x{ent_ptr:x}")
            
            if ent_ptr:
                enc = self.read_u64(ent_ptr + 0x28)
                dec = self.decrypt(enc)
                print(f"  +0x28 enc:  0x{enc:016x}")
                print(f"  +0x28 dec:  0x{dec:016x}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nError: Please provide the C constant!")
        print("Get it from host: C = RCX ^ RAX at thunk breakpoint")
        sys.exit(1)
    
    # Parse C constant
    C = int(sys.argv[1], 16) if sys.argv[1].startswith('0x') else int(sys.argv[1])
    print(f"[*] Using C = 0x{C:016x}")
    
    reader = OverwatchReader(C)
    
    if not reader.attach():
        sys.exit(1)
    
    # Menu
    while True:
        print("\n=== Overwatch Decryption Tool ===")
        print("1. Scan entities")
        print("2. Monitor entity health")
        print("3. Test decryption")
        print("4. Decrypt single value")
        print("5. Exit")
        
        try:
            choice = input("\nChoice: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
            
        if choice == '1':
            reader.scan_entities()
        elif choice == '2':
            slot = int(input("Slot number: "))
            reader.monitor_health(slot)
        elif choice == '3':
            reader.test_decrypt()
        elif choice == '4':
            val = input("Encrypted value (hex): ")
            enc = int(val, 16) if val.startswith('0x') else int(val, 16)
            dec = reader.decrypt(enc)
            print(f"Decrypted: 0x{dec:016x}")
        elif choice == '5':
            break
    
    print("[*] Bye!")


if __name__ == '__main__':
    main()
