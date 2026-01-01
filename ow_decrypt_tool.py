"""
Overwatch Pointer Decryption Tool v2
Run inside Windows VM to read and decrypt Overwatch memory

Usage:
    python ow_decrypt_tool.py <C_CONSTANT>
    
Example:
    python ow_decrypt_tool.py 0xb37673a668217138
"""

import ctypes
from ctypes import wintypes
import struct
import sys
import time

# Setup Windows API with proper 64-bit support
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

# Constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
LIST_MODULES_ALL = 0x03

# Setup function signatures for 64-bit
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,    # hProcess
    ctypes.c_uint64,    # lpBaseAddress (64-bit!)
    ctypes.c_void_p,    # lpBuffer
    ctypes.c_size_t,    # nSize
    ctypes.POINTER(ctypes.c_size_t)  # lpNumberOfBytesRead
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

# EnumProcessModulesEx for 64-bit
psapi.EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(ctypes.c_uint64),  # 64-bit module handles
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD
]
psapi.EnumProcessModulesEx.restype = wintypes.BOOL

psapi.GetModuleBaseNameW.argtypes = [
    wintypes.HANDLE,
    ctypes.c_uint64,
    wintypes.LPWSTR,
    wintypes.DWORD
]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD

psapi.EnumProcesses.argtypes = [
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)
]
psapi.EnumProcesses.restype = wintypes.BOOL

# Offsets
OFFSETS = {
    'entity_admin': 0x37EE2A0,
    'view_matrix': 0x400A2C8,
}

ENTITY = {
    'component_ptr': 0x28,
    'entity_id': 0x60,
    'rotation': 0x170,
    'position': 0x280,
    'health': 0x3c8,
}


class OverwatchReader:
    def __init__(self, C: int):
        self.C = C
        self.pid = None
        self.handle = None
        self.base = None
        
    def decrypt(self, encrypted: int) -> int:
        return self.C ^ encrypted
    
    def find_process(self) -> bool:
        pids = (wintypes.DWORD * 2048)()
        bytes_returned = wintypes.DWORD()
        
        if not psapi.EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(bytes_returned)):
            print("[-] EnumProcesses failed")
            return False
        
        num_pids = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
        
        for i in range(num_pids):
            pid = pids[i]
            if pid == 0:
                continue
                
            h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if h:
                name = ctypes.create_unicode_buffer(260)
                if psapi.GetModuleBaseNameW(h, 0, name, 260):
                    if 'Overwatch' in name.value:
                        self.pid = pid
                        kernel32.CloseHandle(h)
                        print(f"[+] Found Overwatch.exe PID: {pid}")
                        return True
                kernel32.CloseHandle(h)
        
        print("[-] Overwatch.exe not found")
        return False
    
    def attach(self) -> bool:
        if not self.find_process():
            return False
            
        self.handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 
            False, 
            self.pid
        )
        if not self.handle:
            print(f"[-] OpenProcess failed: {ctypes.get_last_error()}")
            return False
        
        # Get base address using EnumProcessModulesEx
        modules = (ctypes.c_uint64 * 1024)()
        needed = wintypes.DWORD()
        
        if psapi.EnumProcessModulesEx(
            self.handle, 
            modules, 
            ctypes.sizeof(modules), 
            ctypes.byref(needed),
            LIST_MODULES_ALL
        ):
            self.base = modules[0]
            print(f"[+] Base address: 0x{self.base:x}")
            return True
        else:
            print(f"[-] EnumProcessModulesEx failed: {ctypes.get_last_error()}")
            return False
    
    def read_bytes(self, addr: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()
        
        success = kernel32.ReadProcessMemory(
            self.handle,
            ctypes.c_uint64(addr),
            buf,
            size,
            ctypes.byref(bytes_read)
        )
        
        if success:
            return buf.raw
        return b'\x00' * size
    
    def read_u64(self, addr: int) -> int:
        data = self.read_bytes(addr, 8)
        return struct.unpack('<Q', data)[0]
    
    def read_u32(self, addr: int) -> int:
        data = self.read_bytes(addr, 4)
        return struct.unpack('<I', data)[0]
    
    def read_float(self, addr: int) -> float:
        data = self.read_bytes(addr, 4)
        return struct.unpack('<f', data)[0]
    
    def read_vec3(self, addr: int) -> tuple:
        data = self.read_bytes(addr, 12)
        return struct.unpack('<fff', data)
    
    def get_entity_admin(self) -> int:
        addr = self.base + OFFSETS['entity_admin']
        return self.read_u64(addr)
    
    def get_entity_list(self) -> int:
        admin = self.get_entity_admin()
        if admin == 0:
            return 0
        return self.read_u64(admin)
    
    def read_entity(self, slot: int) -> dict:
        entity_list = self.get_entity_list()
        if entity_list == 0:
            return None
            
        slot_addr = entity_list + (slot * 16)
        entity_ptr = self.read_u64(slot_addr)
        
        if entity_ptr == 0:
            return None
        
        entity_id = self.read_u64(entity_ptr + ENTITY['entity_id'])
        
        # Check valid entity prefix
        if (entity_id >> 48) != 0x0a50:
            return None
        
        pos = self.read_vec3(entity_ptr + ENTITY['position'])
        health = self.read_float(entity_ptr + ENTITY['health'])
        
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
        print(f"\n[*] Scanning {max_slots} entity slots...")
        print("-" * 80)
        
        # First check if we can read entity_admin
        admin = self.get_entity_admin()
        print(f"[*] entity_admin ptr: 0x{admin:x}")
        
        entity_list = self.get_entity_list()
        print(f"[*] entity_list ptr:  0x{entity_list:x}")
        
        if entity_list == 0:
            print("[-] Entity list is null - may need different offsets")
            return
        
        found = 0
        for i in range(max_slots):
            ent = self.read_entity(i)
            if ent:
                found += 1
                x, y, z = ent['pos']
                print(f"[{i:3}] HP={ent['health']:6.1f} Pos=({x:8.1f}, {y:8.1f}, {z:8.1f})")
        
        print("-" * 80)
        print(f"[+] Found {found} entities")
    
    def dump_memory(self, addr: int, size: int = 64):
        """Hex dump memory at address"""
        print(f"\n[*] Memory at 0x{addr:x}:")
        data = self.read_bytes(addr, size)
        for i in range(0, len(data), 16):
            hex_str = ' '.join(f'{b:02x}' for b in data[i:i+16])
            print(f"  +0x{i:03x}: {hex_str}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nError: Provide C constant!")
        print("Example: python ow_decrypt_tool.py 0xb37673a668217138")
        sys.exit(1)
    
    C = int(sys.argv[1], 16) if sys.argv[1].startswith('0x') else int(sys.argv[1])
    print(f"[*] C = 0x{C:016x}")
    
    reader = OverwatchReader(C)
    
    if not reader.attach():
        sys.exit(1)
    
    while True:
        print("\n=== Menu ===")
        print("1. Scan entities")
        print("2. Dump memory at address")
        print("3. Decrypt value")
        print("4. Exit")
        
        try:
            choice = input("\nChoice: ").strip()
        except:
            break
            
        if choice == '1':
            reader.scan_entities()
        elif choice == '2':
            addr = input("Address (hex): ")
            addr = int(addr, 16) if addr.startswith('0x') else int(addr, 16)
            reader.dump_memory(addr)
        elif choice == '3':
            val = input("Value (hex): ")
            enc = int(val, 16)
            print(f"Decrypted: 0x{reader.decrypt(enc):016x}")
        elif choice == '4':
            break
    
    print("[*] Bye!")


if __name__ == '__main__':
    main()
