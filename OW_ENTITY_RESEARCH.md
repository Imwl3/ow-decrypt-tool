# Overwatch Entity System Research

**Last Verified:** Session PID 5648, Base 0x7ff76fe00000, IDA Base 0x7ff6413f0000

## 🎯 Quick Reference

**Entity enumeration is SIMPLE - slot array is NOT encrypted!**

| What You Need | Offset from Base | Type |
|---------------|------------------|------|
| Slot array pointer | `+0x37EE2A0` | u64 VA |
| Active entity count | `+0x37EE290` | u32 |
| Max entities | 2048 slots | - |
| Slot size | 16 bytes | - |

**Each slot (16 bytes):**
- `+0x00`: entity_ptr (u64) - **NOT ENCRYPTED** ✅
- `+0x08`: flags (u32)
- `+0x0C`: next_free (u32)

**Each entity object:**
- `+0x80`: component_array_ptr (u64 pointing to **ENCRYPTED** pointers) ❌
- `+0x88`: component_count (u32) ✅
- `+0x110`: component_bitmask0 (u64) ✅
- `+0x118`: component_bitmask1 (u64) ✅
- `+0x120`: component_bitmask2 (u64) ✅
- `+0x134`: entity_id (u32) ✅

**Key Insight:** The entity slot array and entity objects are plaintext. Only component pointers require VMP thunk decryption.

---

## IDA Database Info
- **File**: Overwatch_dump.exe
- **Base**: 0x7ff6413f0000
- **Size**: 0x459f000

---

## Key Globals (offset from base)

| Global | Offset | Description |
|--------|--------|-------------|
| `g_ow_entity_slots_ptr` | 0x37EE2A0 | Pointer to entity slot array |
| `g_ow_entity_count` | 0x37EE290 | Active entity count (u32) |
| `g_ow_entity_admin_flags_count` | 0x37EE288 | Flags + max count |
| `g_ow_entity_admin` | 0x37EE280 | Entity admin vtable |
| `g_ow_xor_obfuscation_key` | 0x3646851 | XOR key (usually 0x92) |
| `g_ow_decrypt_context_ptr` | 0x3947AF8 | Decrypt context table |
| `g_ow_component_type_registry` | 0x3F07880 | Component type registry (32 bytes per type) ✅ VERIFIED |
| `decrypt_thunk` | 0x523290 | VMP thunk for decryption |

---

## Entity Slot Array Structure (16 bytes each)

```
+0x00: entity_ptr     (u64) - Pointer to entity object
+0x08: flags          (u32) - Entity flags
+0x0C: next_free      (u32) - Freelist next index
```

Max entities: 2048 (0x800)

---

## Entity Object Structure

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x80 | 8 | component_array | Pointer to encrypted component pointers ✅ VERIFIED |
| 0x88 | 4 | component_count | Number of components (value 4 observed) ✅ VERIFIED |
| 0x8C | 4 | component_capacity | Array capacity (0x80000010 observed) |
| 0x110 | 8 | component_bitmask0 | Which component types present (0x8000a observed) ✅ VERIFIED |
| 0x118 | 8 | component_bitmask1 | Component types (bits 64-127) ✅ VERIFIED |
| 0x120 | 8 | component_bitmask2 | Component types (bits 128-191) |
| 0x130 | 4 | component_counts | 4 bytes of running counts |
| 0x134 | 4 | entity_handle | Entity handle (0x4cd, 0xcdc observed) ✅ VERIFIED |
| 0x138 | 4 | entity_id | Entity ID (0xd2, 0x197 observed) ✅ VERIFIED |

---

## Component Pointer Decryption

From `ow_component_read_by_index` @ base+0x2EB0B30:

```c
// Step 1: Read encrypted value
encrypted = component_array[index]

// Step 2: Bit rotations
temp = ROR64(encrypted, 3)
temp = ROL64(temp, 23)

// Step 3: Add constant
temp = temp + 0x77D1EEE9B57BB5D7

// Step 4: XOR with obfuscation key
temp = temp ^ g_ow_xor_obfuscation_key  // Usually 0x92

// Step 5: Call ow_ptr_encrypt_rol28 (transforms value)
temp = ow_ptr_encrypt_rol28(temp)

// Step 6: XOR with constant
temp = temp ^ 0xD4AAE416F53FAE18

// Step 7: Call VMP thunk (ow_loader_decrypt_thunk)
thunk_result = ow_loader_decrypt_thunk(temp)

// Step 8: Final transform
result = (thunk_result + 0x246F476B55B569AA) ^ decrypt_context[0x17F]
```

**Key constants:**
- 0x77D1EEE9B57BB5D7
- 0xD4AAE416F53FAE18
- 0x246F476B55B569AA
- 0x2E5D1C5A009DFD9B
- decrypt_context offset: 0x17F (383)

---

## Component Type Registry Structure (32 bytes per entry)

```
+0x00: constructor_fn   (u64) - Function to create component
+0x08: another_fn       (u64) - Another function pointer
+0x10: unknown          (u64)
+0x18: component_size   (u32) - Size of component data
+0x1C: padding          (u32)
```

### Known Component Types (from registry analysis):
- Type 1: size 0x300 (768 bytes)
- Type 3: size 0x5C0 (1472 bytes)
- Type 4: size 0xAD0 (2768 bytes)
- Type 5: size 0x140 (320 bytes)
- Type 6: size 0x80 (128 bytes)
- Type 7: size 0x68 (104 bytes)
- Type 12: size 0x130 (304 bytes)

### Registered Component Names:
- "Model" (type 18)
- "ModelVertexData" (type 39)
- "Fracturable" (type 33)
- "Skeleton" (type 20)
- "Material" (type 2)
- "MaterialData" (type 1)
- "MapShadowData" (type 32)

---

## Render Entity Structure (passed to render handlers)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x38 | 8 | data_flags | Flags |
| 0x40 | 4 | flags0 | More flags |
| 0x48 | 4 | flags1 | Additional flags |
| 0x4C | 2 | type_info | Type info word |
| 0x4E | 1 | render_type | 4=normal, 6=special, 7=special, 9=shadow |
| 0x50 | 1 | some_byte | Unknown |
| 0x58 | 8 | render_data_ptr | Pointer to render data |
| 0x120 | - | uv_data | UV/texture coords |
| 0x12C | 4 | some_dword | At +300 |
| 0x2B8 | 8 | player_info_ptr | Pointer to player info struct |
| 0x2C0 | 8 | texture_id1 | Texture handle |
| 0x2C8 | 8 | texture_id2 | Another texture |
| 0x2D0 | 8 | texture_id3 | Third texture |
| 0x2D8 | 4 | frame_index | Frame counter |
| 0x2E4 | 2 | team_index | Team index value |
| 0x2E8 | 4 | team_id | Team ID |
| 0x2EC | 4 | bounds_min_x | Float - min X |
| 0x2F0 | 4 | bounds_min_y | Float - min Y |
| 0x2F4 | 4 | bounds_max_x | Float - max X |
| 0x2F8 | 4 | bounds_max_y | Float - max Y |
| 0x2FC | 1 | flag1 | Some flag |
| 0x2FD | 1 | flag2 | Another flag |
| 0x2FF | 1 | is_ally | Is ally (byte) |
| 0x300 | 1 | is_enemy | Is enemy (byte) |
| 0x301 | 1 | flag3 | Flag |
| 0x30C | 1 | flag4 | Flag |

---

## Player Info Structure (at render_entity + 0x2B8)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0x20 | 8 | some_ptr | Some pointer |
| 0x54 | 4 | frame_counter1 | Frame counter |
| 0x58 | 4 | frame_counter2 | Frame counter 2 |
| 0x68 | 8 | texture1 | Texture handle |
| 0x70 | 8 | texture2 | Texture handle 2 |
| 0x88 | 1 | team_byte | Team ID byte |
| 0x89 | 1 | is_friendly | Is friendly flag |
| 0x8A | 1 | something | Unknown |
| 0x8C | 1 | ally_flag1 | Ally related |
| 0x8D | 1 | ally_flag2 | Ally related |
| 0xA4 | 4 | some_index | Some index |
| 0xA8 | 1 | special | Special byte |

---

## Key Functions

| Function | Address (offset) | Description |
|----------|-----------------|-------------|
| ow_entity_spawn | 0x2EA3A90 | Creates new entity |
| ow_entity_create | 0x2EA7F70 | Registers entity in slots |
| ow_entity_destroy | 0x2EA4BE0 | Destroys entity |
| ow_entity_update | 0x2EA64E0 | Updates entity |
| ow_entity_admin_init | 0x2EA4540 | Initializes entity system |
| ow_entity_component_handler | 0x2EA6290 | Handles components |
| ow_entity_component_decrypt | 0x2EB1B80 | Decrypts component array |
| ow_component_read_by_index | 0x2EB0B30 | Reads single component |
| ow_component_array_decrypt_iterate | 0x2EAF970 | Iterates and decrypts |
| ow_entity_render_dispatcher | 0x31AF240 | Main render dispatch |
| ow_entity_render_type6_handler | 0x3192C00 | Type 6 render |
| ow_entity_render_type7_handler | 0x31946B0 | Type 7 render |
| ow_is_enemy_team | 0x3095790 | Checks if entity is enemy |
| ow_team_render_handler | 0x3099FA0 | Team-specific rendering |
| ow_health_component_create | 0x1B6B8D0 | Creates health component |
| ow_health_data_init | 0x1B6AC70 | Initializes health data |
| ow_loader_decrypt_thunk | 0x1913290 | VMP decrypt thunk |
| ow_loader_decrypt_init_thunk | 0x19132B0 | VMP init thunk |
| ow_ptr_encrypt_rol28 | 0x1915350 | Pointer encryption |
| ow_ptr_decrypt_ror28 | 0x1915630 | Pointer decryption |

---

## ow_is_enemy_team Logic

```c
bool ow_is_enemy_team(__int64 player_info) {
    return player_info[768] && !player_info->field_696[137];
}
```

---

## Health Component Structure

From `ow_health_component_create`:
- Size: 48 bytes allocated
- vtable at offset 0
- Health data initialized at offset +16 with capacity 1400
- Some string data at offset +1320

---

## Render Dispatch Flow

1. `ow_entity_render_dispatcher` @ base+0x31AF240
2. Iterates entity list at render_context+2584 (0xA18)
3. For each entity in the list at render_context+2584:
   - v13 = entity pointer from list
   - v14 = flags from entity+56 (0x38)
   - render_type = *(entity+78) [offset 0x4E]

4. Dispatches to type-specific handler:
   - Type 4: Normal entity render (sub_7FF643196420)
   - Type 6: `ow_entity_render_type6_handler`
   - Type 7: `ow_entity_render_type7_handler`
   - Type 9: Shadow casting

5. Calls `ow_is_enemy_team` to determine team status:
   ```c
   // player_info at offset 5384 (0x1508) from some context
   player_info = context[5384]
   if (player_info && player_info[771] && (player_info[767] || ow_is_enemy_team(player_info)))
   ```

---

## ow_is_enemy_team Detailed Analysis

```c
// player_info structure key offsets:
// +767 (0x2FF): is_ally flag
// +768 (0x300): is_enemy flag
// +771 (0x303): some_active_flag
// +772 (0x304): team_byte

bool ow_is_enemy_team(__int64 player_info) {
    return player_info[768] && !player_info[767+137]; // Actually checks offset 904
}
```

---

## Entity Spawn Flow (ow_entity_spawn)

1. Get component constructor from registry: `g_ow_component_type_registry + 32*type + 8`
2. Calculate total entity size (base 336 bytes + aligned component sizes)
3. Allocate entity memory with 16-byte alignment
4. Call `ow_entity_create` to register in slot array
5. Set up component bitmasks at entity+272, entity+280, entity+288
6. Encrypt component pointers using reverse of decrypt chain:
   ```c
   encrypted = ROL3(ROR23((value ^ 0x92) - 0x77D1EEE9B57BB5D7), 3)
   ```
7. Calculate component counts using popcount on bitmasks

---

## Component Bitmask Calculation

Components use popcount (population count) to determine array indices:
```c
// Check if component type N exists:
bitmask_index = N >> 6;  // Which 64-bit word
bit = 1ULL << (N & 0x3F);  // Which bit
has_component = (entity->component_bitmask[bitmask_index] & bit) != 0;

// Get component array index:
prior_bits = bitmask & (bit - 1);
index = popcount64(prior_bits) + entity->component_counts[bitmask_index];
```

---

## Render Context Structure

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0xA10 | 8 | render_data_ptr | Pointer to render data |
| 0xA18 | 8 | entity_list | Current entity render list |
| 0xA20 | 4 | entity_count | Number of entities in list |
| 0xA28 | 8 | render_output | Render output buffer |

---

## TODO: Still Need

1. ~~Position/Transform Component~~: **Component positions are encrypted, but render entity has bounds at +0x2EC-0x2F8**
2. ~~Live Memory Reading~~: **Use render entity bounds instead of decrypted components**
3. **Training Range Test**: Verify 12 entities can be enumerated

---

## CRITICAL FINDING: Slot Array is NOT Encrypted

**PROOF from ow_entity_create @ base+0x2EA7F70:**

```asm
; At offset 0x2EA80A1:
add     r8, cs:g_ow_entity_slots_ptr   ; r8 = slot address
mov     [r8], rdi                      ; Write entity pointer DIRECTLY - NO ENCRYPTION!
inc     dword ptr cs:g_ow_entity_count ; Increment count
```

The entity pointer is written with a simple `mov [r8], rdi` instruction.

### What IS Encrypted ❌
- **Component pointers** at entity+0x80 (requires VMP thunk)
- Individual component data structures

### What is NOT Encrypted ✅

| Data | Location | Access |
|------|----------|--------|
| Slot array base pointer | `g_ow_entity_slots_ptr` @ base+0x37EE2A0 | Direct read (u64) |
| Active entity count | `g_ow_entity_count` @ base+0x37EE290 | Direct read (u32) |
| **Entity pointers in slots** | `slot[i]+0x00` | **Direct read (u64)** |
| Slot flags | `slot[i]+0x08` | Direct read (u32) |
| Freelist next | `slot[i]+0x0C` | Direct read (u32) |
| Entity ID | `entity+0x134` | Direct read (u32) |
| Entity handle | `entity+0x138` | Direct read (u32) |
| Component bitmask 0 | `entity+0x110` | Direct read (u64) |
| Component bitmask 1 | `entity+0x118` | Direct read (u64) |
| Component bitmask 2 | `entity+0x120` | Direct read (u64) |
| Component count | `entity+0x88` | Direct read (u32) |
| Component capacity | `entity+0x8C` | Direct read (u32) |

---

## Entity Enumeration Algorithm

### Step 1: Read Globals
```c
QEMU_PID = get_qemu_pid()
RAM_BASE = find_guest_ram_base(QEMU_PID)
OW_BASE_PA = get_overwatch_base_pa()  // From EPROCESS+0x2B0

// Read entity system globals
slots_ptr_va = read_u64(RAM_BASE + OW_BASE_PA + 0x37EE2A0)
entity_count = read_u32(RAM_BASE + OW_BASE_PA + 0x37EE290)
max_count = read_u32(RAM_BASE + OW_BASE_PA + 0x37EE288) >> 32  // Upper 32 bits
```

### Step 2: Translate Slot Array VA to PA
```c
// Walk CR3 page tables to translate slots_ptr_va to physical address
slots_ptr_pa = va_to_pa(CR3, slots_ptr_va)
```

### Step 3: Enumerate Entities
```c
for (slot_index = 0; slot_index < 2048; slot_index++) {
    slot_offset = slots_ptr_pa + (slot_index * 16)

    // Read slot structure (16 bytes)
    entity_ptr_va = read_u64(RAM_BASE + slot_offset + 0)
    flags = read_u32(RAM_BASE + slot_offset + 8)
    next_free = read_u32(RAM_BASE + slot_offset + 12)

    // Skip empty slots
    if (entity_ptr_va == 0) continue

    // Translate entity VA to PA
    entity_pa = va_to_pa(CR3, entity_ptr_va)

    // Read entity structure
    entity_id = read_u32(RAM_BASE + entity_pa + 0x134)
    component_count = read_u32(RAM_BASE + entity_pa + 0x88)
    bitmask0 = read_u64(RAM_BASE + entity_pa + 0x110)
    bitmask1 = read_u64(RAM_BASE + entity_pa + 0x118)
    bitmask2 = read_u64(RAM_BASE + entity_pa + 0x120)

    // Note: component_array at entity+0x80 points to ENCRYPTED pointers
    // Cannot decrypt without calling VMP thunk

    print(f"Entity {entity_id} at slot {slot_index}")
    print(f"  Components: {component_count}")
    print(f"  Bitmasks: 0x{bitmask0:x} 0x{bitmask1:x} 0x{bitmask2:x}")
}
```

### Step 4: Alternative - Use Render Entity Bounds
Since component pointers are encrypted, use render entity bounds for position:
- Render entities are populated during the render pass
- Position bounds at render_entity+0x2EC through +0x2F8 (floats)
- Team info at render_entity+0x2FF and +0x300

---

## Memory Layout Summary

```
g_ow_entity_slots_ptr (VA) ────┐
                               │
                               ▼
┌─────────────────────────────────────┐
│ Slot Array (32KB = 2048 * 16 bytes) │ ◄── NOT ENCRYPTED
├─────────────────────────────────────┤
│ Slot 0:  [entity_ptr | flags | next]│
│ Slot 1:  [entity_ptr | flags | next]│
│ Slot 2:  [entity_ptr | flags | next]│
│ ...                                  │
│ Slot 2047: [entity_ptr | flags | next]│
└─────────────────────────────────────┘
         │
         └─────> entity_ptr (VA) ────┐
                                     │
                                     ▼
              ┌─────────────────────────────────┐
              │ Entity Object                   │ ◄── NOT ENCRYPTED
              ├─────────────────────────────────┤
              │ +0x80: component_array (ptr)    │ ──┐
              │ +0x88: component_count          │   │
              │ +0x8C: component_capacity       │   │
              │ +0x110: component_bitmask0      │   │
              │ +0x118: component_bitmask1      │   │
              │ +0x120: component_bitmask2      │   │
              │ +0x130: component_counts        │   │
              │ +0x134: entity_id               │   │
              │ +0x138: entity_handle           │   │
              └─────────────────────────────────┘   │
                                     │              │
                                     ▼              │
              ┌─────────────────────────────────┐◄──┘
              │ Component Pointer Array         │
              ├─────────────────────────────────┤
              │ [0]: encrypted_ptr ────────────────> Component 0 (ENCRYPTED)
              │ [1]: encrypted_ptr ────────────────> Component 1 (ENCRYPTED)
              │ [2]: encrypted_ptr ────────────────> Component 2 (ENCRYPTED)
              │ ...                              │
              └─────────────────────────────────┘
```

---

## Testing Checklist

- [x] Read g_ow_entity_slots_ptr from base+0x37EE2A0 ✅ VERIFIED
- [x] Read g_ow_entity_count from base+0x37EE290
- [ ] Verify count matches training range (12 entities expected)
- [x] Enumerate slots and find non-NULL entity pointers ✅ VERIFIED (found heap ptrs 0x1cc..., 0x1ca...)
- [x] Read entity IDs from entity+0x134 ✅ VERIFIED (0xd2, 0x197)
- [x] Read component bitmasks to identify component types ✅ VERIFIED (0x8000a)
- [x] Verify bitmask popcount matches component_count ✅ VERIFIED (count=4)

---

## Usage Notes

**Simple enumeration without decryption:**
1. Get QEMU PID and RAM base
2. Read `g_ow_entity_slots_ptr` @ base+0x37EE2A0 to get slot array VA
3. Use GDB breakpoint on thunk to access virtual memory in process context
4. For each slot (0-2047), read entity_ptr at slot+0
5. If entity_ptr != 0, read entity structure at that VA
6. Entity ID, bitmasks, counts are all plaintext

**Component access requires:**
- Component pointers at entity+0x80 are ENCRYPTED
- Values like 0x939fdbaca7e379f7 need full decryption chain
- Alternative: Use render entity bounds at +0x2EC-0x2F8 for position

**NOTE:** CR3 page table walking from host doesn't work (PML4 returns zeros).
Must use GDB with breakpoint on decrypt thunk for virtual memory access.
