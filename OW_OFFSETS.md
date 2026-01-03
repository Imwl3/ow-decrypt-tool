# Overwatch 2 Offsets & Component Reading Guide

## Global Offsets (from Overwatch.exe base)

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x37EE2A0 | ptr | `g_entity_slots_ptr` | Pointer to entity slot array |
| +0x37EE290 | u32 | `g_entity_count` | Active entity count |
| +0x37EE28C | u32 | `g_entity_capacity` | Max entity slots |
| +0x3947AF8 | ptr | `g_context_ptr` | Decrypt context (read +0x17F for ctx_xor) |
| +0x3646851 | u8 | `g_xor_key` | XOR obfuscation key (usually 0x92) |
| +0x523290 | func | `decrypt_thunk` | VMP decrypt function |

---

## Entity Slot Array

**Location:** `*(base + 0x37EE2A0)`

Each slot is 16 bytes:

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x00 | ptr | entity_ptr | Pointer to entity (0 = empty) |
| +0x08 | u32 | flags | Entity type flags |
| +0x0C | u32 | next_free | 0xFFFFFFFF = active, else freelist index |

**Active entity check:**
```cpp
bool IsActiveSlot(Slot* slot) {
    return slot->entity_ptr != 0 && slot->next_free == 0xFFFFFFFF;
}
```

---

## Entity Structure

| Offset | Type | Name | Description |
|--------|------|------|-------------|
| +0x80 | ptr | component_array | Pointer to ENCRYPTED component pointers |
| +0x88 | u32 | component_count | Number of components |
| +0x8C | u32 | component_capacity | Array capacity |
| +0x110 | u64 | bitmask0 | Component types 0-63 present |
| +0x118 | u64 | bitmask1 | Component types 64-127 present |
| +0x120 | u64 | bitmask2 | Component types 128-191 present |
| +0x134 | u32 | entity_handle | Entity handle |
| +0x138 | u32 | entity_id | Unique entity ID |

---

## Component Type IDs

| Type | Hex | Name | Which Entity |
|------|-----|------|--------------|
| 1 | 0x01 | MaterialData | - |
| 4 | 0x04 | **Model** | ComponentParent |
| 22 | 0x16 | ContactSet | - |
| 25 | 0x19 | DataFlow | Both |
| 26 | 0x1A | VoiceSet | - |
| 32 | 0x20 | Lerp | - |
| 33 | 0x21 | **Team** | ComponentParent |
| 35 | 0x23 | MirroredIdleAnim | - |
| 36 | 0x24 | Movement | - |
| 37 | 0x25 | BattleTag | - |
| 39 | 0x27 | Skeleton | - |
| 45 | 0x2D | CaptureArea | - |
| 47 | 0x2F | Rotation | ComponentParent |
| 50 | 0x32 | LocalIdleAnim | - |
| 52 | 0x34 | **Link** | LinkParent |
| 53 | 0x35 | **Visibility** | LinkParent |
| 54 | 0x36 | FirstPerson | - |
| 55 | 0x37 | Skill | Both |
| 57 | 0x39 | Weapon | - |
| 58 | 0x3A | ProjectileVisual | - |
| 59 | 0x3B | **Health** | ComponentParent |
| 67 | 0x43 | **PlayerController** | ComponentParent |
| 84 | 0x54 | **HeroID** | LinkParent |
| 85 | 0x55 | TargetTag | Both |
| 88 | 0x58 | FallingDamage | - |
| 90 | 0x5A | ImpactEffectOverride | - |
| 91 | 0x5B | Outline | - |
| 95 | 0x5F | AIBehavior | LinkParent |
| 114 | 0x72 | Escort | - |
| 131 | 0x83 | HeroSpec | - |

---

## Component-Specific Offsets

### Model Component (Type 0x04)

| Offset | Type | Name |
|--------|------|------|
| +0x50 | Vec3 | Velocity |
| +0xC8 | ptr | HitboxData |
| +0x200 | Vec3 | **Position** |
| +0x8B0 | ptr | BoneData |

```cpp
Vec3 GetPosition(uintptr_t modelComp) {
    return *(Vec3*)(modelComp + 0x200);
}

Vec3 GetVelocity(uintptr_t modelComp) {
    return *(Vec3*)(modelComp + 0x50);
}
```

### Health Component (Type 0x3B)

| Offset | Type | Name |
|--------|------|------|
| +0xDC | float | HealthMax |
| +0xE0 | float | Health |
| +0x220 | float | Armor |
| +0x360 | float | Barrier |
| +0x4A8 | bool | IsInvincible |
| +0x4A9 | bool | IsImmortal |

```cpp
float GetHealth(uintptr_t healthComp) {
    float hp = *(float*)(healthComp + 0xE0);
    float armor = *(float*)(healthComp + 0x220);
    float barrier = *(float*)(healthComp + 0x360);
    return hp + armor + barrier;
}

bool IsAlive(uintptr_t healthComp) {
    return GetHealth(healthComp) > 0.0f;
}
```

### HeroID Component (Type 0x54)

| Offset | Type | Name |
|--------|------|------|
| +0xD0 | u16 | HeroID |

```cpp
uint16_t GetHeroID(uintptr_t heroComp) {
    return *(uint16_t*)(heroComp + 0xD0);
}
```

### Team Component (Type 0x21)

| Offset | Type | Name |
|--------|------|------|
| +0x58 | u32 | TeamFlags |

```cpp
uint32_t GetTeamID(uintptr_t teamComp) {
    return *(uint32_t*)(teamComp + 0x58) & 0xF800000;
}
```

### PlayerController Component (Type 0x43)

| Offset | Type | Name |
|--------|------|------|
| +0x11BC | ? | Key |
| +0x1200 | Vec3 | ViewAngle |
| +0x2188 | float | Sensitivity |

### Visibility Component (Type 0x35)

| Offset | Type | Name |
|--------|------|------|
| +0x98 | u64 | VisKey2 |
| +0xA0 | u64 | VisKey1 |

```cpp
bool IsVisible(uintptr_t visComp) {
    uint64_t k2 = *(uint64_t*)(visComp + 0x98);
    return k2 != 0;
}
```

### Link Component (Type 0x34)

| Offset | Type | Name |
|--------|------|------|
| +0xD4 | u32 | UniqueID |
| +0x134 | Vec3 | Rotation |

### Rotation Component (Type 0x2F)

| Offset | Type | Name |
|--------|------|------|
| +0x7B0 | ptr | RotationPtr |

```cpp
Vec3 GetRotation(uintptr_t rotComp) {
    uintptr_t rotPtr = *(uintptr_t*)(rotComp + 0x7B0);
    if (!rotPtr) return {0,0,0};
    return *(Vec3*)(rotPtr + 0x8FC);
}
```

---

## How to Read Components

### Step 1: Check if entity has component (bitmask)

```cpp
bool HasComponent(uintptr_t entity, uint8_t typeID) {
    uint64_t bitmask;
    if (typeID < 64) {
        bitmask = *(uint64_t*)(entity + 0x110);
        return (bitmask & (1ULL << typeID)) != 0;
    } else if (typeID < 128) {
        bitmask = *(uint64_t*)(entity + 0x118);
        return (bitmask & (1ULL << (typeID - 64))) != 0;
    } else {
        bitmask = *(uint64_t*)(entity + 0x120);
        return (bitmask & (1ULL << (typeID - 128))) != 0;
    }
}
```

### Step 2: Get component index from bitmask

```cpp
int GetComponentIndex(uintptr_t entity, uint8_t typeID) {
    if (!HasComponent(entity, typeID)) return -1;

    uint64_t bm0 = *(uint64_t*)(entity + 0x110);
    uint64_t bm1 = *(uint64_t*)(entity + 0x118);
    uint64_t bm2 = *(uint64_t*)(entity + 0x120);

    int index = 0;

    if (typeID < 64) {
        uint64_t mask = (1ULL << typeID) - 1;
        index = __popcnt64(bm0 & mask);
    } else if (typeID < 128) {
        index = __popcnt64(bm0);
        uint64_t mask = (1ULL << (typeID - 64)) - 1;
        index += __popcnt64(bm1 & mask);
    } else {
        index = __popcnt64(bm0) + __popcnt64(bm1);
        uint64_t mask = (1ULL << (typeID - 128)) - 1;
        index += __popcnt64(bm2 & mask);
    }

    return index;
}
```

### Step 3: Read encrypted pointer from component array

```cpp
uintptr_t GetComponentArray(uintptr_t entity) {
    uintptr_t arr = *(uintptr_t*)(entity + 0x80);
    // First 16 bytes are header: [pool_ptr, count/flags]
    return *(uintptr_t*)arr;  // Return actual pool pointer
}

uint64_t GetEncryptedComponent(uintptr_t entity, int index) {
    uintptr_t pool = GetComponentArray(entity);
    return *(uint64_t*)(pool + index * 8);
}
```

### Step 4: Decrypt component pointer

```cpp
inline uint64_t ror64(uint64_t val, int n) {
    return (val >> n) | (val << (64 - n));
}

inline uint64_t rol64(uint64_t val, int n) {
    return (val << n) | (val >> (64 - n));
}

uintptr_t DecryptComponent(uint64_t encrypted, uint64_t C, uint64_t ctx_xor) {
    uint64_t v = encrypted;

    // Step 1-2: Rotations
    v = ror64(v, 3);
    v = rol64(v, 23);

    // Step 3-4: Add and XOR
    v += 0x77D1EEE9B57BB5D7ULL;
    v ^= 0x92;  // g_xor_key

    // Step 5: ROL28 transform
    v = rol64(v, 28);
    v += 0x5C2713451FEB52FAULL;
    v ^= 0x1F4723AC9E4C34DDULL;

    // Step 6-7: More XORs
    v ^= 0xD4AAE416F53FAE18ULL;
    v ^= C;  // Session constant from thunk

    // Step 8-9: Final transform
    v += 0x246F476B55B569AAULL;
    v ^= ctx_xor;  // From *(*(base + 0x3947AF8) + 0x17F)

    return (uintptr_t)v;
}
```

### Step 5: Complete GetComponent function

```cpp
uintptr_t GetComponent(uintptr_t entity, uint8_t typeID, uint64_t C, uint64_t ctx_xor) {
    int index = GetComponentIndex(entity, typeID);
    if (index < 0) return 0;

    uint64_t encrypted = GetEncryptedComponent(entity, index);
    if (encrypted == 0) return 0;

    return DecryptComponent(encrypted, C, ctx_xor);
}
```

---

## Entity Pairing System

Heroes consist of TWO linked entities:

| Entity | Has Components | Purpose |
|--------|----------------|---------|
| **ComponentParent** | Model, Health, Team, Rotation, Skill | Main game entity |
| **LinkParent** | HeroID, Visibility, Link, TargetTag | Hero data entity |

### Finding Linked Entity

```cpp
// Entity+0x138 contains link info
// 0x800000XX = forward link to slot XX
// 0xC00000XX = back link to slot XX

uint32_t GetLinkedSlot(uintptr_t entity) {
    uint32_t linkVal = *(uint32_t*)(entity + 0x138);
    if ((linkVal & 0xFF000000) == 0x80000000 ||
        (linkVal & 0xFF000000) == 0xC0000000) {
        return linkVal & 0xFFFFFF;
    }
    return 0xFFFFFFFF;  // No link
}
```

### Reading a Full Player

```cpp
struct Player {
    uintptr_t ComponentParent;
    uintptr_t LinkParent;
    Vec3 Position;
    float Health;
    uint16_t HeroID;
    uint32_t TeamID;
    bool IsVisible;
};

bool ReadPlayer(uintptr_t entity, Player* out, uint64_t C, uint64_t ctx_xor) {
    // Check if this is a player entity (has Model + Health)
    if (!HasComponent(entity, 0x04) || !HasComponent(entity, 0x3B))
        return false;

    out->ComponentParent = entity;

    // Find linked entity for HeroID
    uint32_t linkedSlot = GetLinkedSlot(entity);
    if (linkedSlot != 0xFFFFFFFF) {
        uintptr_t slots = *(uintptr_t*)(g_base + 0x37EE2A0);
        out->LinkParent = *(uintptr_t*)(slots + linkedSlot * 16);
    }

    // Read Model component for position
    uintptr_t model = GetComponent(entity, 0x04, C, ctx_xor);
    if (model) {
        out->Position = *(Vec3*)(model + 0x200);
    }

    // Read Health component
    uintptr_t health = GetComponent(entity, 0x3B, C, ctx_xor);
    if (health) {
        out->Health = *(float*)(health + 0xE0);
    }

    // Read HeroID from LinkParent
    if (out->LinkParent && HasComponent(out->LinkParent, 0x54)) {
        uintptr_t heroComp = GetComponent(out->LinkParent, 0x54, C, ctx_xor);
        if (heroComp) {
            out->HeroID = *(uint16_t*)(heroComp + 0xD0);
        }
    }

    // Read Team
    uintptr_t team = GetComponent(entity, 0x21, C, ctx_xor);
    if (team) {
        out->TeamID = *(uint32_t*)(team + 0x58) & 0xF800000;
    }

    // Read Visibility from LinkParent
    if (out->LinkParent && HasComponent(out->LinkParent, 0x35)) {
        uintptr_t vis = GetComponent(out->LinkParent, 0x35, C, ctx_xor);
        if (vis) {
            out->IsVisible = *(uint64_t*)(vis + 0x98) != 0;
        }
    }

    return true;
}
```

---

## Getting C Value (Session Constant)

C must be captured once per game session via GDB or DLL hook.

### Via GDB (from host)

```bash
OW_BASE=0x7ff67b810000  # Get from vm_fast_introspect.py
CR3=0x2e1cf0000         # Get from vm_fast_introspect.py
COMP_CALL=$((OW_BASE + 0x1AC0BA0))

sudo timeout 20 gdb -q -batch \
  -ex "set architecture i386:x86-64" \
  -ex "target remote localhost:1234" \
  -ex "set \$cr3 = $CR3" \
  -ex "hbreak *$COMP_CALL" \
  -ex "continue" \
  -ex "set \$in = \$rcx" \
  -ex "stepi" \
  -ex "finish" \
  -ex "printf \"C = 0x%llx\\n\", \$in ^ \$rax" \
  -ex "delete" \
  -ex "detach"
```

### Via DLL Hook (CalcC)

```cpp
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
```

---

## Quick Reference

```cpp
// Globals
#define OFF_SLOTS_PTR       0x37EE2A0
#define OFF_ENTITY_COUNT    0x37EE290
#define OFF_CONTEXT_PTR     0x3947AF8
#define OFF_XOR_KEY         0x3646851

// Entity offsets
#define ENT_COMP_ARRAY      0x80
#define ENT_COMP_COUNT      0x88
#define ENT_BITMASK0        0x110
#define ENT_BITMASK1        0x118
#define ENT_BITMASK2        0x120
#define ENT_HANDLE          0x134
#define ENT_ENTITY_ID       0x138

// Component types
#define TYPE_MODEL          0x04
#define TYPE_TEAM           0x21
#define TYPE_LINK           0x34
#define TYPE_VISIBILITY     0x35
#define TYPE_SKILL          0x37
#define TYPE_HEALTH         0x3B
#define TYPE_CONTROLLER     0x43
#define TYPE_HEROID         0x54

// Model offsets
#define MODEL_VELOCITY      0x50
#define MODEL_HITBOX        0xC8
#define MODEL_POSITION      0x200
#define MODEL_BONES         0x8B0

// Health offsets
#define HEALTH_MAX          0xDC
#define HEALTH_CURRENT      0xE0
#define HEALTH_ARMOR        0x220
#define HEALTH_BARRIER      0x360
#define HEALTH_INVINCIBLE   0x4A8

// HeroID offset
#define HEROID_VALUE        0xD0

// Team offset
#define TEAM_FLAGS          0x58
```
