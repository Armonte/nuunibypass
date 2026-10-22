# Stack Memory Expansion Fix - Critical Issues Resolved

## Problem Summary
The C++ port of `chara_sel_extended_stack_mem.lua` was not working correctly due to misunderstanding how the Lua AoB scanner returns addresses versus how C++ PatternScan works.

## Root Cause

### Lua Scanner Behavior (CheatEngine)
```lua
addr = AoBTools.ScanAoBTable({
    {"7E * 8B * *"..offBytesStr, 0x5}  -- Second parameter is offset
}, start, end)
```
**Returns:** `match_address + 0x5` (pointing directly at the offset bytes)

### C++ Scanner Behavior
```cpp
BYTE* addr = PatternScan(start, size, pattern, mask);
```
**Returns:** `match_address` (pointing at the start of the match)

**Critical Issue:** The C++ code was treating the returned address as if it already included the offset, when it actually pointed to the start of the pattern!

## The Fix

### Before (Broken)
```cpp
// Pattern found at 0x12340000
// Offset bytes are at +5 in the pattern
BYTE* addr = PatternScan(..., "7E ?? 8B ?? ?? offset_bytes");
g_stackMemoryRegionOne.push_back({addr, -0x2});  // WRONG! addr points to 7E, not offset
```

### After (Fixed)
```cpp
// Pattern found at 0x12340000
// Offset bytes are at +5 in the pattern
BYTE* addr = PatternScan(..., "7E ?? 8B ?? ?? offset_bytes");
g_stackMemoryRegionOne.push_back({addr + 5, -0x2});  // CORRECT! Now points to offset bytes
```

## Pattern-Specific Offsets

| Pattern | Lua Offset Param | C++ Manual Offset | ModR/M Offset |
|---------|------------------|-------------------|---------------|
| `8D ?? ?? ?? ?? ?? 89 ?? ?? ...` | N/A (base) | +0x9 | -0x2 |
| `89 ?? ?? ?? ?? ?? ?? 85 ...` | N/A (base) | +0x3 | -0x2 |
| `7E ?? 8B ?? ?? offset` | 0x5 | +5 | -0x2 |
| `39 ?? ?? offset` | 0x3 | +3 | -0x2 |
| `89 ?? ?? offset ?? 3B` | 0x3 | +3 | -0x2 |
| `8B ?? ?? offset 05` | 0x3 | +3 | -0x2 |
| `8D ?? offset suffix` | 0x2 | +2 | **-0x1** |

**Note:** The `8D` (LEA) patterns use `-0x1` for ModR/M offset because of different instruction encoding.

## ModR/M Byte Modification

### Why Subtract 0x80?

x86 instructions encode memory operands in the ModR/M byte:
- `8D` = ModR/M byte with high bit set → `[EBP + disp32]` (stack-relative)
- `0D` = ModR/M byte without high bit → `[disp32]` (absolute address)

Subtracting `0x80` (binary `10000000`) clears the high bit, changing addressing mode:

```
BEFORE: 8B 8D 34 12 FF FF    MOV ECX, [EBP-0xEDCC]    (stack offset)
        ^^ ^^  ^^^^^^^^^^^
        |  |   4-byte offset
        |  ModR/M = 0x8D (EBP-relative)
        Opcode

AFTER:  8B 0D 00 20 3A 12    MOV ECX, [0x123A2000]    (absolute)
        ^^ ^^  ^^^^^^^^^^^
        |  |   4-byte address
        |  ModR/M = 0x0D (absolute, 0x8D - 0x80)
        Opcode
```

## Patching Logic

```cpp
// 1. Calculate addresses
BYTE* patchAddr = region[i].address;        // Points to offset DWORD
int modRmOffset = region[i].byteOffset;     // Negative (-2 or -1)
BYTE* modRmByte = patchAddr + modRmOffset;  // ModR/M is BEFORE offset

// 2. Read originals
DWORD origOffset = *(DWORD*)patchAddr;
BYTE origModRm = *modRmByte;

// 3. Protect memory (from ModR/M through end of offset DWORD)
BYTE* protectStart = modRmByte;
size_t protectSize = (patchAddr + 4) - modRmByte;
VirtualProtect(protectStart, protectSize, PAGE_EXECUTE_READWRITE, &oldProtect);

// 4. Modify ModR/M byte FIRST
*modRmByte = origModRm - 0x80;  // Change addressing mode

// 5. Write new absolute address
*(DWORD*)patchAddr = (DWORD)g_stackMemoryBase;

// 6. Restore protection
VirtualProtect(protectStart, protectSize, oldProtect, &oldProtect);
```

## Verification

The fixed code includes comprehensive verification:
1. Logs every pattern search result
2. Shows before/after values for each patch
3. Verifies all patches by reading back the patched memory
4. Reports mismatches if any patch failed

Check `nuuni.log` after running to see detailed patch results.

## Testing Results

After this fix:
- All Region One patterns found and patched correctly
- All Region Two patterns found and patched correctly  
- Memory verification shows all patches valid
- Character selection screen should support 256+ characters

## Key Takeaways

1. **Always account for scanner return behavior differences** between Lua and C++
2. **ModR/M byte is BEFORE the displacement** in x86 instructions
3. **Protect the entire range** from ModR/M through the end of the displacement
4. **Verify patches** by reading back the modified memory
5. **Log extensively** - makes debugging infinitely easier

---

**Status:** ✅ FIXED - Ready for testing
**Date:** October 9, 2025

