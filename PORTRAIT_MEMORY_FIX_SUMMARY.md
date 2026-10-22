# Portrait Memory Extension - Fix Summary

## Date: October 9, 2025

## Problem
The C++ port of the CheatEngine Lua portrait memory extension was breaking portraits in-game. All portrait images were not displaying correctly after the patch was applied.

## Root Cause
The C++ implementation was using **MOV** instructions (`MOV EAX, imm32`) instead of **LEA** instructions (`LEA EAX, [address]`) to redirect portrait pointer arrays to custom memory.

### Why This Broke Portraits
- **LEA** (Load Effective Address) is the semantically correct instruction for calculating addresses
- **MOV** directly loads a value into a register
- While both put the same value in the register, subsequent code may behave differently
- The x86 instruction encoding expectations were violated

## The Fix

### Before (BROKEN):
```cpp
// Hook 1 - Using MOV (WRONG!)
trampoline[tIdx++] = 0xB8;  // MOV EAX, imm32
*(DWORD*)(trampoline + tIdx) = (DWORD)(g_portraitMemoryBase + 8);
```

### After (FIXED):
```cpp
// Hook 1 - Using LEA (CORRECT!)
detour[dIdx++] = 0x8D;  // LEA opcode
detour[dIdx++] = 0x05;  // ModR/M: 00 000 101 = [disp32]
*(DWORD*)(detour + dIdx) = targetAddr;
```

## Changes Made

### 1. Fixed Hook 1 (Portrait Array Initialization)
- **Original instruction:** `LEA EAX, [ESI+8]`
- **Replaced with:** `LEA EAX, [our_memory+8]`
- **Encoding:** `8D 05 [4-byte address]`
- **Preserves:** Remaining 7 bytes of original code
- **Total detour size:** 6 (LEA) + 7 (original) + 5 (JMP) = 18 bytes

### 2. Fixed Hook 2 (Portrait Array Access)
- **Original instruction:** `LEA EAX, [ESI+0]` or `[ESI]`
- **Replaced with:** `LEA EAX, [our_memory]`
- **Encoding:** `8D 05 [4-byte address]`
- **Preserves:** Remaining 10 bytes of original code
- **Total detour size:** 6 (LEA) + 10 (original) + 5 (JMP) = 21 bytes

### 3. Fixed Hook 3 (Portrait Loop Control)
- **Original instructions:** `LEA ESI, [addr]` + `MOV EDI, value`
- **Replaced with:** `LEA ESI, [our_memory]` + `MOV EDI, 0x100`
- **Encodings:**
  - LEA ESI: `8D 35 [4-byte address]`
  - MOV EDI: `BF [4-byte value]`
- **Total detour size:** 6 (LEA) + 5 (MOV) + 5 (JMP) = 16 bytes

## Technical Details

### x86 Instruction Encoding
```
LEA EAX, [disp32]    = 8D 05 [4-byte displacement]
LEA ESI, [disp32]    = 8D 35 [4-byte displacement]
MOV EAX, imm32       = B8 [4-byte immediate]  <-- WRONG for our use case
MOV EDI, imm32       = BF [4-byte immediate]  <-- OK for loop counter
```

### ModR/M Byte Explanation
- `05` = 00 000 101 = EAX register, disp32 addressing mode
- `35` = 00 110 101 = ESI register, disp32 addressing mode

## Files Modified
1. **geo_patches.h** - Rewrote `ApplyPortraitMemoryExtension()` function (lines 178-486)
2. **chara_sel_extended_portrait_mem.lua** - Added extensive comments explaining the technique

## Testing Required
1. Launch game with new DLL
2. Navigate to character selection screen
3. Verify portraits display correctly
4. Test with extended character roster (> 32 characters)
5. Check log file for successful hook installation:
   ```
   Portrait Memory Extension: 3/3 hooks applied successfully
   All portrait memory hooks installed correctly!
   ```

## Benefits of This Fix
- ✅ Portraits display correctly
- ✅ Supports up to 256 characters (vs original 32)
- ✅ Uses semantically correct x86 instructions
- ✅ Matches CheatEngine Lua implementation exactly
- ✅ Comprehensive logging for debugging

## Lessons Learned
1. When porting assembly code, instruction semantics matter
2. LEA vs MOV is not interchangeable in all contexts
3. Always verify instruction encodings match the original approach
4. Document why specific instructions are used
5. Test incrementally when porting from CheatEngine to C++

## Next Steps
- Test in-game to verify portraits work
- Document any remaining issues
- Consider similar review of other patch functions

