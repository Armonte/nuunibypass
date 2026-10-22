# Portrait Memory Extension - Diagnosis & Fix

## Problem Summary
The C++ port of the portrait memory extension is breaking portraits. The Lua version works perfectly in CheatEngine.

## Root Cause Analysis

### What the Lua Version Does (CORRECT)
1. **Allocates memory** for portrait pointer array (256 pointers × 4 bytes = 1024 bytes)
2. **Creates detours** in that allocated memory containing:
   - NEW `LEA` instruction pointing to custom memory
   - REMAINING original bytes (after the LEA we replaced)
   - `JMP` back to continue execution
3. **Overwrites original code** locations with `JMP` to detours + NOPs for padding

### What the C++ Version Does (WRONG)
1. ✅ Allocates memory correctly
2. ❌ **Creates trampolines using `MOV EAX, imm32` instead of `LEA EAX, [address]`**
3. ❌ Uses complex trampoline copying logic that doesn't match Lua's approach

##Key Difference: LEA vs MOV

**Lua version (CORRECT):**
```asm
; Detour contains:
lea eax,[CSel_Portrait_Extension_Memory_Pointers+8]  ; Point to our memory
db C7 46 04 00 00 00 00  ; Remaining original bytes
jmp cselPortraitExtension_return
```

**C++ version (WRONG):**
```cpp
trampoline[tIdx++] = 0xB8;  // MOV EAX, imm32  <-- WRONG INSTRUCTION!
*(DWORD*)(trampoline + tIdx) = (DWORD)(g_portraitMemoryBase + 8);
```

### Why This Matters
- `LEA` (Load Effective Address) calculates an address
- `MOV` loads a value directly
- While both put a value in EAX, `LEA` is the **semantically correct** instruction
- The following code may behave differently depending on which instruction was used
- Using MOV breaks the instruction encoding expectations

## The Fix

The C++ version needs to:
1. Use actual `LEA` instructions in the detours (like Lua does)
2. Copy the remaining original bytes after the LEA (like Lua does)
3. Simplify the approach - no need for complex trampoline logic

### Correct Instruction Encoding

**For Patch 1:**
Original: `8D 46 08` = `LEA EAX, [ESI+8]`
Replace with: `8D 05 [4-byte address]` = `LEA EAX, [absolute_address]`

**For Patch 2:**
Original: `8D 46 00` = `LEA EAX, [ESI+0]`
Replace with: `8D 05 [4-byte address]` = `LEA EAX, [absolute_address]`

**For Patch 3:**
Original: `8D 35 [4-byte addr]` = `LEA ESI, [absolute_address]`
Replace with: `8D 35 [4-byte addr]` (pointing to our memory)
Plus: `BF [4-byte value]` = `MOV EDI, 0x100`

## Pattern Match Details

### Patch Point 1
- **Pattern:** `C6 ?? ?? 02 8D ?? ?? C7 ?? ?? 00 00 00 00`
- **Offset:** +0x4 (points to `8D` opcode)
- **Bytes to save:** 10 (0xA)
- **Structure:** `8D 46 08` (LEA, 3 bytes) + following 7 bytes

### Patch Point 2
- **Pattern:** `0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ?? ?? ?? ?? 00 00 00 00`
- **Offset:** +0x6 (points to `8D` opcode)
- **Bytes to save:** 13 (0xD)
- **Structure:** `8D 46 00` (LEA, 3 bytes) + following 10 bytes

### Patch Point 3
- **Pattern:** `C7 ?? ?? 00 00 00 00 8D ?? ?? BF ?? ?? ?? ??`
- **Offset:** +0x7 (points to `8D` opcode)
- **Bytes to save:** 8 (0x8)
- **Structure:** `8D 35 [4]` (LEA ESI, 6 bytes) + `BF [4]` (MOV EDI, overlaps to 8 total)

## Implementation Strategy

The correct C++ approach:
1. Allocate memory with READWRITE permission (detours don't need to be executable separately)
2. For each patch point:
   a. Find the pattern
   b. Save original bytes
   c. Build detour in allocated memory:
      - Write correct LEA instruction (6 bytes for absolute addressing)
      - Copy remaining original bytes (skip first 3)
      - Write JMP back (5 bytes)
   d. Overwrite original location with JMP to detour + NOPs

## Next Steps
1. Rewrite `ApplyPortraitMemoryExtension()` function
2. Use proper x86 instruction encoding for LEA
3. Test with game to verify portraits work

