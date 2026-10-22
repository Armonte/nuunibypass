# Portrait Memory Extension - Debugging Guide

**Date:** October 9, 2025

## Problem

The portrait memory expansion patch is breaking portrait rendering. No portraits display when the patch is active.

## Enhanced Logging

We've added comprehensive logging to both the C++ and Lua implementations to help diagnose the issue.

### What We're Logging

#### C++ Version (`geo_patches.h`)
- Memory allocation details (addresses, sizes, permissions)
- Pattern matching results for all 3 hooks
- Original instruction bytes (before patching)
- Detour construction (byte-by-byte breakdown)
- Complete detour bytecode dumps
- Hook installation (JMP offsets, patch verification)
- Memory accessibility tests
- Portrait array sample reads

#### Lua Version (`chara_sel_extended_portrait_mem.lua`)
- Memory allocation confirmation
- Pattern search results for all 3 hooks
- Original instruction bytes
- Hook preparation status
- Restoration status on disable

## How to Use the Logs

### 1. Build and Run the C++ Version

```bash
# Build your DLL
# Copy winmm.dll to game directory
# Launch the game
# Check the log file (should be in game directory or user directory)
```

### 2. Look for These Key Sections in the C++ Log

```
=== Applying Portrait Memory Extension (DEBUG MODE) ===
```

Check for:
- ✓ **Memory Allocation**: Did it succeed? What address?
- ✓ **All 3 Hooks Found**: Did all patterns match?
- ✓ **Detour Bytecode**: Does it look correct?
- ✓ **Verification**: Do the bytes read back match what was written?

### 3. Compare with Lua Version (CheatEngine)

Enable the Lua script in CheatEngine and compare:
- Are the **same addresses** being found?
- Are the **original bytes** identical?
- Do both versions create the **same detours**?

## Critical Things to Check

### 1. Address Space Layout

**Problem:** If the allocated memory is too far from the game code, relative JMPs might overflow.

**Check in log:**
```
Allocated X bytes at 0x[ADDRESS] for portrait memory
  Portrait array: 0x[ADDRESS]
  Detour code area: 0x[ADDRESS]
```

**Compare with:**
```
Found at 0x[ADDRESS], hook point at 0x[ADDRESS]
```

**Calculate JMP distance:**
- JMP can only reach ±2GB (signed 32-bit offset)
- If addresses are > 2GB apart, JMP will fail silently

### 2. Instruction Encoding

**Problem:** LEA encoding might be wrong for absolute addressing.

**Check in log:**
```
[0-5] LEA: 8D 05 XX XX XX XX (LEA EAX, [0xXXXXXXXX])
```

**Expected encodings:**
- `8D 05 [addr]` = LEA EAX, [disp32]
- `8D 35 [addr]` = LEA ESI, [disp32]

**The issue:** In 32-bit x86, `8D 05` might be interpreted as IP-relative, not absolute!

### 3. Detour Execution

**Problem:** Detour code might not be executable or might fault.

**Check in log:**
```
Memory accessibility test:
  - State: COMMITTED
  - Protection: 0x40 (R/W/X)
```

**Expected:** Protection should include EXECUTE permission (PAGE_EXECUTE_READWRITE = 0x40)

### 4. Portrait Array Access

**Problem:** Portrait array might not be readable/writable.

**Check in log:**
```
Portrait array sample (first 8 pointers):
  [0] @ 0xXXXXXXXX = 0x00000000
  [1] @ 0xXXXXXXXX = 0x00000000
  ...
```

**Expected:** All addresses should be readable, all values initially 0x00000000

## Common Issues and Fixes

### Issue 1: LEA Absolute Addressing in 32-bit

**Symptom:** Detours are created but portraits don't render.

**Cause:** `LEA EAX, [disp32]` (8D 05) in 32-bit x86 uses **absolute addressing**, but the game might expect **register-relative** addressing.

**Fix Options:**
1. Use a different approach: Load address into register first, then use it
2. Use position-independent code (PIC)
3. Allocate memory closer to game code

### Issue 2: JMP Out of Range

**Symptom:** Game crashes when patch is active.

**Cause:** The detour memory is too far from the hook point.

**Fix:** Allocate memory using `VirtualAllocEx` with a preferred address near the game module.

### Issue 3: Memory Permissions

**Symptom:** Access violation when detour executes.

**Cause:** Detour memory doesn't have EXECUTE permission.

**Fix:** Already using `PAGE_EXECUTE_READWRITE`, so this shouldn't be the issue.

### Issue 4: Instruction Length Mismatch

**Symptom:** Game crashes or behaves erratically.

**Cause:** We're not copying enough bytes from the original code.

**Fix:** Verify that:
- Hook 1: 10 bytes (3 LEA + 7 remaining)
- Hook 2: 13 bytes (3 LEA + 10 remaining)
- Hook 3: 8 bytes (6 LEA + 2 MOV, overlapping)

## Diagnostic Procedure

### Step 1: Verify Hook Locations Match

Run both C++ and Lua versions, compare addresses:

```
C++ Log:  Hook 1 Found at: 0x[ADDRESS]
Lua Log:  Hook 1 Found at: 0x[ADDRESS]
```

Should be **identical**.

### Step 2: Verify Original Bytes Match

Compare the "Original X bytes" lines:

```
C++ Log:  Original 10 bytes: 8D 46 08 C7 46 04 00 00 00 00
Lua Log:  Original 10 bytes: 8D 46 08 C7 46 04 00 00 00 00
```

Should be **identical**.

### Step 3: Check Detour Bytecode

Look at the complete detour dump in C++ log:

```
Complete detour bytes:
  8D 05 XX XX XX XX C7 46
  04 00 00 00 00 E9 YY YY
  YY YY
```

Verify:
- First 6 bytes: `8D 05 [4-byte addr]` (LEA)
- Next N bytes: Copy of original code
- Last 5 bytes: `E9 [4-byte offset]` (JMP)

### Step 4: Test with Single Hook

Modify `geo_patches.h` to only install Hook 3 (the loop control):

```cpp
// Comment out Hook 1 and 2, only test Hook 3
```

This hook is simpler and less likely to cause issues. If portraits still don't work, the problem might be elsewhere.

### Step 5: Add Runtime Logging

Add a detour that logs when it's executed:

```cpp
// In detour code, add:
// PUSH EAX
// PUSH "Hook executed!"
// CALL WriteLogFromAsm
// POP EAX
```

This will tell you if the detour is even being called.

## Next Steps

1. **Run the game with enhanced logging**
2. **Compare C++ log with Lua behavior**
3. **Look for differences in:**
   - Addresses found
   - Original bytes
   - Detour construction
4. **Test the hypothesis in LIKELY_ISSUE.md** (see below)

## Most Likely Issue: LEA Addressing Mode

Based on the documentation, the most likely issue is:

**The LEA instruction with ModR/M byte 0x05 might not behave as expected in 32-bit mode.**

In 32-bit x86:
- `8D 05 [disp32]` = LEA EAX, [disp32]
- This should load the address `disp32` into EAX

However, there's a subtle issue: **This is an absolute address**, but the game's original code used **register-relative addressing** (`LEA EAX, [ESI+8]`).

The game might be expecting ESI to contain a specific base pointer that other code uses. By replacing it with an absolute address, we might be breaking that assumption.

## Recommended Fix

Instead of using LEA with absolute addressing, we should:

1. **Set ESI register to point to our memory** (already done in Hook 3)
2. **Use the original LEA instructions** but ensure ESI is correct

OR

3. **Verify that our absolute LEA is actually correct** by checking what address it produces at runtime

## Test Plan

1. Add logging to capture the value of EAX/ESI after each LEA instruction executes
2. Compare with what the original code would have produced
3. Determine if the addresses match
4. If they don't match, that's the bug!

## Log Analysis Checklist

- [ ] Memory allocated successfully?
- [ ] All 3 patterns found?
- [ ] Original bytes match between C++ and Lua?
- [ ] Detour bytecode looks valid?
- [ ] Hook installation verified?
- [ ] Memory has EXECUTE permission?
- [ ] Portrait array is accessible?
- [ ] JMP offsets are reasonable (< 2GB)?
- [ ] Addresses match between C++ and Lua?

## Contact/Notes

After running with enhanced logging, review the output and check off items above. The logs should reveal where the C++ version diverges from the working Lua version.

