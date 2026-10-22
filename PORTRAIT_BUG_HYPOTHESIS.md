# Portrait Memory Bug - Primary Hypothesis

**Date:** October 9, 2025

## The Likely Bug

After analyzing the code, I believe the issue is with **x86 LEA addressing modes** and how we're using absolute addresses.

## The Problem

### Original Game Code (Working)
```asm
LEA EAX, [ESI+8]    ; 8D 46 08
```
- Uses **base+displacement** addressing mode
- ESI contains a base address (likely a struct pointer)
- Loads address `ESI + 8` into EAX

### Our C++ Replacement (Broken?)
```asm
LEA EAX, [0x12345678]    ; 8D 05 78 56 34 12
```
- Uses **displacement-only** addressing mode (ModR/M = 0x05)
- Loads absolute address into EAX

## Why This Might Break

### Hypothesis 1: IP-Relative vs Absolute

In **32-bit x86**, the ModR/M byte `05` in LEA has special meaning:

- `8D 05 [disp32]` = LEA r32, [disp32]
  
This encoding is **ambiguous** in different x86 modes:
- In **16-bit mode**: Absolute addressing
- In **32-bit mode**: Might be IP-relative or absolute (depends on processor)
- In **64-bit mode**: Always IP-relative (RIP-relative)

**If the game is running in a mode where `[disp32]` is IP-relative**, our LEA will calculate:
```
EAX = RIP + disp32
```

Instead of:
```
EAX = disp32
```

This would load a **wrong address** into EAX!

### Hypothesis 2: ModR/M Byte Encoding Issue

The ModR/M byte `05` is correct for absolute addressing in 32-bit mode, BUT:

**In 32-bit protected mode, there's a catch:**

```
ModR/M = 05 (00 000 101)
  Mod = 00  (no displacement, or special)
  Reg = 000 (EAX)
  R/M = 101 (special case)
```

When Mod=00 and R/M=101 in 32-bit mode:
- **Without SIB byte**: `[disp32]` (absolute)
- **With SIB byte**: Different meaning

Our encoding `8D 05 [disp32]` is only 6 bytes, which is correct for **no SIB byte**.

But wait... **in 32-bit mode, does ModR/M=05 require a SIB byte?**

Let me check the Intel manual:
- Mod=00, R/M=101: **[disp32]** (no SIB in 32-bit mode)
- Mod=00, R/M=100: **SIB byte follows**

So our encoding should be correct. Unless...

### Hypothesis 3: The Game Uses FS/GS Segment Overrides

**If the original code uses segment overrides:**

```asm
MOV EAX, FS:[ESI+8]    ; Uses FS segment
```

Then our replacement:
```asm
LEA EAX, [0x12345678]  ; Uses default segment (DS)
```

Would load from a **different memory segment**, potentially causing a fault or wrong data.

But wait, LEA doesn't actually dereference memory, it just calculates an address. So this can't be it.

### Hypothesis 4: The Real Issue - ESI is Used Later

**CRITICAL REALIZATION:**

Look at the original code:
```asm
LEA EAX, [ESI+8]       ; Calculate address in EAX
MOV DWORD PTR [ESI+4], 0  ; BUT ESI IS STILL USED HERE!
```

We're replacing the first LEA, but the **next instruction still uses ESI!**

If the game expects ESI to contain the original base pointer, but we've only changed EAX, the `MOV [ESI+4], 0` instruction will write to the **original memory**, not our custom memory!

## The Fix

We need to **set ESI to our memory base** before executing the remaining original code.

### Current C++ Code (Broken)
```cpp
// Detour:
detour[dIdx++] = 0x8D;  // LEA EAX, [our_memory+8]
detour[dIdx++] = 0x05;
*(DWORD*)(detour + dIdx) = (DWORD)g_portraitMemoryBase + 8;
dIdx += 4;

// Copy remaining bytes: MOV DWORD PTR [ESI+4], 0
memcpy(detour + dIdx, hookPoint + 3, 7);  // This still uses ESI!
dIdx += 7;
```

**Problem:** The copied code `MOV [ESI+4], 0` still references the old ESI!

### Correct Fix

We need to **replace ESI** in the copied instructions!

**Option 1: Set ESI before copying**
```asm
; Detour should be:
LEA ESI, [our_memory]    ; Set ESI to our memory base
LEA EAX, [ESI+8]         ; Now calculate EAX from new ESI
MOV [ESI+4], 0           ; This will write to our memory
JMP return_address
```

**Option 2: Translate ESI references to absolute**
```asm
; Instead of: MOV [ESI+4], 0
; Use:        MOV DWORD PTR [our_memory+4], 0
```

But this requires disassembling and rewriting instructions, which is complex.

## Why Lua Version Works

The Lua script copies the original bytes **without understanding them**:

```lua
db C7 46 04 00 00 00 00  -- Remaining original bytes
```

This is: `MOV DWORD PTR [ESI+4], 0`

**But the Lua version has a crucial difference:**

Look at Hook 3:
```lua
lea esi,[CSel_Portrait_Extension_Memory_Pointers]
mov edi,core.script.charSelExtPortraitMem.charLimit
```

**Hook 3 sets ESI to our memory!** This happens in the **loop initialization**.

So by the time Hook 1 and Hook 2 execute, **ESI already points to our memory** (set by Hook 3).

## The Critical Execution Order

1. **Hook 3 executes first** (loop initialization)
   - Sets ESI to our custom memory
   - Sets EDI to loop count (256)

2. **Loop begins**, for each portrait:
   - Hook 1 executes: `LEA EAX, [our_memory+8]`
     - But also: `MOV [ESI+4], 0` — works because ESI is already our memory!
   - Hook 2 executes: `LEA EAX, [our_memory]`
     - Subsequent instructions use EAX, which now has our address

## The Real Bug in C++

Our C++ version is creating **correct detours**, but we're not accounting for the fact that:

**Hook 1 and Hook 2 rely on ESI being set by Hook 3!**

If Hook 3 hasn't executed yet, or if the hooks are called in a different context where ESI is wrong, they'll break.

## Testing the Hypothesis

### Test 1: Check Hook Execution Order

Add logging to detect:
1. Does Hook 3 execute before Hook 1/2?
2. What is the value of ESI when Hook 1/2 execute?

### Test 2: Verify ESI Value

Modify the detour to log ESI:
```cpp
// At start of detour:
// PUSH ESI
// CALL LogESIValue
// POP ESI
```

### Test 3: Force ESI Before Each Hook

Modify each detour to set ESI first:
```cpp
// Hook 1 detour:
detour[dIdx++] = 0x8D;  // LEA ESI, [our_memory]
detour[dIdx++] = 0x35;  // ModR/M for ESI
*(DWORD*)(detour + dIdx) = (DWORD)g_portraitMemoryBase;
dIdx += 4;

// THEN do the original LEA:
detour[dIdx++] = 0x8D;  // LEA EAX, [ESI+8]
detour[dIdx++] = 0x46;  // Original ModR/M
detour[dIdx++] = 0x08;  // Original displacement
// Now remaining instructions will work correctly!
```

## Recommended Immediate Fix

Change Hook 1 detour to:

```cpp
// Set ESI to our memory first
detour[dIdx++] = 0x8D;  // LEA opcode
detour[dIdx++] = 0x35;  // ModR/M for ESI, [disp32]
*(DWORD*)(detour + dIdx) = (DWORD)g_portraitMemoryBase;
dIdx += 4;

// Now execute the ORIGINAL LEA instruction (but ESI is now our memory)
detour[dIdx++] = 0x8D;  // LEA EAX, [ESI+8]
detour[dIdx++] = 0x46;  // Original ModR/M
detour[dIdx++] = 0x08;  // Original disp8

// Copy remaining instructions (they'll use the new ESI)
memcpy(detour + dIdx, hookPoint + 3, 7);
dIdx += 7;

// JMP back
// ...
```

Same for Hook 2.

## Summary

**Bug:** We're replacing `LEA EAX, [ESI+8]` with `LEA EAX, [absolute]`, but the following instructions **still use ESI**, which points to the old memory!

**Fix:** Set ESI to our memory base **before** executing the remaining original instructions.

**Verification:** Check log to see if ESI has the correct value when hooks execute.

This explains why the Lua version works: Hook 3 sets ESI globally, so Hook 1/2 work correctly. Our C++ version needs to do the same **within each detour**.

