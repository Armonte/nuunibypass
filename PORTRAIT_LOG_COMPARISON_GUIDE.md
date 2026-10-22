# Portrait Memory Extension - Log Comparison Guide

**Date:** October 9, 2025

## Purpose

This guide helps you compare the enhanced logging output from both the **working Lua version** (CheatEngine) and the **broken C++ version** (DLL) to identify what's different.

## What You'll Need

1. **Lua log output** - Run the Lua script in CheatEngine and copy the console output
2. **C++ log output** - Run the game with the C++ DLL and check the log file
3. This comparison guide

## Step-by-Step Comparison

### 1. Memory Allocation

**Lua:**
```
Allocated 0x1000 bytes at 0x[ADDRESS]
```

**C++:**
```
Allocated [SIZE] bytes at 0x[ADDRESS] for portrait memory
  Portrait array: 0x[ADDRESS]
  Detour code area: 0x[ADDRESS]
```

✓ **Check:**
- Are both allocations successful?
- Note the addresses (they'll be different between runs, that's OK)

---

### 2. Hook 1 - Pattern Matching

**Lua:**
```
Hook 1: Searching for pattern 'C6 * * 02 8D * * C7 * * 00 00 00 00'
  Found at: 0x6312E4 (pattern match + 0x4 offset)
  Original 10 bytes: 8D 46 08 C7 46 04 00 00 00 00
```

**C++:**
```
Hook 1: 'C6 ?? ?? 02 8D ?? ?? C7 ?? ?? 00 00 00 00'
  Found at 0x[BASE], hook point at 0x[BASE+4]
  Original 10 bytes: 8D 46 08 C7 46 04 00 00 00 00
```

✓ **Check:**
- **CRITICAL:** Hook addresses must be IDENTICAL between Lua and C++
- **CRITICAL:** Original bytes must be IDENTICAL
- If addresses differ, pattern scanning is wrong in C++
- If bytes differ, offset calculation is wrong

**Your Lua showed:** `0x6312E4` - your C++ should show this EXACT address

---

### 3. Hook 1 - Detour Code

**Lua:**
```
Hook 1 Verification:
  Original location: 0x6312E4
  Detour location:   0x[DETOUR_ADDR]
  JMP distance:      [BYTES] bytes
  Patched 10 bytes:  E9 [4-byte offset] 90 90 90 90 90
  Detour code:       8D 05 [4-byte addr] C7 46 04 00 00 00 00 E9 [4-byte offset]
```

**C++:**
```
  Detour built at 0x[DETOUR_ADDR], total size [N] bytes
  Complete detour bytes:
    8D 05 [4-byte addr] C7 46 04 00 00 00 00 E9 [4-byte offset]
  Patched 10 bytes: E9 [4-byte offset] 90 90 90 90 90
```

✓ **Check - Patched JMP:**
- First byte should be `E9` (JMP opcode)
- Next 4 bytes are the relative offset (will differ, that's OK)
- Remaining 5 bytes should be `90 90 90 90 90` (NOPs)

✓ **Check - Detour Code Structure:**
- Bytes 0-5: `8D 05 [addr]` - LEA EAX, [absolute]
- Bytes 6-12: `C7 46 04 00 00 00 00` - copied original code
- Bytes 13-17: `E9 [offset]` - JMP back

**Critical Analysis:**
Compare the `[4-byte addr]` in the LEA instruction:
- In Lua: Should be `08 00 83 04` (or similar)
- In C++: Should be `g_portraitMemoryBase + 8`

If these addresses are WILDLY different (like 0x04830008 vs 0x12345678), that's suspicious.

---

### 4. Hook 2 - Pattern Matching

**Lua:**
```
Hook 2: Searching for pattern '0F 84 * * * * 8D * * C7 * * * * * 00 00 00 00'
  Found at: 0x6314AD (pattern match + 0x6 offset)
  Original 13 bytes: 8D 46 08 C7 85 10 FD FF FF 00 00 00 00
```

**C++:**
```
Hook 2: '0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ??'
  Found at 0x[BASE], hook point at 0x[BASE+6]
  Original 13 bytes: 8D 46 08 C7 85 10 FD FF FF 00 00 00 00
```

✓ **Check:**
- **CRITICAL:** Address must be `0x6314AD` (match Lua)
- **CRITICAL:** Original bytes must match exactly

**WAIT - PROBLEM DETECTED!**

Look at your Lua output:
```
Original 13 bytes: 8D 46 08 C7 85 10 FD FF FF 00 00 00 00
```

This shows `8D 46 08` which is **LEA EAX, [ESI+8]**, but according to the comments, Hook 2 should be `LEA EAX, [ESI+0]` (or `8D 46 00`).

**This is suspicious!** Either:
1. The pattern is matching the wrong location, OR
2. The documentation is wrong about what instruction is at Hook 2

Let me decode: `8D 46 08` = LEA EAX, [ESI+8]
But we expected: `8D 46 00` = LEA EAX, [ESI+0]

**This needs investigation!**

---

### 5. Hook 3 - Pattern Matching

**Lua:**
```
Hook 3: Searching for pattern 'C7 * * 00 00 00 00 8D * * BF * * * *'
  Found at: 0x630362 (pattern match + 0x7 offset)
  Original 8 bytes: 8D 73 08 BF 20 00 00 00
```

**C++:**
```
Hook 3: 'C7 ?? ?? 00 00 00 00 8D ?? ?? BF ?? ?? ?? ??'
  Found at 0x[BASE], hook point at 0x[BASE+7]
  Original 8 bytes: 8D 73 08 BF 20 00 00 00
```

✓ **Check:**
- Address must be `0x630362`
- Original bytes must match

**WAIT - ANOTHER PROBLEM!**

`8D 73 08` = LEA ESI, [EBX+8]

But the documentation says:
```
8D 35 [4-byte addr] = LEA ESI, [absolute_address]
```

The actual bytes are `8D 73 08` which is:
- `8D` = LEA opcode
- `73` = ModR/M byte (01 110 011) = LEA ESI, [EBX+disp8]
- `08` = displacement

**This is register-relative, not absolute!**

---

## CRITICAL DISCOVERY

Looking at your Lua log:

1. **Hook 1:** `8D 46 08` = LEA EAX, [ESI+8] ✓ (matches docs)
2. **Hook 2:** `8D 46 08` = LEA EAX, [ESI+8] ✗ (should be [ESI+0]!)
3. **Hook 3:** `8D 73 08` = LEA ESI, [EBX+8] ✗ (should be absolute!)

**The original game code is NOT what the documentation describes!**

## What This Means

The Lua script works because:
1. It copies the original instructions (including the register-relative addressing)
2. It sets ESI/EBX to point to the custom memory (in Hook 3 or earlier)
3. The copied instructions then work correctly with the new base registers

Our C++ approach is trying to replace with absolute addressing, which breaks because:
1. We're changing the instruction encoding
2. The following instructions might still expect register-relative addressing
3. We're not setting the base registers properly

## The Real Fix

We need to **SET THE BASE REGISTER** before executing the original instructions, not replace them with absolute addressing.

### For Hook 1 and Hook 2:
```cpp
// Instead of: LEA EAX, [absolute_address]
// Do: LEA ESI, [absolute_address]
//     LEA EAX, [ESI+8]  (original instruction)
```

### For Hook 3:
```cpp
// Instead of: LEA ESI, [absolute_address]
// Do: LEA EBX, [absolute_address]
//     LEA ESI, [EBX+8]  (original instruction)
```

Or we need to figure out what register the game is actually using as the base.

## Next Steps

1. **Run your C++ version and get the log**
2. **Compare hook addresses** - they MUST match Lua exactly
3. **Look at the detour bytecode** - does it make sense?
4. **Read the actual original bytes** - do they match what Lua sees?
5. **Test the hypothesis in PORTRAIT_BUG_HYPOTHESIS.md**

## Quick Verification Checklist

```
[ ] Hook 1 address matches: 0x6312E4
[ ] Hook 1 original bytes match: 8D 46 08 C7 46 04 00 00 00 00
[ ] Hook 2 address matches: 0x6314AD
[ ] Hook 2 original bytes match: 8D 46 08 C7 85 10 FD FF FF 00 00 00 00
[ ] Hook 3 address matches: 0x630362
[ ] Hook 3 original bytes match: 8D 73 08 BF 20 00 00 00
[ ] All detours successfully installed
[ ] Memory is readable/writable/executable
[ ] Portrait array is accessible
```

If all boxes check, the problem is in how the detours are constructed, not in finding/patching the locations.

