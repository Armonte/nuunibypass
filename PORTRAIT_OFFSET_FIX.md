# Portrait Memory Extension - Offset Bug Fix

**Date:** October 9, 2025

## Problem

After fixing Hook 2's search location, portraits were displaying but **characters showed the wrong portraits** - there was a slight offset in the array alignment.

## Root Cause

Hook 2's detour code was using the **wrong address offset**:

### The Evidence

Looking at the actual bytes from the running game:

**Hook 1 (CORRECT):**
- Original: `8D 46 08` = `LEA EAX, [ESI+8]`
- Detour: `LEA EAX, [0x04EA0008]` ✓ (+8 offset preserved)

**Hook 2 (WRONG):**
- Original: `8D 46 08` = `LEA EAX, [ESI+8]`
- Detour: `LEA EAX, [0x04EA0000]` ❌ (NO offset - missing +8!)

Both hooks have the **same original instruction** (`[ESI+8]`), but Hook 2's detour wasn't applying the +8 offset!

## Why This Broke Portraits

The portrait pointer array is indexed by character ID. When Hook 2 accessed the array without the +8 offset:

- Character 0 would read from position 0 instead of position 2 (8 bytes = 2 pointers)
- Character 1 would read from position 1 instead of position 3
- And so on...

This caused a **2-character offset** in the portrait display, making every character show someone else's portrait.

## The Fix

Changed line 386 in `geo_patches.h`:

**Before (WRONG):**
```cpp
// No offset this time (original was [ESI+0])  ← Wrong comment!
DWORD targetAddr = (DWORD)g_portraitMemoryBase;  // No offset
```

**After (CORRECT):**
```cpp
// NOTE: Original instruction is ALSO [ESI+8], not [ESI+0]!
// We need +8 offset to match (same as Hook 1)
DWORD targetAddr = (DWORD)g_portraitMemoryBase + 8;  // +8 offset like Hook 1!
```

## Why The Confusion?

The Lua script comments suggested Hook 2 used `[ESI+0]`:

```lua
-- Original instruction: 8D 46 00  (LEA EAX, [ESI+0] or LEA EAX, [ESI])
```

But the **actual bytes** found at runtime are `8D 46 08` (`[ESI+8]`), not `8D 46 00` (`[ESI+0]`)!

The Lua script's comments were misleading, but the Lua detour code itself is generic enough that it worked anyway:
- It replaces the LEA with one pointing to custom memory (no offset in the LEA itself)
- But the Lua version must be setting up ESI differently elsewhere, OR
- The Lua autoAssemble is doing something smarter we didn't catch

## Key Lesson

**Always verify the actual bytes at runtime, don't trust comments!**

The pattern scanner found the location and logged the actual bytes:
```
Original 13 bytes: 8D 46 08 C7 85 10 FD FF FF 00 00 00 00
```

That `8D 46 08` tells us the real instruction encoding, which includes the +8 offset.

## Testing

Recompile and run. You should now see:
```
Hook 2: 
  ...
  [0-5] LEA: 8D 05 [addr+8] (LEA EAX, [0x04EA0008])  ← Now with +8!
```

And portraits should now display correctly for each character!

## Summary

| Hook | Original Instruction | Detour Address | Status |
|------|---------------------|----------------|--------|
| Hook 1 | `LEA EAX, [ESI+8]` | `base + 8` ✓ | CORRECT |
| Hook 2 | `LEA EAX, [ESI+8]` | `base + 8` ✓ | NOW FIXED |
| Hook 3 | `LEA ESI, [EBX+8]` | `base` (different use) | CORRECT |

The pattern is clear: when replacing a `[REG+offset]` instruction with an absolute address, **preserve the offset**!

