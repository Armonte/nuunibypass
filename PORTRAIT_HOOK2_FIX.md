# Portrait Memory Extension - Hook 2 False Positive Fix

**Date:** October 9, 2025

## Problem Discovered

The C++ DLL version of the portrait memory extension was **patching the wrong location for Hook 2**, causing portraits to break.

### Evidence from Logs

**Lua version (WORKING):**
- Hook 2 at: `0x6314AD`
- Original bytes: `8D 46 08 C7 85 10 FD FF FF 00 00 00 00`
- Instruction: `LEA EAX, [ESI+8]` ✓ Correct portrait array access

**C++ version (BROKEN):**
- Hook 2 at: `0x47D86D` ❌ **WRONG ADDRESS!**
- Original bytes: `8D 45 E8 C7 45 E8 EA 03 00 00 50 8B 47`
- Instruction: `LEA EAX, [EBP-0x18]` ❌ Random stack variable access

## Root Cause

The C++ code was scanning for Hook 2's pattern from the **module base** every time:

```cpp
BYTE* addr = PatternScanModuleIDA(hGameModule, pattern);
```

But the Lua script searches **starting AFTER Hook 1's location**:

```lua
addr = AoBTools.ScanAoBTable({
    {"0F 84 * * * * 8D * * C7 * * * * * 00 00 00 00", 0x6}
}, addr, core.game.moduleEndAddress)  -- ← starts from previous addr!
```

This ensures the Lua version finds the **second occurrence** of a similar pattern (the real Hook 2), while the C++ version was finding a **false positive** earlier in the binary that happened to match the short pattern.

## The Fix

### Change 1: Store Hook 1's Address

```cpp
// Storage for hook addresses to use as search starting points
BYTE* hook1Addr = nullptr;

// In Hook 1 block:
BYTE* addr = PatternScanModuleIDA(hGameModule, pattern);
hook1Addr = addr;  // Save for Hook 2's search start point
```

### Change 2: Search from Hook 1's Location

```cpp
// Search starting AFTER Hook 1's location (like the Lua version does)
BYTE* searchStart = hook1Addr ? (hook1Addr + 1) : bounds.start;
SIZE_T searchSize = bounds.end - searchStart;
BYTE* addr = PatternScanIDA(searchStart, searchSize, pattern);
```

### Change 3: Use Longer, More Specific Pattern

**Before (too short):**
```cpp
const char* pattern = "0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ??";
```

**After (matches Lua exactly):**
```cpp
const char* pattern = "0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ?? ?? ?? ?? 00 00 00 00";
```

## Why This Works

1. **Avoids False Positives**: By starting the search after Hook 1, we skip any random code earlier in the binary that might match the pattern
2. **Matches Lua Logic**: The Lua implementation explicitly does this, and it works perfectly
3. **More Specific Pattern**: The longer pattern with trailing `00 00 00 00` reduces chances of matching unrelated code

## Expected Result

After this fix, Hook 2 should now find the correct location:
- Address should be `0x6314AD` (matching Lua)
- Original bytes should be `8D 46 08 C7 85 10 FD FF FF 00 00 00 00` (matching Lua)
- Portraits should display correctly in-game

## Follow-up Issue: Offset Bug

After fixing the search location, portraits displayed but with an **offset error** (wrong portraits for characters).

### Root Cause
Hook 2's original instruction is `LEA EAX, [ESI+8]` (with +8 offset), but the C++ detour was using:
```cpp
DWORD targetAddr = (DWORD)g_portraitMemoryBase;  // No offset - WRONG!
```

This caused an 8-byte (2-pointer) misalignment in the portrait array.

### The Fix
Changed Hook 2's detour to use the same +8 offset as Hook 1:
```cpp
DWORD targetAddr = (DWORD)g_portraitMemoryBase + 8;  // +8 offset like Hook 1!
```

Both Hook 1 and Hook 2 use `[ESI+8]` in the original code, so both need the +8 offset in their detours!

## Files Modified

- `/mnt/c/games/qoh/uni2_bypass/geo_patches.h` (lines 220-362)

## Testing

1. Recompile the DLL with these changes
2. Launch the game with the new DLL
3. Check the log file - Hook 2 should now show:
   ```
   Hook 2: Found at 0x006314ad, hook point at 0x006314ad
   Original 13 bytes: 8D 46 08 C7 85 10 FD FF FF 00 00 00 00
   ```
4. Navigate to character selection screen
5. Verify portraits display correctly

## Technical Notes

- The pattern scanner already had support for custom start addresses via `PatternScanIDA(start, size, pattern)`
- We just needed to use it instead of the module-wide `PatternScanModuleIDA`
- This is a common pattern in multi-hook scenarios where hooks need to be found in order
- Hook 3 doesn't need this treatment because its pattern is unique enough

## Lessons Learned

1. Always check if patterns need to be searched sequentially
2. When porting working code, match the search strategy exactly
3. Log the found addresses and compare them to the working version
4. Use longer patterns when possible to avoid false positives
5. The order of hook discovery matters in some cases

