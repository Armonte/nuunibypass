# UNI2 Geo Patches - Testing & Verification Guide

## Quick Start

The DLL is **already deployed** to your game folder and will load automatically when you start UNI2.

### Check If It's Working

1. **Start the game** (through Steam or directly)
2. **Check the log file** in the game directory:
   ```
   C:\Program Files (x86)\Steam\steamapps\common\UNDER NIGHT IN-BIRTH II Sys Celes\uni2_bypass.log
   ```

### What to Look For in the Log

The log should show:
```
=== UNI2 Bypass DLL Loaded ===
=== GEO MEMORY EXPANSION PATCHES ===
=== Applying Palette Bypass Patches ===
  Pattern 1: ... (2 instances expected)
  [Access_All_Palettes_1] Patched at 0x...
  [Access_All_Palettes_2] Patched at 0x...
  ... (continues for all 9 patches)
Palette Bypass: 9/9 patches applied

=== Applying CSS Portrait Count Patch ===
  [CSS_Portrait_Count] Patched at 0x...
CSS Portrait Count: 1/1 patch applied (32 -> 100)

=== Applying Portrait Memory Extension ===
  Allocated ... bytes at 0x... for portrait memory
  Hook 1: ... Found at 0x...
  Hook 2: ... Found at 0x...
  Hook 3: ... Found at 0x...
Portrait Memory Extension: 3/3 hooks applied

=== Applying Stack Memory Expansion ===
  Step 1: Finding Region One base offset...
    Found at 0x..., original offset: 0x...
  Step 2: Finding Region Two base offset...
    Found at 0x..., original offset: 0x...
  Step 3: Finding additional Region One references...
  Step 4: Finding additional Region Two references...
  Step 5: Applying all stack memory patches...
    Patching Region One (3 locations)...
    Patching Region Two (7 locations)...
Stack Memory Expansion: 10 patches applied

=== Total Geo Patches Applied: 23 ===
```

---

## Verification with IDA Pro MCP

Since you have IDA connected, you can verify the patches in real-time!

### 1. Check Pattern Matching

```python
# In your Python script or IDA console
from ida_funcs import *
from ida_bytes import *

# Example: Verify palette bypass pattern 1
pattern = "75 ?? 8B ?? ?? 83 ?? ?? 7C"
# Use IDA's pattern search to confirm location
```

### 2. Verify Patched Instructions

After the game loads with the DLL:
```python
# Read the patched bytes
addr = 0x<ADDRESS_FROM_LOG>
byte = get_byte(addr)
print(f"Patched byte at {hex(addr)}: {hex(byte)}")
# Should show 0xEB (JMP) instead of 0x7C (JL) for palette patches
```

### 3. Check Allocated Memory

The log will show addresses like:
```
Allocated 5120 bytes at 0x12340000 for portrait memory
Allocated 4096 bytes at 0x56780000 for stack memory
```

These addresses should be valid and writable.

---

## In-Game Testing

### Test 1: Palette Access
**What to test:**
- Load custom palettes for characters
- Try accessing more than the vanilla limit (usually 18 palettes)
- All palette slots should be accessible without crashes

**Expected result:** ✅ All custom palettes load and are selectable

### Test 2: CSS Portrait Count
**What to test:**
- Character select screen
- Load characters beyond slot 32
- Up to 100 portrait slots should be available

**Expected result:** ✅ Portraits for all characters display correctly

### Test 3: Portrait Memory
**What to test:**
- Load many characters (especially custom ones)
- Navigate character select screen
- Check for visual glitches or crashes

**Expected result:** ✅ All character portraits load without corruption

### Test 4: Stack Memory
**What to test:**
- Full character select with maximum custom characters
- Navigate through all pages/options
- Test with 256 character slots if possible

**Expected result:** ✅ No stack overflow, all data accessible

---

## Troubleshooting

### Problem: "Pattern not found" in log

**Cause:** Game was updated and patterns changed

**Solution:**
1. Use IDA Pro MCP to find the new pattern location
2. Update the pattern in `geo_patches.h`
3. Rebuild: `./build.sh`

### Problem: Game crashes on startup

**Cause:** Bad memory patch

**Solution:**
1. Check log to see which patch failed
2. Verify pattern match in IDA
3. May need to adjust offsets

### Problem: Patches applied but features don't work

**Cause:** Patterns found but wrong location

**Solution:**
1. Use IDA MCP to verify the patched instructions
2. Disassemble the function containing the patch
3. Confirm logic matches Geo's scripts

---

## Advanced: Using IDA Pro MCP for Verification

### Get Current Function Info
```python
# Connect to IDA MCP (you already have this set up)
# Example queries:

# 1. Get metadata about the IDB
metadata = get_metadata()

# 2. Decompile a function at a patch address
addr = "0x<ADDRESS_FROM_LOG>"
decompiled = decompile_function(addr)
print(decompiled)

# 3. Disassemble to see actual instructions
asm = disassemble_function(addr)
print(asm)

# 4. Get cross-references to verify hook points
xrefs = get_xrefs_to(addr)
for xref in xrefs:
    print(f"Referenced from: {hex(xref)}")
```

### Verify Pattern Matches
```python
# Example: Check if palette bypass patterns are correct
patterns = [
    "75 ?? 8B ?? ?? 83 ?? ?? 7C",  # Pattern 1
    "83 ?? ?? 72 ?? 83 ?? ?? 83",  # Pattern 2
    "83 ?? ?? 7D ?? 83 ?? ?? 72",  # Pattern 3
]

for i, pattern in enumerate(patterns):
    # Use IDA's pattern scanner
    results = find_pattern(pattern)
    print(f"Pattern {i+1}: Found {len(results)} matches")
    for addr in results:
        print(f"  - {hex(addr)}")
```

---

## Success Checklist

- [ ] DLL loads without errors (check log)
- [ ] All 23 patches report success in log
- [ ] No crashes on game startup
- [ ] Palette access works for custom characters
- [ ] Portrait count increased to 100
- [ ] Character select memory expanded
- [ ] No visual corruption or glitches
- [ ] Can load maximum custom content

---

## Performance Notes

The patches should have **zero performance impact** because:
- Simple byte patches (just changing jump conditions)
- Memory is allocated once at startup
- No runtime hooking or interception
- Direct memory redirection (not dynamic)

---

## Log Analysis Tips

### Good Log (Everything Working):
```
Palette Bypass: 9/9 patches applied
CSS Portrait Count: 1/1 patch applied
Portrait Memory Extension: 3/3 hooks applied
Stack Memory Expansion: 10 patches applied
=== Total Geo Patches Applied: 23 ===
```

### Warning Log (Some Patterns Missing):
```
Palette Bypass: 7/9 patches applied
  Warning: 'Access_All_Palettes_8' pattern not found
```
→ Game may have updated, need to verify patterns

### Error Log (Critical Failure):
```
ERROR: Failed to allocate portrait memory!
```
→ System memory issue or permissions problem

---

## Next Steps After Testing

1. **If everything works:** Share with modding community!
2. **If patterns fail:** Use IDA MCP to update patterns
3. **If crashes occur:** Check specific patch addresses in IDA
4. **If features don't work:** May need to adjust hook logic

---

## Contact & Credits

**Original Scripts:** Geo (Cheat Engine Lua)
**C++ Port:** This implementation
**Tools Used:** IDA Pro, MCP, MinGW, Pattern Scanner

**Game:** Under Night In-Birth II Sys:Celes
**Platform:** Steam (Windows 32-bit)

