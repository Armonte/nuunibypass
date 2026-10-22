# Binary Comparison Guide

## Addresses to Check in Cheat Engine

Load the Cheat Engine table `debug_addresses.CT` and compare these values between:
- **Vanilla uni2.exe** (without our DLL)
- **Vanilla uni2.exe** (with our DLL loaded)
- **uni2_booty.exe** (BootySama's patched version)

## Key Areas to Monitor:

### 1. D Folder Flags (Should ALL be `01`)
These are the 14 flags that enable the D folder system:
- `0xDA44, 0xDA4E, 0xDA58, 0xDA62, 0xDA6C, 0xDA80, 0xDA8A` (Region 1)
- `0x4DCA24, 0x4DCA2E, 0x4DCA38, 0x4DCA42, 0x4DCA4C, 0x4DCA60, 0x4DCA6A` (Region 2)

### 2. Critical Jump (Should be `90 90` = NOP NOP)
- **Address**: `0x4BA708` (File offset: `0xB9B08`)
- **Vanilla**: `74 77` (JZ - Jump if Zero)
- **Patched**: `90 90` (NOP NOP - Always fall through)

### 3. Runtime Flag (Should be `01`)
- **Address**: `0x99868C` (Runtime memory)
- This is `g_bUseDFolderSystem` - the global flag checked by the conditional jump

### 4. CSS Portrait Limit (Should be `64` = 100 decimal)
- **Address**: `0x4AE9F1` (File offset: `0x24E9F1`)
- **Vanilla**: `20` (32 portraits)
- **Patched**: `64` (100 portraits)

### 5. D Folder Array (Portrait path strings)
Starting at `0x3F46EC0`, there are 4 string arrays (260 bytes each) that should contain the `__St` folder paths:
- Array[0]: Should be a path string
- Array[1]: Should be a path string  
- Array[2]: Should be a path string
- Array[3]: Should be a path string

## IDA Pro Function Reference

The key function to examine: `sub_4BA6B0` (File load function)

**Critical line at `0x4BA708`:**
```assembly
mov al, byte_99868C     ; Load g_bUseDFolderSystem flag
test al, al             ; Test if zero
jz loc_4BA781          ; *** THIS JUMP *** - Skip D folder logic if zero
; --- D folder code runs here if flag is 1 ---
xor eax, eax
mov edi, offset byte_3F46EC0  ; Load D folder array
```

If the jump at `0x4BA708` is taken (flag=0), it skips ALL the D folder logic and goes straight to the fallback file loading at `0x4BA920`.

## What to Look For:

1. **With vanilla uni2.exe + our DLL:**
   - All 14 flags should be `01`
   - Jump at `0xB9B08` should be `90 90`
   - Runtime flag at `0x99868C` should be `01` (if it copies from the static flags)
   - D folder array should have path strings

2. **With uni2_booty.exe:**
   - Same as above - should match our patches exactly

3. **If portraits don't load:**
   - Check if the D folder array strings are correct
   - Check if there's another check/jump we're missing
   - Monitor the execution flow around `0x4BA708-0x4BA920` to see which code path is taken

## Testing Steps:

1. Open Cheat Engine, attach to `uni2.exe`
2. Load `debug_addresses.CT`
3. Go to CSS screen
4. Take screenshots of all values
5. Compare with `uni2_booty.exe`
6. Look for differences in the D folder array strings especially

## Expected Portrait Path Format:

The D folder strings should look something like:
- `__St/JA/` or `__St/EN/` etc.
- Or possibly `data/__St/JA/` depending on the game's path structure

If these strings are empty or incorrect, that's likely the issue!

