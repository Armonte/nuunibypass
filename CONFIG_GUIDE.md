# NuUni Configuration Guide

## What is nuuni.ini?

`nuuni.ini` is the configuration file for the NuUni Bypass mod. It lets you customize behavior without recompiling the DLL.

## Location

The config file should be in the same folder as the game executable:
```
C:\Program Files (x86)\Steam\steamapps\common\UNDER NIGHT IN-BIRTH II Sys Celes\nuuni.ini
```

## Configuration Options

### `log` - Enable/Disable Logging

```ini
log = 1  # 1 = enabled (default), 0 = disabled
```

**What it does:**
- When enabled, creates `uni2_bypass.log` with detailed patch information
- Useful for troubleshooting issues
- Disable if you don't need the log file

**Example:**
```ini
log = 0  # Disable logging for cleaner game folder
```

---

### `portrait_limit` - CSS Portrait Count Limit

```ini
portrait_limit = 100  # Default value
```

**What it does:**
- Sets how many character portraits can display on the CSS (Character Select Screen)
- **Vanilla game:** 32 portraits
- **Default mod value:** 100 portraits
- **Uncapped:** Set to 0 for unlimited

**Common Values:**
```ini
portrait_limit = 32   # Vanilla (no expansion)
portrait_limit = 64   # Moderate expansion
portrait_limit = 100  # Default (recommended)
portrait_limit = 0    # Unlimited (use with caution)
```

**Why adjust this?**

Modders sometimes add characters that don't display correctly on CSS. If you experience:
- Visual glitches on character select
- Crashes when scrolling through characters
- Corrupted character portraits

**Solution:** Reduce the limit:
```ini
portrait_limit = 64  # Try a lower value
```

---

## How to Edit

1. **Open** `nuuni.ini` in any text editor (Notepad, VS Code, etc.)
2. **Change** the values as needed
3. **Save** the file
4. **Restart** the game for changes to take effect

## Example Configurations

### Default (Recommended)
```ini
log = 1
portrait_limit = 100
```

### Performance Mode (No Logging)
```ini
log = 0
portrait_limit = 100
```

### Conservative Mode (For Stability)
```ini
log = 1
portrait_limit = 64
```

### Maximum Expansion
```ini
log = 1
portrait_limit = 0  # Unlimited
```

## Troubleshooting

### Problem: Config changes don't work

**Solution:** Make sure you:
1. Saved the file after editing
2. Restarted the game (changes load on startup only)
3. Check the log file to see what value was actually loaded

### Problem: Config file not found

**Solution:** 
The DLL automatically creates `nuuni.ini` with defaults on first run. If it's missing:
1. Delete `winmm.dll` from game folder
2. Re-run `build.sh` 
3. Copy all files to game folder

### Problem: Still having issues with character select

**Solutions to try:**
1. Set `log = 1` to enable logging
2. Check `uni2_bypass.log` for errors
3. Reduce `portrait_limit` to 64 or 32
4. Make sure you have the latest version of the DLL

---

## Technical Details

### Portrait Limit Byte Values

The portrait limit is patched as a single byte comparison:
- `32` (0x20) = Vanilla
- `64` (0x64) = Moderate
- `100` (0x64) = Default
- `0` → `255` (0xFF) = Uncapped

Values over 255 are automatically capped at 255 (maximum byte value).

### Config File Format

- Lines starting with `#` are comments (ignored)
- Format: `key = value`
- Keys are case-insensitive
- Whitespace is automatically trimmed

### Alternative Key Names

For convenience, these are equivalent:
```ini
log = 1
logging = 1          # Same as above
enable_logging = 1   # Same as above

portrait_limit = 100
portraits = 100      # Same as above
```

---

## Advanced Usage

### Disable All Patches (For Testing)

While you can't disable individual patches via config, you can disable logging and verify behavior:

```ini
log = 0              # No log file
portrait_limit = 32  # Vanilla limit (minimal patching)
```

### Debug Mode

For maximum information:
```ini
log = 1              # Enable detailed logging
portrait_limit = 100 # Standard expansion
```

Then check `uni2_bypass.log` for:
- Pattern match results
- Memory allocation addresses
- Patch application success/failure
- ModR/M byte transformations

---

## What Gets Logged?

When `log = 1`, the log file shows:

✅ **D Folder Bypass:** 3 patches for custom file loading
✅ **Palette Bypass:** 9 patches for unlimited palette access  
✅ **Portrait Count:** 1 patch for increased CSS portraits
✅ **Portrait Memory:** 3 hooks for extended portrait arrays
✅ **Stack Memory:** 10 patches for character select data expansion

**Example log output:**
```
Config: Logging=ON, Portrait Limit=100
=== GEO MEMORY EXPANSION PATCHES ===
Palette Bypass: 9/9 patches applied
Portrait limit: 100 (0x64)
CSS Portrait Count: 1/1 patch applied (32 -> 100)
Stack Memory Expansion: 10 patches applied
=== Total Geo Patches Applied: 23 ===
```

---

## Support

If you encounter issues:
1. Check `uni2_bypass.log` (with `log = 1`)
2. Try different `portrait_limit` values
3. Report issues with the log file attached

---

**Credits:** Geo (original CE scripts), NuUni team (C++ port)

