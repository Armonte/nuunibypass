# NuUni Bypass - Complete Modding System

A WinMM proxy DLL that unlocks UNI2's full modding potential by:
1. **Bypassing D folder checks** - Load files directly from extracted folders
2. **Expanding memory limits** - Geo's memory expansion patches for custom characters
3. **User configuration** - Customizable settings via `nuuni.ini`

## What It Does

### D Folder Bypass
The game normally requires a `d` folder containing packed game data. This bypass patches the game's file loading system to skip `d` folder checks entirely, allowing modders to work with extracted files directly.

### Memory Expansion (Geo Patches)
Implements **all 3 of Geo's Cheat Engine scripts** in native C++:
- ✅ **Palette Bypass** - Unlimited palette access for all characters
- ✅ **Portrait Count** - Configurable CSS portrait limit (default: 100, vanilla: 32)
- ✅ **Portrait Memory** - Extended memory for 256 character portraits
- ✅ **Stack Memory** - Expanded character select data structures

**Total: 26 patches** applied automatically on game startup!

## How It Works

### WinMM DLL Proxy

The bypass uses a proxy DLL technique:
1. `winmm.dll` is placed in the game directory
2. Game loads our proxy instead of system winmm.dll
3. Our DLL loads the real winmm.dll and forwards all calls
4. During initialization, three patches are applied to the game executable

### Pattern Scanning

The bypass uses **pattern scanning** to find patch locations dynamically:
- Works across game updates - no hardcoded addresses
- Scans for unique byte signatures in the game's `.text` section
- IDA-style wildcards (`??`) for flexible matching
- Logs success/failure for each pattern match

### The Patches

All patches are applied at runtime by modifying the game's memory:

**Patch 1 & 2: Skip D Folder File Checks**
- Pattern: `E8 ?? ?? ?? ?? 84 C0 74 ??` (call + test + conditional jump)
- Original: `call CheckFileInDIndex`
- Patched: `xor al, al; nop; nop; nop` (always return false)
- Effect: File open operations never check if files exist in the d folder

**Patch 3: Ignore D Folder Load Failure**
- Pattern: `84 C0 75 08 6A FF` (test + conditional jump)
- Original: `jnz short fail_handler` (jump if d folder load fails)
- Patched: `jmp short fail_handler` (unconditional jump, always "fails")
- Effect: Game continues even when d folder indices don't load

## Installation

1. Download `winmm.dll`, `steam_appid.txt`, and `nuuni.ini`
2. Place all files in your game directory (same folder as `uni2.exe`)
3. *(Optional)* Edit `nuuni.ini` to configure settings
4. Launch the game normally through Steam or `uni2.exe`

The game will automatically load and patch itself at startup. Works seamlessly with Steam!

### Configuration

Edit `nuuni.ini` to customize:
```ini
log = 1              # Enable/disable logging (1 = on, 0 = off)
portrait_limit = 100 # CSS portrait count (32 = vanilla, 100 = default, 0 = unlimited)
```

See `CONFIG_GUIDE.md` for detailed configuration options.

## Building

```bash
./build.sh
```

Requires `i686-w64-mingw32-g++` for cross-compilation to 32-bit Windows.

Outputs:
- `winmm.dll` - The proxy DLL (with all patches)
- `steam_appid.txt` - Steam app ID file (2076010)
- `nuuni.ini` - Config file (auto-generated)

## Technical Details

### Core Systems
- **Patch Method:** Pattern scanning + VirtualProtect + direct memory writes
- **Pattern Scanner:** IDA-style wildcards (`??`), multi-instance scanning, dynamic pattern building
- **Function Forwarding:** All winmm.dll exports forwarded to system32's winmm.dll
- **Initialization:** Patches applied in DllMain on DLL_PROCESS_ATTACH
- **Config System:** INI parser with auto-generation and validation
- **Logging:** Configurable via `nuuni.ini`, creates `uni2_bypass.log` in game directory

### Geo Patches (26 Total)
1. **D Folder Bypass** - 3 patches (original functionality)
2. **Palette Bypass** - 9 patches (remove palette restrictions)
3. **Portrait Count** - 1 configurable patch (expand CSS portraits)
4. **Portrait Memory** - 3 code cave hooks (allocate 5KB)
5. **Stack Memory** - 10 dynamic patches (allocate 8KB, transform ModR/M bytes)

### Memory Allocations
- Portrait Memory: 5,120 bytes (5KB) for 256 characters
- Stack Memory: 8,192 bytes (8KB) for extended character select data
- Both use `VirtualAlloc` with PAGE_READWRITE permissions

## Result

Game loads all assets from extracted folders:
- `data/` - Game data files
- `BattleRes/` - Battle resources
- `Bgm/` - Background music
- `se/` - Sound effects
- `bg/` - Background images
- `script/` - Game scripts
- `grpdat/` - Graphics data
- `System/` - System files
- `Shader/` - Shader files
- `___English/` (and other language folders) - Localization


**No `d` folder required!**

## Credits

**Original Research & Cheat Engine Scripts:**
- **Geo** - Pattern discovery, memory architecture analysis, all 3 CE scripts

**NuUni Implementation:**
- D folder bypass system
- C++ port of Geo's scripts
- Config system & build infrastructure

**Tools:**
- IDA Pro + MCP (pattern verification)
- Cheat Engine (original development)
- MinGW (cross-compilation)
