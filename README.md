# UNI2 D Folder Bypass

A WinMM proxy DLL that patches UNDER NIGHT IN-BIRTH II Sys:Celes to run without requiring the `d` folder, allowing the game to load files directly from extracted folders.

## What It Does

The game normally requires a `d` folder containing packed game data. This bypass patches the game's file loading system to skip `d` folder checks entirely, allowing modders to work with extracted files directly.

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
- 100% pattern-based - no fallback addresses

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

1. Download `winmm.dll` and `steam_appid.txt`
2. Place both files in your game directory (same folder as `uni2.exe`)
3. Launch the game normally through Steam or `uni2.exe`

The game will automatically load and patch itself at startup. Works seamlessly with Steam!

## Building

```bash
./build.sh
```

Requires `i686-w64-mingw32-g++` for cross-compilation to 32-bit Windows.

Outputs:
- `winmm.dll` - The proxy DLL
- `steam_appid.txt` - Steam app ID file (2076010)

## Technical Details

- **Patch Method:** Pattern scanning + VirtualProtect + direct memory writes
- **Function Forwarding:** All winmm.dll exports forwarded to system32's winmm.dll
- **Initialization:** Patches applied in DllMain on DLL_PROCESS_ATTACH
- **Thread Safety:** All function pointers initialized upfront before game uses them
- **Logging:** Creates `uni2_bypass.log` in game directory (auto-clears on each launch)

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
- `DLC/` - DLC content

**No `d` folder required!**
