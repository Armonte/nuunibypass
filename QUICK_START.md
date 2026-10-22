# NuUni Bypass - Quick Start

## 🚀 Installation (30 seconds)

1. **Copy files** to game folder:
   - `winmm.dll`
   - `steam_appid.txt`
   - `nuuni.ini`

2. **Launch game** - That's it!

**Game folder:** `C:\Program Files (x86)\Steam\steamapps\common\UNDER NIGHT IN-BIRTH II Sys Celes\`

---

## ⚙️ Configuration

Edit `nuuni.ini` in game folder:

```ini
# Enable/disable logging
log = 1              # 1 = ON (default), 0 = OFF

# Portrait limit (reduce if CSS glitches)
portrait_limit = 100 # 32, 64, 100 (default), 0 (unlimited)
```

**Restart game** after editing config.

---

## 🎮 What You Get

✅ **Load files** from extracted folders (no d folder needed)
✅ **Unlimited palettes** for all characters
✅ **100 CSS portraits** (vs vanilla 32) - configurable
✅ **256 character support** with extended memory
✅ **Expanded character select** data structures

---

## 🐛 Troubleshooting

### Game crashes on CSS
→ Reduce portrait limit in `nuuni.ini`:
```ini
portrait_limit = 64  # Or try 32
```

### Want to debug
→ Enable logging and check `uni2_bypass.log`:
```ini
log = 1
```

### CSS characters look broken
→ Some custom characters may need portrait limit adjustment:
```ini
portrait_limit = 64  # Lower if needed
```

---

## 📊 Success Check

After launching, check `uni2_bypass.log`:

```
=== UNI2 Bypass DLL Loaded ===
Config: Logging=ON, Portrait Limit=100
Total: 3/3 patches applied (D folder)
Palette Bypass: 9/9 patches applied
CSS Portrait Count: 1/1 patch applied (32 -> 100)
Portrait Memory Extension: 3/3 hooks applied
Stack Memory Expansion: 10 patches applied
=== Total Geo Patches Applied: 23 ===
```

**26/26 patches = Perfect!** 🎉

---

## 📚 More Info

- `CONFIG_GUIDE.md` - Detailed config options
- `TESTING_GUIDE.md` - Verification procedures  
- `README.md` - Full technical details

---

**Status:** Production Ready | **Build:** Automatic | **Works with:** Steam & Direct Launch

