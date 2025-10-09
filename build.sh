#!/bin/bash
echo "UNI2 D Folder Bypass - WSL Build"
echo "================================="
echo

GAME_DIR="/mnt/c/Program Files (x86)/Steam/steamapps/common/UNDER NIGHT IN-BIRTH II Sys Celes"

echo "Building winmm.dll (WinMM Proxy DLL)..."
i686-w64-mingw32-g++ -m32 -shared -O2 -o winmm.dll winmm.cpp winmm.def -lkernel32 -s -static-libgcc -static-libstdc++

if [ $? -ne 0 ]; then
    echo "[ERROR] winmm.dll build failed!"
    exit 1
fi
echo "[OK] winmm.dll created"
echo

echo "Creating steam_appid.txt..."
echo "2076010" > steam_appid.txt
echo "[OK] steam_appid.txt created"
echo

echo "Creating default nuuni.ini..."
cat > nuuni.ini << 'EOF'
# NuUni Bypass Configuration
# Generated automatically - feel free to edit!

# Enable logging to uni2_bypass.log (0 = disabled, 1 = enabled)
# Default: 0 (off) - enable for troubleshooting
log = 0

# CSS Portrait limit (0 = uncapped, or set a specific limit)
# Default is 100 (0x64). Reduce if you have display issues.
# Examples: 32 (vanilla), 64, 100 (default), 0 (unlimited)
portrait_limit = 100

# Note: Changes take effect after restarting the game
EOF
echo "[OK] nuuni.ini created"
echo

echo "Copying to game folder..."
cp -f winmm.dll "$GAME_DIR/" 2>/dev/null
cp -f steam_appid.txt "$GAME_DIR/" 2>/dev/null

# Copy nuuni.ini only if it doesn't exist (don't overwrite user settings)
if [ ! -f "$GAME_DIR/nuuni.ini" ]; then
    cp -f nuuni.ini "$GAME_DIR/" 2>/dev/null
    echo "[OK] nuuni.ini created in game folder (first time)"
else
    echo "[OK] nuuni.ini already exists, preserving user settings"
fi

if [ $? -eq 0 ]; then
    echo "[OK] Files copied to: $GAME_DIR"
else
    echo "[WARNING] Could not auto-copy - copy manually"
fi

echo
echo "================================="
echo " Build Complete!"
echo "================================="
echo
ls -lh winmm.dll steam_appid.txt nuuni.ini 2>/dev/null
echo
echo "USAGE: Drop winmm.dll, steam_appid.txt, and nuuni.ini in game folder!"
echo "Configure settings in nuuni.ini (logging, portrait limits, etc.)"
echo "Works seamlessly with Steam and requires no launcher."

