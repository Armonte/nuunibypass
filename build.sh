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

echo "Copying to game folder..."
cp -f winmm.dll "$GAME_DIR/" 2>/dev/null
cp -f steam_appid.txt "$GAME_DIR/" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "[OK] Copied to: $GAME_DIR"
else
    echo "[WARNING] Could not auto-copy - copy manually"
fi

echo
echo "================================="
echo " Build Complete!"
echo "================================="
echo
ls -lh winmm.dll steam_appid.txt 2>/dev/null
echo
echo "USAGE: Drop winmm.dll and steam_appid.txt in game folder - auto-loads with game!"
echo "Works seamlessly with Steam and requires no launcher."

