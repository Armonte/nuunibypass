// UNI2 D Folder Bypass - WinMM Proxy (Pattern-Based)
// Uses pattern scanning to work across game updates

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include "pattern_scanner.h"
#include "nuuni_config.h"
#include "geo_patches.h"

// Global config instance
NuUniConfigManager* g_Config = nullptr;

// Real WinMM DLL handle
HMODULE hRealWinMM = nullptr;

// Include all winmm exports
#include "winmm_exports.h"

static bool g_logInitialized = false;

void WriteLog(const char* msg) {
    // Skip logging if disabled in config
    if (!IsLoggingEnabled()) {
        return;
    }
    
    const char* mode = g_logInitialized ? "a" : "w";
    g_logInitialized = true;

    FILE* log = fopen("uni2_bypass.log", mode);
    if (log) {
        fprintf(log, "%s\n", msg);
        fflush(log);
        fclose(log);
    }
}

void InitializeFunctionPointers() {
    if (!hRealWinMM) return;

    WriteLog("Initializing function pointers...");

    // Initialize all function pointers using macro
    #define X(name) INIT_FUNC(name);
    WINMM_FUNCTIONS
    #undef X

    WriteLog("Function pointers initialized!");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Initialize config system FIRST (before any logging)
        g_Config = new NuUniConfigManager();
        g_Config->LoadConfig();
        
        WriteLog("=== UNI2 Bypass DLL Loaded ===");
        
        // Log config settings
        char configBuf[256];
        sprintf(configBuf, "Config: Logging=%s, Portrait Limit=%d", 
                g_Config->IsLoggingEnabled() ? "ON" : "OFF",
                g_Config->GetPortraitLimit());
        WriteLog(configBuf);

        // Check which process loaded us
        char exeName[MAX_PATH];
        GetModuleFileNameA(NULL, exeName, MAX_PATH);
        WriteLog(exeName);

        // Only patch if loaded by uni2.exe, not Steam or other processes
        if (strstr(exeName, "uni2.exe") == NULL) {
            WriteLog("Not loaded by uni2.exe, skipping patches");
            // Still load real winmm for forwarding
            char sysDir[MAX_PATH];
            GetSystemDirectoryA(sysDir, MAX_PATH);
            strcat(sysDir, "\\winmm.dll");
            hRealWinMM = LoadLibraryA(sysDir);
            if (hRealWinMM) {
                InitializeFunctionPointers();
            }
            return TRUE;
        }

        // Load real WinMM from system32
        char sysDir[MAX_PATH];
        GetSystemDirectoryA(sysDir, MAX_PATH);
        strcat(sysDir, "\\winmm.dll");
        hRealWinMM = LoadLibraryA(sysDir);

        if (hRealWinMM) {
            WriteLog("Real winmm.dll loaded successfully");

            // Initialize all function pointers NOW before game tries to use them
            InitializeFunctionPointers();
        } else {
            WriteLog("ERROR: Failed to load real winmm.dll!");
            MessageBoxA(NULL, "Failed to load system winmm.dll!", "UNI2 Bypass Error", MB_OK | MB_ICONERROR);
            return FALSE;
        }

        // Apply patches using pattern scanning
        WriteLog("Applying patches (pattern-based)...");

        HMODULE hGameModule = GetModuleHandleA(NULL);
        int patchCount = 0;
        DWORD oldProtect;
        char buf[256];

        // Pattern 1: E8 ?? ?? ?? ?? 84 C0 74 69
        WriteLog("Searching for Pattern 1...");
        const BYTE pattern1[] = "\xE8\x00\x00\x00\x00\x84\xC0\x74\x69";
        const char mask1[] = "x????xxxx";
        BYTE* patch1 = PatternScanModule(hGameModule, pattern1, mask1);
        if (patch1) {
            sprintf(buf, "  Found at: 0x%p", patch1);
            WriteLog(buf);
            if (VirtualProtect(patch1, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                patch1[0] = 0x30; patch1[1] = 0xC0; patch1[2] = 0x90; patch1[3] = 0x90; patch1[4] = 0x90;
                VirtualProtect(patch1, 5, oldProtect, &oldProtect);
                WriteLog("  Status: PATCHED");
                patchCount++;
            } else {
                WriteLog("  Status: VirtualProtect failed");
            }
        } else {
            WriteLog("  Status: NOT FOUND - Pattern scanning failed");
        }

        // Pattern 2: E8 ?? ?? ?? ?? 84 C0 74 3A
        WriteLog("Searching for Pattern 2...");
        const BYTE pattern2[] = "\xE8\x00\x00\x00\x00\x84\xC0\x74\x3A";
        const char mask2[] = "x????xxxx";
        BYTE* patch2 = PatternScanModule(hGameModule, pattern2, mask2);
        if (patch2) {
            sprintf(buf, "  Found at: 0x%p", patch2);
            WriteLog(buf);
            if (VirtualProtect(patch2, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                patch2[0] = 0x30; patch2[1] = 0xC0; patch2[2] = 0x90; patch2[3] = 0x90; patch2[4] = 0x90;
                VirtualProtect(patch2, 5, oldProtect, &oldProtect);
                WriteLog("  Status: PATCHED");
                patchCount++;
            } else {
                WriteLog("  Status: VirtualProtect failed");
            }
        } else {
            WriteLog("  Status: NOT FOUND - Pattern scanning failed");
        }

        // Pattern 3: 84 C0 75 08 6A FF
        WriteLog("Searching for Pattern 3...");
        const BYTE pattern3[] = "\x84\xC0\x75\x08\x6A\xFF";
        const char mask3[] = "xxxxxx";
        BYTE* patch3 = PatternScanModule(hGameModule, pattern3, mask3);
        if (patch3) {
            sprintf(buf, "  Found at: 0x%p", patch3);
            WriteLog(buf);
            if (VirtualProtect(patch3 + 2, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                patch3[2] = 0xEB;
                VirtualProtect(patch3 + 2, 1, oldProtect, &oldProtect);
                WriteLog("  Status: PATCHED");
                patchCount++;
            } else {
                WriteLog("  Status: VirtualProtect failed");
            }
        } else {
            WriteLog("  Status: NOT FOUND - Pattern scanning failed");
        }

        sprintf(buf, "Total: %d/3 patches applied", patchCount);
        WriteLog(buf);
        
        // Apply Geo's memory expansion patches
        ApplyAllGeoPatches(hGameModule);
        
        WriteLog("=== DllMain Complete ===");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        // Cleanup
        if (g_Config) {
            delete g_Config;
            g_Config = nullptr;
        }
    }
    return TRUE;
}

// Export all winmm functions using macro
extern "C" {
#define EXPORT __declspec(dllexport)

#define X(name) FORWARD_FUNC(name)
WINMM_FUNCTIONS
#undef X

}
