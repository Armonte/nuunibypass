// UNI2 D Folder Bypass - WinMM Proxy (Pattern-Based)
// Uses pattern scanning to work across game updates

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include "pattern_scanner.h"

// Real WinMM DLL handle
HMODULE hRealWinMM = nullptr;

// Function pointers - initialized in DllMain
FARPROC p_timeGetTime = nullptr;
FARPROC p_timeBeginPeriod = nullptr;
FARPROC p_timeEndPeriod = nullptr;
FARPROC p_timeGetDevCaps = nullptr;
FARPROC p_timeGetSystemTime = nullptr;
FARPROC p_timeSetEvent = nullptr;
FARPROC p_timeKillEvent = nullptr;
FARPROC p_mciSendCommandA = nullptr;
FARPROC p_mciSendStringA = nullptr;
FARPROC p_mciGetErrorStringA = nullptr;
FARPROC p_waveOutOpen = nullptr;
FARPROC p_waveOutClose = nullptr;
FARPROC p_waveOutPrepareHeader = nullptr;
FARPROC p_waveOutUnprepareHeader = nullptr;
FARPROC p_waveOutWrite = nullptr;
FARPROC p_waveOutGetPosition = nullptr;
FARPROC p_waveOutGetVolume = nullptr;
FARPROC p_waveOutSetVolume = nullptr;
FARPROC p_waveOutGetNumDevs = nullptr;
FARPROC p_waveOutGetDevCapsA = nullptr;
FARPROC p_waveOutGetDevCapsW = nullptr;
FARPROC p_waveOutReset = nullptr;
FARPROC p_waveOutMessage = nullptr;
FARPROC p_waveOutGetErrorTextA = nullptr;
FARPROC p_waveOutGetErrorTextW = nullptr;
FARPROC p_waveInOpen = nullptr;
FARPROC p_waveInClose = nullptr;
FARPROC p_waveInPrepareHeader = nullptr;
FARPROC p_waveInUnprepareHeader = nullptr;
FARPROC p_waveInAddBuffer = nullptr;
FARPROC p_waveInStart = nullptr;
FARPROC p_waveInStop = nullptr;
FARPROC p_waveInReset = nullptr;
FARPROC p_waveInGetNumDevs = nullptr;
FARPROC p_waveInGetDevCapsA = nullptr;
FARPROC p_waveInGetDevCapsW = nullptr;
FARPROC p_waveInMessage = nullptr;
FARPROC p_waveInGetErrorTextA = nullptr;
FARPROC p_waveInGetErrorTextW = nullptr;
FARPROC p_mixerOpen = nullptr;
FARPROC p_mixerClose = nullptr;
FARPROC p_mixerGetControlDetailsA = nullptr;
FARPROC p_mixerGetLineControlsA = nullptr;
FARPROC p_mixerGetLineInfoA = nullptr;
FARPROC p_mixerSetControlDetails = nullptr;
FARPROC p_mixerGetID = nullptr;
FARPROC p_mixerGetDevCapsA = nullptr;
FARPROC p_mixerGetDevCapsW = nullptr;
FARPROC p_mixerGetNumDevs = nullptr;
FARPROC p_midiOutGetErrorTextW = nullptr;
FARPROC p_midiOutGetErrorTextA = nullptr;
FARPROC p_midiOutGetNumDevs = nullptr;
FARPROC p_midiOutOpen = nullptr;
FARPROC p_midiOutClose = nullptr;
FARPROC p_midiOutPrepareHeader = nullptr;
FARPROC p_midiOutUnprepareHeader = nullptr;
FARPROC p_midiOutShortMsg = nullptr;
FARPROC p_midiOutLongMsg = nullptr;
FARPROC p_midiOutReset = nullptr;
FARPROC p_midiOutGetDevCapsA = nullptr;
FARPROC p_midiOutGetDevCapsW = nullptr;
FARPROC p_midiOutGetVolume = nullptr;
FARPROC p_midiOutSetVolume = nullptr;
FARPROC p_midiOutMessage = nullptr;
FARPROC p_midiInGetNumDevs = nullptr;
FARPROC p_midiInGetDevCapsA = nullptr;
FARPROC p_midiInGetDevCapsW = nullptr;
FARPROC p_midiInOpen = nullptr;
FARPROC p_midiInClose = nullptr;
FARPROC p_midiInPrepareHeader = nullptr;
FARPROC p_midiInUnprepareHeader = nullptr;
FARPROC p_midiInAddBuffer = nullptr;
FARPROC p_midiInStart = nullptr;
FARPROC p_midiInStop = nullptr;
FARPROC p_midiInReset = nullptr;
FARPROC p_midiInMessage = nullptr;
FARPROC p_midiInGetErrorTextA = nullptr;
FARPROC p_midiInGetErrorTextW = nullptr;
FARPROC p_PlaySoundA = nullptr;
FARPROC p_PlaySoundW = nullptr;
FARPROC p_sndPlaySoundA = nullptr;
FARPROC p_sndPlaySoundW = nullptr;

static bool g_logInitialized = false;

void WriteLog(const char* msg) {
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

    p_timeGetTime = GetProcAddress(hRealWinMM, "timeGetTime");
    p_timeBeginPeriod = GetProcAddress(hRealWinMM, "timeBeginPeriod");
    p_timeEndPeriod = GetProcAddress(hRealWinMM, "timeEndPeriod");
    p_timeGetDevCaps = GetProcAddress(hRealWinMM, "timeGetDevCaps");
    p_timeGetSystemTime = GetProcAddress(hRealWinMM, "timeGetSystemTime");
    p_timeSetEvent = GetProcAddress(hRealWinMM, "timeSetEvent");
    p_timeKillEvent = GetProcAddress(hRealWinMM, "timeKillEvent");
    p_mciSendCommandA = GetProcAddress(hRealWinMM, "mciSendCommandA");
    p_mciSendStringA = GetProcAddress(hRealWinMM, "mciSendStringA");
    p_mciGetErrorStringA = GetProcAddress(hRealWinMM, "mciGetErrorStringA");
    p_waveOutOpen = GetProcAddress(hRealWinMM, "waveOutOpen");
    p_waveOutClose = GetProcAddress(hRealWinMM, "waveOutClose");
    p_waveOutPrepareHeader = GetProcAddress(hRealWinMM, "waveOutPrepareHeader");
    p_waveOutUnprepareHeader = GetProcAddress(hRealWinMM, "waveOutUnprepareHeader");
    p_waveOutWrite = GetProcAddress(hRealWinMM, "waveOutWrite");
    p_waveOutGetPosition = GetProcAddress(hRealWinMM, "waveOutGetPosition");
    p_waveOutGetVolume = GetProcAddress(hRealWinMM, "waveOutGetVolume");
    p_waveOutSetVolume = GetProcAddress(hRealWinMM, "waveOutSetVolume");
    p_waveOutGetNumDevs = GetProcAddress(hRealWinMM, "waveOutGetNumDevs");
    p_waveOutGetDevCapsA = GetProcAddress(hRealWinMM, "waveOutGetDevCapsA");
    p_waveOutGetDevCapsW = GetProcAddress(hRealWinMM, "waveOutGetDevCapsW");
    p_waveOutReset = GetProcAddress(hRealWinMM, "waveOutReset");
    p_waveOutMessage = GetProcAddress(hRealWinMM, "waveOutMessage");
    p_waveOutGetErrorTextA = GetProcAddress(hRealWinMM, "waveOutGetErrorTextA");
    p_waveOutGetErrorTextW = GetProcAddress(hRealWinMM, "waveOutGetErrorTextW");
    p_waveInOpen = GetProcAddress(hRealWinMM, "waveInOpen");
    p_waveInClose = GetProcAddress(hRealWinMM, "waveInClose");
    p_waveInPrepareHeader = GetProcAddress(hRealWinMM, "waveInPrepareHeader");
    p_waveInUnprepareHeader = GetProcAddress(hRealWinMM, "waveInUnprepareHeader");
    p_waveInAddBuffer = GetProcAddress(hRealWinMM, "waveInAddBuffer");
    p_waveInStart = GetProcAddress(hRealWinMM, "waveInStart");
    p_waveInStop = GetProcAddress(hRealWinMM, "waveInStop");
    p_waveInReset = GetProcAddress(hRealWinMM, "waveInReset");
    p_waveInGetNumDevs = GetProcAddress(hRealWinMM, "waveInGetNumDevs");
    p_waveInGetDevCapsA = GetProcAddress(hRealWinMM, "waveInGetDevCapsA");
    p_waveInGetDevCapsW = GetProcAddress(hRealWinMM, "waveInGetDevCapsW");
    p_waveInMessage = GetProcAddress(hRealWinMM, "waveInMessage");
    p_waveInGetErrorTextA = GetProcAddress(hRealWinMM, "waveInGetErrorTextA");
    p_waveInGetErrorTextW = GetProcAddress(hRealWinMM, "waveInGetErrorTextW");
    p_mixerOpen = GetProcAddress(hRealWinMM, "mixerOpen");
    p_mixerClose = GetProcAddress(hRealWinMM, "mixerClose");
    p_mixerGetControlDetailsA = GetProcAddress(hRealWinMM, "mixerGetControlDetailsA");
    p_mixerGetLineControlsA = GetProcAddress(hRealWinMM, "mixerGetLineControlsA");
    p_mixerGetLineInfoA = GetProcAddress(hRealWinMM, "mixerGetLineInfoA");
    p_mixerSetControlDetails = GetProcAddress(hRealWinMM, "mixerSetControlDetails");
    p_mixerGetID = GetProcAddress(hRealWinMM, "mixerGetID");
    p_mixerGetDevCapsA = GetProcAddress(hRealWinMM, "mixerGetDevCapsA");
    p_mixerGetDevCapsW = GetProcAddress(hRealWinMM, "mixerGetDevCapsW");
    p_mixerGetNumDevs = GetProcAddress(hRealWinMM, "mixerGetNumDevs");
    p_midiOutGetErrorTextW = GetProcAddress(hRealWinMM, "midiOutGetErrorTextW");
    p_midiOutGetErrorTextA = GetProcAddress(hRealWinMM, "midiOutGetErrorTextA");
    p_midiOutGetNumDevs = GetProcAddress(hRealWinMM, "midiOutGetNumDevs");
    p_midiOutOpen = GetProcAddress(hRealWinMM, "midiOutOpen");
    p_midiOutClose = GetProcAddress(hRealWinMM, "midiOutClose");
    p_midiOutPrepareHeader = GetProcAddress(hRealWinMM, "midiOutPrepareHeader");
    p_midiOutUnprepareHeader = GetProcAddress(hRealWinMM, "midiOutUnprepareHeader");
    p_midiOutShortMsg = GetProcAddress(hRealWinMM, "midiOutShortMsg");
    p_midiOutLongMsg = GetProcAddress(hRealWinMM, "midiOutLongMsg");
    p_midiOutReset = GetProcAddress(hRealWinMM, "midiOutReset");
    p_midiOutGetDevCapsA = GetProcAddress(hRealWinMM, "midiOutGetDevCapsA");
    p_midiOutGetDevCapsW = GetProcAddress(hRealWinMM, "midiOutGetDevCapsW");
    p_midiOutGetVolume = GetProcAddress(hRealWinMM, "midiOutGetVolume");
    p_midiOutSetVolume = GetProcAddress(hRealWinMM, "midiOutSetVolume");
    p_midiOutMessage = GetProcAddress(hRealWinMM, "midiOutMessage");
    p_midiInGetNumDevs = GetProcAddress(hRealWinMM, "midiInGetNumDevs");
    p_midiInGetDevCapsA = GetProcAddress(hRealWinMM, "midiInGetDevCapsA");
    p_midiInGetDevCapsW = GetProcAddress(hRealWinMM, "midiInGetDevCapsW");
    p_midiInOpen = GetProcAddress(hRealWinMM, "midiInOpen");
    p_midiInClose = GetProcAddress(hRealWinMM, "midiInClose");
    p_midiInPrepareHeader = GetProcAddress(hRealWinMM, "midiInPrepareHeader");
    p_midiInUnprepareHeader = GetProcAddress(hRealWinMM, "midiInUnprepareHeader");
    p_midiInAddBuffer = GetProcAddress(hRealWinMM, "midiInAddBuffer");
    p_midiInStart = GetProcAddress(hRealWinMM, "midiInStart");
    p_midiInStop = GetProcAddress(hRealWinMM, "midiInStop");
    p_midiInReset = GetProcAddress(hRealWinMM, "midiInReset");
    p_midiInMessage = GetProcAddress(hRealWinMM, "midiInMessage");
    p_midiInGetErrorTextA = GetProcAddress(hRealWinMM, "midiInGetErrorTextA");
    p_midiInGetErrorTextW = GetProcAddress(hRealWinMM, "midiInGetErrorTextW");
    p_PlaySoundA = GetProcAddress(hRealWinMM, "PlaySoundA");
    p_PlaySoundW = GetProcAddress(hRealWinMM, "PlaySoundW");
    p_sndPlaySoundA = GetProcAddress(hRealWinMM, "sndPlaySoundA");
    p_sndPlaySoundW = GetProcAddress(hRealWinMM, "sndPlaySoundW");

    WriteLog("Function pointers initialized!");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        WriteLog("=== UNI2 Bypass DLL Loaded ===");

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

        // Fallback hardcoded addresses (IDA-based)
        const DWORD IDA_BASE = 0x400000;
        BYTE* exeBase = (BYTE*)hGameModule;
        BYTE* fallback1 = exeBase + (0x4BA80C - IDA_BASE);
        BYTE* fallback2 = exeBase + (0x4BA96D - IDA_BASE);
        BYTE* fallback3 = exeBase + (0x8DA1FD - IDA_BASE);

        // Pattern 1: E8 ?? ?? ?? ?? 84 C0 74 69
        WriteLog("Searching for Pattern 1...");
        const BYTE pattern1[] = "\xE8\x00\x00\x00\x00\x84\xC0\x74\x69";
        const char mask1[] = "x????xxxx";
        BYTE* patch1 = PatternScanModule(hGameModule, pattern1, mask1);
        if (!patch1) {
            WriteLog("  Pattern not found, trying fallback address...");
            patch1 = fallback1;
        }
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
            WriteLog("  Status: NOT FOUND");
        }

        // Pattern 2: E8 ?? ?? ?? ?? 84 C0 74 3A
        WriteLog("Searching for Pattern 2...");
        const BYTE pattern2[] = "\xE8\x00\x00\x00\x00\x84\xC0\x74\x3A";
        const char mask2[] = "x????xxxx";
        BYTE* patch2 = PatternScanModule(hGameModule, pattern2, mask2);
        if (!patch2) {
            WriteLog("  Pattern not found, trying fallback address...");
            patch2 = fallback2;
        }
        if (patch2) {
            sprintf(buf, "  Found at: 0x%p", patch2);
            WriteLog(buf);
        }
        if (patch2 && VirtualProtect(patch2, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            patch2[0] = 0x30; patch2[1] = 0xC0; patch2[2] = 0x90; patch2[3] = 0x90; patch2[4] = 0x90;
            VirtualProtect(patch2, 5, oldProtect, &oldProtect);
            WriteLog("Patch 2: SUCCESS");
            patchCount++;
        } else {
            WriteLog("Patch 2: FAILED");
        }

        // Pattern 3: 84 C0 75 08 6A FF
        WriteLog("Searching for Pattern 3...");
        const BYTE pattern3[] = "\x84\xC0\x75\x08\x6A\xFF";
        const char mask3[] = "xxxxxx";
        BYTE* patch3 = PatternScanModule(hGameModule, pattern3, mask3);
        if (!patch3) {
            WriteLog("  Pattern not found, trying fallback address...");
            patch3 = fallback3;
        }
        if (patch3) {
            sprintf(buf, "  Found at: 0x%p", patch3);
            WriteLog(buf);
        }
        if (patch3 && VirtualProtect(patch3 + 2, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            patch3[2] = 0xEB;
            VirtualProtect(patch3 + 2, 1, oldProtect, &oldProtect);
            WriteLog("Patch 3: SUCCESS");
            patchCount++;
        } else {
            WriteLog("Patch 3: FAILED");
        }

        sprintf(buf, "Total: %d/3 patches applied", patchCount);
        WriteLog(buf);
        WriteLog("=== DllMain Complete ===");
    }
    return TRUE;
}

// Export the WinMM functions that the game needs
extern "C" {

#define EXPORT __declspec(dllexport)

// Time functions (most commonly used by games)
EXPORT DWORD WINAPI timeGetTime() {
    return p_timeGetTime ? ((DWORD(WINAPI*)())p_timeGetTime)() : 0;
}

EXPORT DWORD WINAPI timeBeginPeriod(DWORD period) {
    return p_timeBeginPeriod ? ((DWORD(WINAPI*)(DWORD))p_timeBeginPeriod)(period) : 0;
}

EXPORT DWORD WINAPI timeEndPeriod(DWORD period) {
    return p_timeEndPeriod ? ((DWORD(WINAPI*)(DWORD))p_timeEndPeriod)(period) : 0;
}

EXPORT DWORD WINAPI timeGetDevCaps(void* ptc, DWORD cbtc) {
    return p_timeGetDevCaps ? ((DWORD(WINAPI*)(void*, DWORD))p_timeGetDevCaps)(ptc, cbtc) : 0;
}

EXPORT DWORD WINAPI timeGetSystemTime(void* pmmt, DWORD cbmmt) {
    return p_timeGetSystemTime ? ((DWORD(WINAPI*)(void*, DWORD))p_timeGetSystemTime)(pmmt, cbmmt) : 0;
}

EXPORT DWORD WINAPI timeSetEvent(DWORD a, DWORD b, void* c, DWORD d, DWORD e) {
    return p_timeSetEvent ? ((DWORD(WINAPI*)(DWORD, DWORD, void*, DWORD, DWORD))p_timeSetEvent)(a, b, c, d, e) : 0;
}

EXPORT DWORD WINAPI timeKillEvent(DWORD a) {
    return p_timeKillEvent ? ((DWORD(WINAPI*)(DWORD))p_timeKillEvent)(a) : 0;
}

// MCI functions
EXPORT DWORD WINAPI mciSendCommandA(DWORD a, DWORD b, DWORD c, DWORD d) {
    return p_mciSendCommandA ? ((DWORD(WINAPI*)(DWORD, DWORD, DWORD, DWORD))p_mciSendCommandA)(a, b, c, d) : 0;
}

EXPORT DWORD WINAPI mciSendStringA(void* a, void* b, DWORD c, void* d) {
    return p_mciSendStringA ? ((DWORD(WINAPI*)(void*, void*, DWORD, void*))p_mciSendStringA)(a, b, c, d) : 0;
}

EXPORT DWORD WINAPI mciGetErrorStringA(DWORD a, void* b, DWORD c) {
    return p_mciGetErrorStringA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_mciGetErrorStringA)(a, b, c) : 0;
}
// Wave Out functions
EXPORT DWORD WINAPI waveOutOpen(void* a, DWORD b, void* c, DWORD d, DWORD e, DWORD f) {
    return p_waveOutOpen ? ((DWORD(WINAPI*)(void*, DWORD, void*, DWORD, DWORD, DWORD))p_waveOutOpen)(a, b, c, d, e, f) : 0;
}

EXPORT DWORD WINAPI waveOutClose(void* a) {
    return p_waveOutClose ? ((DWORD(WINAPI*)(void*))p_waveOutClose)(a) : 0;
}

EXPORT DWORD WINAPI waveOutPrepareHeader(void* a, void* b, DWORD c) {
    return p_waveOutPrepareHeader ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_waveOutPrepareHeader)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveOutUnprepareHeader(void* a, void* b, DWORD c) {
    return p_waveOutUnprepareHeader ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_waveOutUnprepareHeader)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveOutWrite(void* a, void* b, DWORD c) {
    return p_waveOutWrite ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_waveOutWrite)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveOutGetPosition(void* a, void* b, DWORD c) {
    return p_waveOutGetPosition ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_waveOutGetPosition)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveOutGetVolume(void* a, void* b) {
    return p_waveOutGetVolume ? ((DWORD(WINAPI*)(void*, void*))p_waveOutGetVolume)(a, b) : 0;
}

EXPORT DWORD WINAPI waveOutSetVolume(void* a, DWORD b) {
    return p_waveOutSetVolume ? ((DWORD(WINAPI*)(void*, DWORD))p_waveOutSetVolume)(a, b) : 0;
}

EXPORT DWORD WINAPI waveOutGetNumDevs() {
    return p_waveOutGetNumDevs ? ((DWORD(WINAPI*)())p_waveOutGetNumDevs)() : 0;
}

EXPORT DWORD WINAPI waveOutGetDevCapsA(DWORD a, void* b, DWORD c) {
    return p_waveOutGetDevCapsA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_waveOutGetDevCapsA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveOutGetDevCapsW(DWORD a, void* b, DWORD c) {
    return p_waveOutGetDevCapsW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_waveOutGetDevCapsW)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveOutReset(void* a) {
    return p_waveOutReset ? ((DWORD(WINAPI*)(void*))p_waveOutReset)(a) : 0;
}

EXPORT DWORD WINAPI waveOutMessage(void* a, DWORD b, DWORD c, DWORD d) {
    return p_waveOutMessage ? ((DWORD(WINAPI*)(void*, DWORD, DWORD, DWORD))p_waveOutMessage)(a, b, c, d) : 0;
}

EXPORT DWORD WINAPI waveOutGetErrorTextA(DWORD a, void* b, DWORD c) {
    return p_waveOutGetErrorTextA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_waveOutGetErrorTextA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveOutGetErrorTextW(DWORD a, void* b, DWORD c) {
    return p_waveOutGetErrorTextW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_waveOutGetErrorTextW)(a, b, c) : 0;
}

// Wave In functions
EXPORT DWORD WINAPI waveInOpen(void* a, DWORD b, void* c, DWORD d, DWORD e, DWORD f) {
    return p_waveInOpen ? ((DWORD(WINAPI*)(void*, DWORD, void*, DWORD, DWORD, DWORD))p_waveInOpen)(a, b, c, d, e, f) : 0;
}

EXPORT DWORD WINAPI waveInClose(void* a) {
    return p_waveInClose ? ((DWORD(WINAPI*)(void*))p_waveInClose)(a) : 0;
}

EXPORT DWORD WINAPI waveInPrepareHeader(void* a, void* b, DWORD c) {
    return p_waveInPrepareHeader ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_waveInPrepareHeader)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveInUnprepareHeader(void* a, void* b, DWORD c) {
    return p_waveInUnprepareHeader ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_waveInUnprepareHeader)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveInAddBuffer(void* a, void* b, DWORD c) {
    return p_waveInAddBuffer ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_waveInAddBuffer)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveInStart(void* a) {
    return p_waveInStart ? ((DWORD(WINAPI*)(void*))p_waveInStart)(a) : 0;
}

EXPORT DWORD WINAPI waveInStop(void* a) {
    return p_waveInStop ? ((DWORD(WINAPI*)(void*))p_waveInStop)(a) : 0;
}

EXPORT DWORD WINAPI waveInReset(void* a) {
    return p_waveInReset ? ((DWORD(WINAPI*)(void*))p_waveInReset)(a) : 0;
}

EXPORT DWORD WINAPI waveInGetNumDevs() {
    return p_waveInGetNumDevs ? ((DWORD(WINAPI*)())p_waveInGetNumDevs)() : 0;
}

EXPORT DWORD WINAPI waveInGetDevCapsA(DWORD a, void* b, DWORD c) {
    return p_waveInGetDevCapsA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_waveInGetDevCapsA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveInGetDevCapsW(DWORD a, void* b, DWORD c) {
    return p_waveInGetDevCapsW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_waveInGetDevCapsW)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveInMessage(void* a, DWORD b, DWORD c, DWORD d) {
    return p_waveInMessage ? ((DWORD(WINAPI*)(void*, DWORD, DWORD, DWORD))p_waveInMessage)(a, b, c, d) : 0;
}

EXPORT DWORD WINAPI waveInGetErrorTextA(DWORD a, void* b, DWORD c) {
    return p_waveInGetErrorTextA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_waveInGetErrorTextA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI waveInGetErrorTextW(DWORD a, void* b, DWORD c) {
    return p_waveInGetErrorTextW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_waveInGetErrorTextW)(a, b, c) : 0;
}

// Mixer functions
EXPORT DWORD WINAPI mixerOpen(void* a, DWORD b, DWORD c, DWORD d, DWORD e) {
    return p_mixerOpen ? ((DWORD(WINAPI*)(void*, DWORD, DWORD, DWORD, DWORD))p_mixerOpen)(a, b, c, d, e) : 0;
}

EXPORT DWORD WINAPI mixerClose(void* a) {
    return p_mixerClose ? ((DWORD(WINAPI*)(void*))p_mixerClose)(a) : 0;
}

EXPORT DWORD WINAPI mixerGetControlDetailsA(void* a, void* b, DWORD c) {
    return p_mixerGetControlDetailsA ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_mixerGetControlDetailsA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI mixerGetLineControlsA(void* a, void* b, DWORD c) {
    return p_mixerGetLineControlsA ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_mixerGetLineControlsA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI mixerGetLineInfoA(void* a, void* b, DWORD c) {
    return p_mixerGetLineInfoA ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_mixerGetLineInfoA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI mixerSetControlDetails(void* a, void* b, DWORD c) {
    return p_mixerSetControlDetails ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_mixerSetControlDetails)(a, b, c) : 0;
}

EXPORT DWORD WINAPI mixerGetID(void* a, void* b, DWORD c) {
    return p_mixerGetID ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_mixerGetID)(a, b, c) : 0;
}

EXPORT DWORD WINAPI mixerGetDevCapsA(DWORD a, void* b, DWORD c) {
    return p_mixerGetDevCapsA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_mixerGetDevCapsA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI mixerGetDevCapsW(DWORD a, void* b, DWORD c) {
    return p_mixerGetDevCapsW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_mixerGetDevCapsW)(a, b, c) : 0;
}

EXPORT DWORD WINAPI mixerGetNumDevs() {
    return p_mixerGetNumDevs ? ((DWORD(WINAPI*)())p_mixerGetNumDevs)() : 0;
}

// MIDI functions
EXPORT DWORD WINAPI midiOutGetErrorTextW(DWORD a, void* b, DWORD c) {
    return p_midiOutGetErrorTextW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_midiOutGetErrorTextW)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiOutGetErrorTextA(DWORD a, void* b, DWORD c) {
    return p_midiOutGetErrorTextA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_midiOutGetErrorTextA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiOutGetNumDevs() {
    return p_midiOutGetNumDevs ? ((DWORD(WINAPI*)())p_midiOutGetNumDevs)() : 0;
}

EXPORT DWORD WINAPI midiOutOpen(void* a, DWORD b, DWORD c, DWORD d, DWORD e) {
    return p_midiOutOpen ? ((DWORD(WINAPI*)(void*, DWORD, DWORD, DWORD, DWORD))p_midiOutOpen)(a, b, c, d, e) : 0;
}

EXPORT DWORD WINAPI midiOutClose(void* a) {
    return p_midiOutClose ? ((DWORD(WINAPI*)(void*))p_midiOutClose)(a) : 0;
}

EXPORT DWORD WINAPI midiOutPrepareHeader(void* a, void* b, DWORD c) {
    return p_midiOutPrepareHeader ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_midiOutPrepareHeader)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiOutUnprepareHeader(void* a, void* b, DWORD c) {
    return p_midiOutUnprepareHeader ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_midiOutUnprepareHeader)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiOutShortMsg(void* a, DWORD b) {
    return p_midiOutShortMsg ? ((DWORD(WINAPI*)(void*, DWORD))p_midiOutShortMsg)(a, b) : 0;
}

EXPORT DWORD WINAPI midiOutLongMsg(void* a, void* b, DWORD c) {
    return p_midiOutLongMsg ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_midiOutLongMsg)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiOutReset(void* a) {
    return p_midiOutReset ? ((DWORD(WINAPI*)(void*))p_midiOutReset)(a) : 0;
}

EXPORT DWORD WINAPI midiOutGetDevCapsA(DWORD a, void* b, DWORD c) {
    return p_midiOutGetDevCapsA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_midiOutGetDevCapsA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiOutGetDevCapsW(DWORD a, void* b, DWORD c) {
    return p_midiOutGetDevCapsW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_midiOutGetDevCapsW)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiOutGetVolume(void* a, void* b) {
    return p_midiOutGetVolume ? ((DWORD(WINAPI*)(void*, void*))p_midiOutGetVolume)(a, b) : 0;
}

EXPORT DWORD WINAPI midiOutSetVolume(void* a, DWORD b) {
    return p_midiOutSetVolume ? ((DWORD(WINAPI*)(void*, DWORD))p_midiOutSetVolume)(a, b) : 0;
}

EXPORT DWORD WINAPI midiOutMessage(void* a, DWORD b, DWORD c, DWORD d) {
    return p_midiOutMessage ? ((DWORD(WINAPI*)(void*, DWORD, DWORD, DWORD))p_midiOutMessage)(a, b, c, d) : 0;
}

EXPORT DWORD WINAPI midiInGetNumDevs() {
    return p_midiInGetNumDevs ? ((DWORD(WINAPI*)())p_midiInGetNumDevs)() : 0;
}

EXPORT DWORD WINAPI midiInGetDevCapsA(DWORD a, void* b, DWORD c) {
    return p_midiInGetDevCapsA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_midiInGetDevCapsA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiInGetDevCapsW(DWORD a, void* b, DWORD c) {
    return p_midiInGetDevCapsW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_midiInGetDevCapsW)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiInOpen(void* a, DWORD b, DWORD c, DWORD d, DWORD e) {
    return p_midiInOpen ? ((DWORD(WINAPI*)(void*, DWORD, DWORD, DWORD, DWORD))p_midiInOpen)(a, b, c, d, e) : 0;
}

EXPORT DWORD WINAPI midiInClose(void* a) {
    return p_midiInClose ? ((DWORD(WINAPI*)(void*))p_midiInClose)(a) : 0;
}

EXPORT DWORD WINAPI midiInPrepareHeader(void* a, void* b, DWORD c) {
    return p_midiInPrepareHeader ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_midiInPrepareHeader)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiInUnprepareHeader(void* a, void* b, DWORD c) {
    return p_midiInUnprepareHeader ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_midiInUnprepareHeader)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiInAddBuffer(void* a, void* b, DWORD c) {
    return p_midiInAddBuffer ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_midiInAddBuffer)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiInStart(void* a) {
    return p_midiInStart ? ((DWORD(WINAPI*)(void*))p_midiInStart)(a) : 0;
}

EXPORT DWORD WINAPI midiInStop(void* a) {
    return p_midiInStop ? ((DWORD(WINAPI*)(void*))p_midiInStop)(a) : 0;
}

EXPORT DWORD WINAPI midiInReset(void* a) {
    return p_midiInReset ? ((DWORD(WINAPI*)(void*))p_midiInReset)(a) : 0;
}

EXPORT DWORD WINAPI midiInMessage(void* a, DWORD b, DWORD c, DWORD d) {
    return p_midiInMessage ? ((DWORD(WINAPI*)(void*, DWORD, DWORD, DWORD))p_midiInMessage)(a, b, c, d) : 0;
}

EXPORT DWORD WINAPI midiInGetErrorTextA(DWORD a, void* b, DWORD c) {
    return p_midiInGetErrorTextA ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_midiInGetErrorTextA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI midiInGetErrorTextW(DWORD a, void* b, DWORD c) {
    return p_midiInGetErrorTextW ? ((DWORD(WINAPI*)(DWORD, void*, DWORD))p_midiInGetErrorTextW)(a, b, c) : 0;
}

// Sound playback functions
EXPORT DWORD WINAPI PlaySoundA(void* a, void* b, DWORD c) {
    return p_PlaySoundA ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_PlaySoundA)(a, b, c) : 0;
}

EXPORT DWORD WINAPI PlaySoundW(void* a, void* b, DWORD c) {
    return p_PlaySoundW ? ((DWORD(WINAPI*)(void*, void*, DWORD))p_PlaySoundW)(a, b, c) : 0;
}

EXPORT DWORD WINAPI sndPlaySoundA(void* a, DWORD b) {
    return p_sndPlaySoundA ? ((DWORD(WINAPI*)(void*, DWORD))p_sndPlaySoundA)(a, b) : 0;
}

EXPORT DWORD WINAPI sndPlaySoundW(void* a, DWORD b) {
    return p_sndPlaySoundW ? ((DWORD(WINAPI*)(void*, DWORD))p_sndPlaySoundW)(a, b) : 0;
}
}
