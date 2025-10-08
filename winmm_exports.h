// Auto-generated winmm.dll exports
// All functions forward to real winmm.dll

#pragma once
#include <windows.h>

// Macro to declare function pointer
#define DECLARE_FUNC(name) FARPROC p_##name = nullptr

// Macro to initialize function pointer
#define INIT_FUNC(name) p_##name = GetProcAddress(hRealWinMM, #name)

// Macro to export and forward function (generic calling convention)
#define FORWARD_FUNC(name) \
    EXPORT DWORD WINAPI name(void* a, void* b, void* c, void* d, void* e, void* f) { \
        return p_##name ? ((DWORD(WINAPI*)(void*, void*, void*, void*, void*, void*))p_##name)(a, b, c, d, e, f) : 0; \
    }

// List of all winmm functions
#define WINMM_FUNCTIONS \
    X(CloseDriver) \
    X(OpenDriver) \
    X(SendDriverMessage) \
    X(GetDriverModuleHandle) \
    X(DrvGetModuleHandle) \
    X(DriverCallback) \
    X(DefDriverProc) \
    X(timeGetTime) \
    X(timeBeginPeriod) \
    X(timeEndPeriod) \
    X(timeGetDevCaps) \
    X(timeGetSystemTime) \
    X(timeSetEvent) \
    X(timeKillEvent) \
    X(mciSendCommandA) \
    X(mciSendStringA) \
    X(mciGetErrorStringA) \
    X(mciSendCommandW) \
    X(mciSendStringW) \
    X(mciGetErrorStringW) \
    X(mciGetDeviceIDA) \
    X(mciGetDeviceIDW) \
    X(mciExecute) \
    X(mciGetCreatorTask) \
    X(mciGetDeviceIDFromElementIDA) \
    X(mciGetDeviceIDFromElementIDW) \
    X(mciGetDriverData) \
    X(mciGetYieldProc) \
    X(mciSetDriverData) \
    X(mciSetYieldProc) \
    X(mciLoadCommandResource) \
    X(mciFreeCommandResource) \
    X(mciDriverNotify) \
    X(mciDriverYield) \
    X(mmioAdvance) \
    X(mmioAscend) \
    X(mmioClose) \
    X(mmioCreateChunk) \
    X(mmioDescend) \
    X(mmioFlush) \
    X(mmioGetInfo) \
    X(mmioInstallIOProcA) \
    X(mmioInstallIOProcW) \
    X(mmioOpenA) \
    X(mmioOpenW) \
    X(mmioRead) \
    X(mmioRenameA) \
    X(mmioRenameW) \
    X(mmioSeek) \
    X(mmioSendMessage) \
    X(mmioSetBuffer) \
    X(mmioSetInfo) \
    X(mmioStringToFOURCCA) \
    X(mmioStringToFOURCCW) \
    X(mmioWrite) \
    X(mmsystemGetVersion) \
    X(mmTaskBlock) \
    X(mmTaskCreate) \
    X(mmTaskSignal) \
    X(mmTaskYield) \
    X(mmGetCurrentTask) \
    X(mmDrvInstall) \
    X(waveOutOpen) \
    X(waveOutClose) \
    X(waveOutPrepareHeader) \
    X(waveOutUnprepareHeader) \
    X(waveOutWrite) \
    X(waveOutGetPosition) \
    X(waveOutGetVolume) \
    X(waveOutSetVolume) \
    X(waveOutGetNumDevs) \
    X(waveOutGetDevCapsA) \
    X(waveOutGetDevCapsW) \
    X(waveOutReset) \
    X(waveOutMessage) \
    X(waveOutGetErrorTextA) \
    X(waveOutGetErrorTextW) \
    X(waveOutGetID) \
    X(waveOutPause) \
    X(waveOutRestart) \
    X(waveOutBreakLoop) \
    X(waveOutGetPitch) \
    X(waveOutSetPitch) \
    X(waveOutGetPlaybackRate) \
    X(waveOutSetPlaybackRate) \
    X(waveInOpen) \
    X(waveInClose) \
    X(waveInPrepareHeader) \
    X(waveInUnprepareHeader) \
    X(waveInAddBuffer) \
    X(waveInStart) \
    X(waveInStop) \
    X(waveInReset) \
    X(waveInGetNumDevs) \
    X(waveInGetDevCapsA) \
    X(waveInGetDevCapsW) \
    X(waveInMessage) \
    X(waveInGetErrorTextA) \
    X(waveInGetErrorTextW) \
    X(waveInGetID) \
    X(waveInGetPosition) \
    X(mixerOpen) \
    X(mixerClose) \
    X(mixerGetControlDetailsA) \
    X(mixerGetControlDetailsW) \
    X(mixerGetLineControlsA) \
    X(mixerGetLineControlsW) \
    X(mixerGetLineInfoA) \
    X(mixerGetLineInfoW) \
    X(mixerSetControlDetails) \
    X(mixerGetID) \
    X(mixerGetDevCapsA) \
    X(mixerGetDevCapsW) \
    X(mixerGetNumDevs) \
    X(mixerMessage) \
    X(midiOutGetErrorTextW) \
    X(midiOutGetErrorTextA) \
    X(midiOutGetNumDevs) \
    X(midiOutOpen) \
    X(midiOutClose) \
    X(midiOutPrepareHeader) \
    X(midiOutUnprepareHeader) \
    X(midiOutShortMsg) \
    X(midiOutLongMsg) \
    X(midiOutReset) \
    X(midiOutGetDevCapsA) \
    X(midiOutGetDevCapsW) \
    X(midiOutGetVolume) \
    X(midiOutSetVolume) \
    X(midiOutMessage) \
    X(midiOutGetID) \
    X(midiOutCachePatches) \
    X(midiOutCacheDrumPatches) \
    X(midiInGetNumDevs) \
    X(midiInGetDevCapsA) \
    X(midiInGetDevCapsW) \
    X(midiInOpen) \
    X(midiInClose) \
    X(midiInPrepareHeader) \
    X(midiInUnprepareHeader) \
    X(midiInAddBuffer) \
    X(midiInStart) \
    X(midiInStop) \
    X(midiInReset) \
    X(midiInMessage) \
    X(midiInGetErrorTextA) \
    X(midiInGetErrorTextW) \
    X(midiInGetID) \
    X(midiConnect) \
    X(midiDisconnect) \
    X(midiStreamOpen) \
    X(midiStreamClose) \
    X(midiStreamOut) \
    X(midiStreamPause) \
    X(midiStreamPosition) \
    X(midiStreamProperty) \
    X(midiStreamRestart) \
    X(midiStreamStop) \
    X(PlaySoundA) \
    X(PlaySoundW) \
    X(sndPlaySoundA) \
    X(sndPlaySoundW) \
    X(auxGetNumDevs) \
    X(auxGetDevCapsA) \
    X(auxGetDevCapsW) \
    X(auxGetVolume) \
    X(auxSetVolume) \
    X(auxOutMessage) \
    X(joyGetNumDevs) \
    X(joyGetDevCapsA) \
    X(joyGetDevCapsW) \
    X(joyGetPos) \
    X(joyGetPosEx) \
    X(joyGetThreshold) \
    X(joySetThreshold) \
    X(joySetCapture) \
    X(joyReleaseCapture) \
    X(joyConfigChanged)

// Declare all function pointers
#define X(name) DECLARE_FUNC(name);
WINMM_FUNCTIONS
#undef X
