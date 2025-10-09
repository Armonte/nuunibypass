// Geo's Memory Expansion Patches for UNI2
// Ported from Cheat Engine Lua scripts to C++
#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>
#include "pattern_scanner.h"
#include "nuuni_config.h"

extern void WriteLog(const char* msg);

// Helper: Apply a simple byte patch with VirtualProtect
bool ApplyBytePatch(BYTE* address, BYTE newByte, const char* patchName) {
    if (!address) {
        char buf[256];
        sprintf(buf, "  [%s] Address is null, skipping", patchName);
        WriteLog(buf);
        return false;
    }
    
    DWORD oldProtect;
    if (!VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        char buf[256];
        sprintf(buf, "  [%s] VirtualProtect failed at 0x%p", patchName, address);
        WriteLog(buf);
        return false;
    }
    
    *address = newByte;
    VirtualProtect(address, 1, oldProtect, &oldProtect);
    
    char buf[256];
    sprintf(buf, "  [%s] Patched at 0x%p", patchName, address);
    WriteLog(buf);
    return true;
}

// ============================================================================
// PATCH 1: Access All Palettes (9 patches)
// ============================================================================
int ApplyPaletteBypassPatches(HMODULE hGameModule) {
    WriteLog("=== Applying Palette Bypass Patches ===");
    int successCount = 0;
    ModuleBounds bounds = GetModuleTextBounds(hGameModule);
    
    if (!bounds.start) {
        WriteLog("ERROR: Could not get module bounds!");
        return 0;
    }
    
    // Pattern 1: "75 ?? 8B ?? ?? 83 ?? ?? 7C" -> patch byte at offset +8 (0x7C -> 0xEB)
    // Find 2 instances
    {
        WriteLog("Pattern 1: '75 ?? 8B ?? ?? 83 ?? ?? 7C' (2 instances expected)");
        const char* pattern = "75 ?? 8B ?? ?? 83 ?? ?? 7C";
        ParsedPattern parsed = ParsePattern(pattern);
        
        BYTE* addr = PatternScan(bounds.start, bounds.size, parsed.bytes.data(), parsed.mask.c_str());
        if (addr && ApplyBytePatch(addr + 8, 0xEB, "Access_All_Palettes_1")) successCount++;
        
        // Find next instance after first
        if (addr) {
            addr = PatternScanFrom(addr + 1, bounds.end, parsed.bytes.data(), parsed.mask.c_str());
            if (addr && ApplyBytePatch(addr + 8, 0xEB, "Access_All_Palettes_2")) successCount++;
        }
    }
    
    // Pattern 2: "83 ?? ?? 72 ?? 83 ?? ?? 83" -> patch byte at offset +3 (0x72 -> 0xEB)
    // Find 4 instances
    {
        WriteLog("Pattern 2: '83 ?? ?? 72 ?? 83 ?? ?? 83' (4 instances expected)");
        const char* pattern = "83 ?? ?? 72 ?? 83 ?? ?? 83";
        ParsedPattern parsed = ParsePattern(pattern);
        
        BYTE* addr = bounds.start;
        for (int i = 3; i <= 6; i++) {
            addr = PatternScanFrom(addr, bounds.end, parsed.bytes.data(), parsed.mask.c_str());
            if (addr) {
                char name[64];
                sprintf(name, "Access_All_Palettes_%d", i);
                if (ApplyBytePatch(addr + 3, 0xEB, name)) successCount++;
                addr = addr + 1; // Move past this match
            }
        }
    }
    
    // Pattern 3: "83 ?? ?? 7D ?? 83 ?? ?? 72" -> patch byte at offset +8 (0x72 -> 0xEB)
    // Find 3 instances
    {
        WriteLog("Pattern 3: '83 ?? ?? 7D ?? 83 ?? ?? 72' (3 instances expected)");
        const char* pattern = "83 ?? ?? 7D ?? 83 ?? ?? 72";
        ParsedPattern parsed = ParsePattern(pattern);
        
        BYTE* addr = bounds.start;
        for (int i = 7; i <= 9; i++) {
            addr = PatternScanFrom(addr, bounds.end, parsed.bytes.data(), parsed.mask.c_str());
            if (addr) {
                char name[64];
                sprintf(name, "Access_All_Palettes_%d", i);
                if (ApplyBytePatch(addr + 8, 0xEB, name)) successCount++;
                addr = addr + 1; // Move past this match
            }
        }
    }
    
    char buf[256];
    sprintf(buf, "Palette Bypass: %d/9 patches applied", successCount);
    WriteLog(buf);
    return successCount;
}

// ============================================================================
// PATCH 2: CSS Portrait Count Increase (32 -> configurable)
// ============================================================================
int ApplyCSSPortraitCountPatch(HMODULE hGameModule) {
    WriteLog("=== Applying CSS Portrait Count Patch ===");
    
    // Get limit from config
    BYTE portraitLimit = g_Config ? g_Config->GetPortraitLimitByte() : 100;
    int displayLimit = g_Config ? g_Config->GetPortraitLimit() : 100;
    
    char buf[256];
    if (displayLimit == 0 || displayLimit > 255) {
        sprintf(buf, "Portrait limit: UNCAPPED (0x%02X)", portraitLimit);
    } else {
        sprintf(buf, "Portrait limit: %d (0x%02X)", displayLimit, portraitLimit);
    }
    WriteLog(buf);
    
    // Pattern: "83 F8 20 0F 82 58 FC FF FF BE 01 00 00 00 8D 8D FC FC FF FF"
    // Change: 0x20 -> configurable value (default 100/0x64)
    const char* pattern = "83 F8 20 0F 82 58 FC FF FF BE 01 00 00 00 8D 8D FC FC FF FF";
    
    BYTE* addr = PatternScanModuleIDA(hGameModule, pattern);
    if (addr) {
        if (ApplyBytePatch(addr + 2, portraitLimit, "CSS_Portrait_Count")) {
            if (displayLimit == 0 || displayLimit > 255) {
                WriteLog("CSS Portrait Count: 1/1 patch applied (32 -> UNCAPPED)");
            } else {
                sprintf(buf, "CSS Portrait Count: 1/1 patch applied (32 -> %d)", displayLimit);
                WriteLog(buf);
            }
            return 1;
        }
    } else {
        WriteLog("CSS Portrait Count: Pattern not found!");
    }
    
    return 0;
}

// ============================================================================
// PATCH 3: Character Select Extended Portrait Memory
// ============================================================================
struct PortraitMemoryHook {
    BYTE* hookAddress;
    BYTE originalBytes[16];
    int originalBytesSize;
    BYTE* allocatedMemory;
    BYTE* trampolineCode;
};

std::vector<PortraitMemoryHook> g_portraitHooks;
BYTE* g_portraitMemoryBase = nullptr;

int ApplyPortraitMemoryExtension(HMODULE hGameModule) {
    WriteLog("=== Applying Portrait Memory Extension ===");
    
    // Allocate memory for data + trampolines
    const int CHAR_LIMIT = 0x100;
    const int DATA_SIZE = 0x1000 + (CHAR_LIMIT * 4);  // Data storage
    const int TRAMPOLINE_SIZE = 0x1000;                // Executable trampoline code
    const int TOTAL_SIZE = DATA_SIZE + TRAMPOLINE_SIZE;
    
    // Allocate with EXECUTE permission for trampolines
    g_portraitMemoryBase = (BYTE*)VirtualAlloc(nullptr, TOTAL_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_portraitMemoryBase) {
        WriteLog("ERROR: Failed to allocate portrait memory!");
        return 0;
    }
    
    char buf[512];
    sprintf(buf, "Allocated %d bytes at 0x%p for portrait memory", TOTAL_SIZE, g_portraitMemoryBase);
    WriteLog(buf);
    
    // Zero out the data area
    memset(g_portraitMemoryBase, 0, DATA_SIZE);
    
    // Trampoline area starts after data
    BYTE* trampolineArea = g_portraitMemoryBase + DATA_SIZE;
    int trampolineOffset = 0;
    
    int successCount = 0;
    ModuleBounds bounds = GetModuleTextBounds(hGameModule);
    DWORD oldProtect;
    
    // Hook 1: "C6 ?? ?? 02 8D ?? ?? C7 ?? ?? 00 00 00 00"
    // Pattern shows: ... 8D [3 bytes for LEA] C7 [6 more bytes] ...
    // We need to replace the 3-byte LEA (8D XX XX) with JMP to trampoline
    {
        WriteLog("Hook 1: 'C6 ?? ?? 02 8D ?? ?? C7 ?? ?? 00 00 00 00'");
        const char* pattern = "C6 ?? ?? 02 8D ?? ?? C7 ?? ?? 00 00 00 00";
        BYTE* addr = PatternScanModuleIDA(hGameModule, pattern);
        
        if (addr) {
            BYTE* hookPoint = addr + 4;  // Points to the 8D (LEA) instruction
            sprintf(buf, "  Found at 0x%p, LEA at 0x%p", addr, hookPoint);
            WriteLog(buf);
            
            // The LEA is 3 bytes: 8D XX XX (or could be longer, let's check the pattern)
            // Pattern shows 8D ?? ?? = 3 bytes
            // Following is C7 ?? ?? 00 00 00 00 = 7 bytes
            // Total to preserve: 10 bytes starting from LEA
            
            // Build trampoline
            BYTE* trampoline = trampolineArea + trampolineOffset;
            int tIdx = 0;
            
            // LEA EAX, [our_memory] - 5 bytes: B8 + DWORD
            trampoline[tIdx++] = 0xB8;  // MOV EAX, imm32
            *(DWORD*)(trampoline + tIdx) = (DWORD)g_portraitMemoryBase;
            tIdx += 4;
            
            // Copy remaining original bytes (skip first 3 bytes which were the LEA)
            memcpy(trampoline + tIdx, hookPoint + 3, 7);
            tIdx += 7;
            
            // JMP back to after the hook (hookPoint + 10)
            trampoline[tIdx++] = 0xE9;  // JMP rel32
            int32_t jmpOffset = (hookPoint + 10) - (trampoline + tIdx + 4);
            *(int32_t*)(trampoline + tIdx) = jmpOffset;
            tIdx += 4;
            
            sprintf(buf, "  Trampoline at 0x%p, size %d bytes", trampoline, tIdx);
            WriteLog(buf);
            
            // Write JMP at hook point (5 bytes) + NOP padding (5 bytes) = 10 total
            if (VirtualProtect(hookPoint, 10, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                hookPoint[0] = 0xE9;  // JMP rel32
                int32_t jmpToTrampoline = trampoline - (hookPoint + 5);
                *(int32_t*)(hookPoint + 1) = jmpToTrampoline;
                
                // NOP out the remaining 5 bytes
                for (int i = 5; i < 10; i++) {
                    hookPoint[i] = 0x90;
                }
                
                VirtualProtect(hookPoint, 10, oldProtect, &oldProtect);
                trampolineOffset += tIdx;
                WriteLog("  Status: HOOKED (trampoline)");
                successCount++;
            }
        } else {
            WriteLog("  Status: NOT FOUND");
        }
    }
    
    // Hook 2: "0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ??"
    // Similar - LEA at offset +6, need to preserve following bytes
    {
        WriteLog("Hook 2: '0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ??'");
        const char* pattern = "0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ??";
        BYTE* addr = PatternScanModuleIDA(hGameModule, pattern);
        
        if (addr) {
            BYTE* hookPoint = addr + 6;  // Points to 8D (LEA)
            sprintf(buf, "  Found at 0x%p, LEA at 0x%p", addr, hookPoint);
            WriteLog(buf);
            
            // Build trampoline
            BYTE* trampoline = trampolineArea + trampolineOffset;
            int tIdx = 0;
            
            // MOV EAX, our_memory
            trampoline[tIdx++] = 0xB8;
            *(DWORD*)(trampoline + tIdx) = (DWORD)g_portraitMemoryBase;
            tIdx += 4;
            
            // Copy remaining original bytes (skip 3-byte LEA)
            memcpy(trampoline + tIdx, hookPoint + 3, 10);
            tIdx += 10;
            
            // JMP back
            trampoline[tIdx++] = 0xE9;
            int32_t jmpOffset = (hookPoint + 13) - (trampoline + tIdx + 4);
            *(int32_t*)(trampoline + tIdx) = jmpOffset;
            tIdx += 4;
            
            sprintf(buf, "  Trampoline at 0x%p, size %d bytes", trampoline, tIdx);
            WriteLog(buf);
            
            // Write JMP + NOPs
            if (VirtualProtect(hookPoint, 13, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                hookPoint[0] = 0xE9;
                *(int32_t*)(hookPoint + 1) = trampoline - (hookPoint + 5);
                for (int i = 5; i < 13; i++) {
                    hookPoint[i] = 0x90;
                }
                
                VirtualProtect(hookPoint, 13, oldProtect, &oldProtect);
                trampolineOffset += tIdx;
                WriteLog("  Status: HOOKED (trampoline)");
                successCount++;
            }
        } else {
            WriteLog("  Status: NOT FOUND");
        }
    }
    
    // Hook 3: "C7 ?? ?? 00 00 00 00 8D ?? ?? BF ?? ?? ?? ??"
    // LEA ESI + MOV EDI
    {
        WriteLog("Hook 3: 'C7 ?? ?? 00 00 00 00 8D ?? ?? BF ?? ?? ?? ??'");
        const char* pattern = "C7 ?? ?? 00 00 00 00 8D ?? ?? BF ?? ?? ?? ??";
        BYTE* addr = PatternScanModuleIDA(hGameModule, pattern);
        
        if (addr) {
            BYTE* hookPoint = addr + 7;  // Points to 8D (LEA ESI)
            sprintf(buf, "  Found at 0x%p, LEA at 0x%p", addr, hookPoint);
            WriteLog(buf);
            
            // Build trampoline
            BYTE* trampoline = trampolineArea + trampolineOffset;
            int tIdx = 0;
            
            // MOV ESI, our_memory
            trampoline[tIdx++] = 0xBE;
            *(DWORD*)(trampoline + tIdx) = (DWORD)g_portraitMemoryBase;
            tIdx += 4;
            
            // MOV EDI, CHAR_LIMIT (the BF instruction at offset +3 in original)
            trampoline[tIdx++] = 0xBF;
            *(DWORD*)(trampoline + tIdx) = CHAR_LIMIT;
            tIdx += 4;
            
            // JMP back (8 bytes was the hook size)
            trampoline[tIdx++] = 0xE9;
            int32_t jmpOffset = (hookPoint + 8) - (trampoline + tIdx + 4);
            *(int32_t*)(trampoline + tIdx) = jmpOffset;
            tIdx += 4;
            
            sprintf(buf, "  Trampoline at 0x%p, size %d bytes", trampoline, tIdx);
            WriteLog(buf);
            
            // Write JMP + NOPs
            if (VirtualProtect(hookPoint, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                hookPoint[0] = 0xE9;
                *(int32_t*)(hookPoint + 1) = trampoline - (hookPoint + 5);
                for (int i = 5; i < 8; i++) {
                    hookPoint[i] = 0x90;
                }
                
                VirtualProtect(hookPoint, 8, oldProtect, &oldProtect);
                trampolineOffset += tIdx;
                WriteLog("  Status: HOOKED (trampoline)");
                successCount++;
            }
        } else {
            WriteLog("  Status: NOT FOUND");
        }
    }
    
    sprintf(buf, "Portrait Memory Extension: %d/3 hooks applied", successCount);
    WriteLog(buf);
    return successCount;
}

// ============================================================================
// PATCH 4: Character Select Extended Stack Memory (Most Complex)
// ============================================================================

// Helper: Convert DWORD offset to hex byte string for pattern building
void OffsetToByteString(int32_t offset, char* outStr, size_t maxLen) {
    // Little-endian byte order
    BYTE b1 = (offset) & 0xFF;
    BYTE b2 = (offset >> 8) & 0xFF;
    BYTE b3 = (offset >> 16) & 0xFF;
    BYTE b4 = (offset >> 24) & 0xFF;
    
    sprintf(outStr, "%02X %02X %02X %02X", b1, b2, b3, b4);
}

struct StackMemoryPatch {
    BYTE* address;
    int byteOffset; // Offset from address where we modify the ModR/M byte
};

std::vector<StackMemoryPatch> g_stackMemoryRegionOne;
std::vector<StackMemoryPatch> g_stackMemoryRegionTwo;
BYTE* g_stackMemoryBase = nullptr;
int32_t g_origOffset1 = 0;
int32_t g_origOffset2 = 0;

int ApplyStackMemoryExpansion(HMODULE hGameModule) {
    WriteLog("=== Applying Stack Memory Expansion ===");
    
    const int CHAR_LIMIT = 0x100;
    // Need space for two arrays: base array + offset array
    // Each character needs 4 bytes (DWORD pointer)
    // Region One: CHAR_LIMIT * 4 bytes
    // Region Two: CHAR_LIMIT * 4 bytes
    // Total minimum: 0x800 bytes, but allocate 0x2000 for safety
    const int ALLOC_SIZE = 0x2000;
    
    char buf[512];
    
    // Allocate extended stack memory (needs to be readable/writable, not executable)
    g_stackMemoryBase = (BYTE*)VirtualAlloc(nullptr, ALLOC_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_stackMemoryBase) {
        WriteLog("ERROR: Failed to allocate stack memory!");
        return 0;
    }
    
    // Verify the allocation is valid
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(g_stackMemoryBase, &mbi, sizeof(mbi))) {
        sprintf(buf, "Memory check: Base=0x%p, Size=%d, State=%d, Protect=%d", 
                mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect);
        WriteLog(buf);
    }
    sprintf(buf, "Allocated %d bytes at 0x%p for stack memory (Region1: 0x%p, Region2: 0x%p)", 
            ALLOC_SIZE, g_stackMemoryBase, 
            g_stackMemoryBase,
            g_stackMemoryBase + (CHAR_LIMIT * 4));
    WriteLog(buf);
    memset(g_stackMemoryBase, 0, ALLOC_SIZE);
    
    ModuleBounds bounds = GetModuleTextBounds(hGameModule);
    if (!bounds.start) {
        WriteLog("ERROR: Could not get module bounds!");
        return 0;
    }
    
    // ========================================================================
    // STEP 1: Find Region One base pattern and extract original offset
    // ========================================================================
    WriteLog("Step 1: Finding Region One base offset...");
    const char* pattern1 = "8D ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ?? ?? 3B ?? 7C ?? 8B";
    BYTE* addr1 = PatternScanIDA(bounds.start, bounds.size, pattern1);
    
    if (!addr1) {
        WriteLog("  ERROR: Region One base pattern not found!");
        return 0;
    }
    
    // Read original offset at addr1+0x9 (signed int32)
    g_origOffset1 = *(int32_t*)(addr1 + 0x9);
    sprintf(buf, "  Found at 0x%p, original offset: 0x%08X (%d)", addr1, g_origOffset1, g_origOffset1);
    WriteLog(buf);
    
    // Save this location for patching
    g_stackMemoryRegionOne.push_back({addr1 + 0x9, -0x2});
    
    // ========================================================================
    // STEP 2: Find Region Two base pattern and extract original offset
    // ========================================================================
    WriteLog("Step 2: Finding Region Two base offset...");
    const char* pattern2 = "89 ?? ?? ?? ?? ?? ?? 85 ?? 7E";
    BYTE* addr2 = PatternScanFrom(addr1, bounds.end, ParsePattern(pattern2).bytes.data(), 
                                    ParsePattern(pattern2).mask.c_str());
    
    if (!addr2) {
        WriteLog("  ERROR: Region Two base pattern not found!");
        return 0;
    }
    
    // Read original offset at addr2+0x3 (signed int32)
    g_origOffset2 = *(int32_t*)(addr2 + 0x3);
    sprintf(buf, "  Found at 0x%p, original offset: 0x%08X (%d)", addr2, g_origOffset2, g_origOffset2);
    WriteLog(buf);
    
    // Save this location for patching
    g_stackMemoryRegionTwo.push_back({addr2 + 0x3, -0x2});
    
    // ========================================================================
    // STEP 3: Build dynamic patterns using origOffset1 (Region One)
    // ========================================================================
    WriteLog("Step 3: Finding additional Region One references...");
    
    char offsetStr1[64];
    OffsetToByteString(g_origOffset1, offsetStr1, sizeof(offsetStr1));
    sprintf(buf, "  Offset bytes: %s", offsetStr1);
    WriteLog(buf);
    
    // Pattern: "7E ?? 8B ?? ??" + offsetBytes
    // Offset bytes are at position 5 in the pattern
    {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "7E ?? 8B ?? ?? %s", offsetStr1);
        BYTE* addr = PatternScanFrom(addr2, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "  Found '7E ?? 8B ?? ??' variant at 0x%p (offset at +5)", addr);
            WriteLog(buf);
            g_stackMemoryRegionOne.push_back({addr + 5, -0x2});  // Offset bytes are at +5
        } else {
            WriteLog("  Warning: '7E ?? 8B ?? ??' variant not found");
        }
    }
    
    // Pattern: "39 ?? ??" + offsetBytes
    // Offset bytes are at position 3 in the pattern
    {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "39 ?? ?? %s", offsetStr1);
        BYTE* addr = PatternScanFrom(addr2, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "  Found '39 ?? ??' variant at 0x%p (offset at +3)", addr);
            WriteLog(buf);
            g_stackMemoryRegionOne.push_back({addr + 3, -0x2});  // Offset bytes are at +3
        } else {
            WriteLog("  Warning: '39 ?? ??' variant not found");
        }
    }
    
    // ========================================================================
    // STEP 4: Build dynamic patterns using origOffset2 (Region Two)
    // ========================================================================
    WriteLog("Step 4: Finding additional Region Two references...");
    
    char offsetStr2[64];
    OffsetToByteString(g_origOffset2, offsetStr2, sizeof(offsetStr2));
    sprintf(buf, "  Offset bytes: %s", offsetStr2);
    WriteLog(buf);
    
    BYTE* searchStart = addr2;
    
    // Pattern: "89 ?? ??" + offsetBytes + "?? 3B"
    // Offset bytes are at position 3 in the pattern
    {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "89 ?? ?? %s ?? 3B", offsetStr2);
        BYTE* addr = PatternScanFrom(searchStart, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "  Found '89 ?? ??' variant at 0x%p (offset at +3)", addr);
            WriteLog(buf);
            g_stackMemoryRegionTwo.push_back({addr + 3, -0x2});  // Offset bytes at +3
            searchStart = addr + 1;
        } else {
            WriteLog("  Warning: '89 ?? ??' variant not found");
        }
    }
    
    // Pattern: "8B ?? ??" + offsetBytes + "05"
    // Offset bytes are at position 3 in the pattern
    {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "8B ?? ?? %s 05", offsetStr2);
        BYTE* addr = PatternScanFrom(searchStart, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "  Found '8B ?? ??' variant at 0x%p (offset at +3)", addr);
            WriteLog(buf);
            g_stackMemoryRegionTwo.push_back({addr + 3, -0x2});  // Offset bytes at +3
            searchStart = addr + 1;
        } else {
            WriteLog("  Warning: '8B ?? ??' variant not found");
        }
    }
    
    // Patterns: "8D ??" + offsetBytes + byte (multiple instances)
    // Offset bytes are at position 2 in the pattern
    const char* suffixes[] = {"6A", "68", "8D", "68"}; // Last one might be duplicate
    for (int i = 0; i < 4; i++) {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "8D ?? %s %s", offsetStr2, suffixes[i]);
        BYTE* addr = PatternScanFrom(searchStart, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "  Found '8D ?? + %s' variant at 0x%p (offset at +2)", suffixes[i], addr);
            WriteLog(buf);
            g_stackMemoryRegionTwo.push_back({addr + 2, -0x1});  // Offset bytes at +2
            searchStart = addr + 1;
        } else {
            sprintf(buf, "  Warning: '8D ?? + %s' variant not found", suffixes[i]);
            WriteLog(buf);
        }
    }
    
    // ========================================================================
    // STEP 5: Apply all patches
    // ========================================================================
    WriteLog("Step 5: Applying all stack memory patches...");
    
    int patchCount = 0;
    DWORD oldProtect;
    
    // Patch Region One: Point to base of allocated memory
    sprintf(buf, "  Patching Region One (%d locations)...", (int)g_stackMemoryRegionOne.size());
    WriteLog(buf);
    
    for (size_t i = 0; i < g_stackMemoryRegionOne.size(); i++) {
        BYTE* patchAddr = g_stackMemoryRegionOne[i].address;
        int modRmOffset = g_stackMemoryRegionOne[i].byteOffset;
        
        // Debug: Read surrounding bytes BEFORE patching
        sprintf(buf, "    [%d] Before: [%02X %02X %02X %02X] %02X %02X %02X %02X at 0x%p", 
                (int)i + 1,
                *(patchAddr-4), *(patchAddr-3), *(patchAddr-2), *(patchAddr-1),
                *(patchAddr), *(patchAddr+1), *(patchAddr+2), *(patchAddr+3),
                patchAddr);
        WriteLog(buf);
        
        DWORD origOffset = *(DWORD*)patchAddr;
        BYTE origModRm = *(patchAddr + modRmOffset);
        
        if (VirtualProtect(patchAddr, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // Write new memory address
            *(DWORD*)patchAddr = (DWORD)g_stackMemoryBase;
            
            // Modify ModR/M byte (subtract 0x80)
            BYTE* modRmByte = patchAddr + modRmOffset;
            if (VirtualProtect(modRmByte, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                *modRmByte = *modRmByte - 0x80;
                VirtualProtect(modRmByte, 1, oldProtect, &oldProtect);
            }
            
            VirtualProtect(patchAddr, 4, oldProtect, &oldProtect);
            patchCount++;
            
            sprintf(buf, "    [%d] Patched offset 0x%08X->0x%08X, ModR/M [0x%p]:%02X->%02X", 
                    (int)i + 1, origOffset, (DWORD)g_stackMemoryBase,
                    modRmByte, origModRm, *modRmByte);
            WriteLog(buf);
        }
    }
    
    // Patch Region Two: Point to base + offset for second array
    sprintf(buf, "  Patching Region Two (%d locations)...", (int)g_stackMemoryRegionTwo.size());
    WriteLog(buf);
    
    DWORD regionTwoAddr = (DWORD)g_stackMemoryBase + (CHAR_LIMIT * 4);
    
    for (size_t i = 0; i < g_stackMemoryRegionTwo.size(); i++) {
        BYTE* patchAddr = g_stackMemoryRegionTwo[i].address;
        int modRmOffset = g_stackMemoryRegionTwo[i].byteOffset;
        
        // Debug: Read surrounding bytes BEFORE patching
        sprintf(buf, "    [%d] Before: [%02X %02X %02X %02X] %02X %02X %02X %02X at 0x%p", 
                (int)i + 1,
                *(patchAddr-4), *(patchAddr-3), *(patchAddr-2), *(patchAddr-1),
                *(patchAddr), *(patchAddr+1), *(patchAddr+2), *(patchAddr+3),
                patchAddr);
        WriteLog(buf);
        
        DWORD origOffset = *(DWORD*)patchAddr;
        BYTE origModRm = *(patchAddr + modRmOffset);
        
        if (VirtualProtect(patchAddr, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // Write new memory address + offset
            *(DWORD*)patchAddr = regionTwoAddr;
            
            // Modify ModR/M byte (subtract 0x80)
            BYTE* modRmByte = patchAddr + modRmOffset;
            if (VirtualProtect(modRmByte, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                *modRmByte = *modRmByte - 0x80;
                VirtualProtect(modRmByte, 1, oldProtect, &oldProtect);
            }
            
            VirtualProtect(patchAddr, 4, oldProtect, &oldProtect);
            patchCount++;
            
            sprintf(buf, "    [%d] Patched offset 0x%08X->0x%08X, ModR/M [0x%p]:%02X->%02X", 
                    (int)i + 1, origOffset, regionTwoAddr,
                    modRmByte, origModRm, *modRmByte);
            WriteLog(buf);
        }
    }
    
    sprintf(buf, "Stack Memory Expansion: %d patches applied", patchCount);
    WriteLog(buf);
    
    // Verify patches by reading back
    WriteLog("Verifying patched memory...");
    for (size_t i = 0; i < g_stackMemoryRegionOne.size(); i++) {
        DWORD readBack = *(DWORD*)g_stackMemoryRegionOne[i].address;
        sprintf(buf, "  Region1[%d]: Read 0x%08X (expected 0x%08X)", 
                (int)i, readBack, (DWORD)g_stackMemoryBase);
        WriteLog(buf);
    }
    for (size_t i = 0; i < g_stackMemoryRegionTwo.size(); i++) {
        DWORD readBack = *(DWORD*)g_stackMemoryRegionTwo[i].address;
        DWORD expected = (DWORD)g_stackMemoryBase + (CHAR_LIMIT * 4);
        sprintf(buf, "  Region2[%d]: Read 0x%08X (expected 0x%08X)", 
                (int)i, readBack, expected);
        WriteLog(buf);
    }
    
    return patchCount;
}

// ============================================================================
// Main Geo Patches Entry Point
// ============================================================================
void ApplyAllGeoPatches(HMODULE hGameModule) {
    WriteLog("");
    WriteLog("====================================");
    WriteLog("=== GEO MEMORY EXPANSION PATCHES ===");
    WriteLog("====================================");
    
    int totalPatches = 0;
    
    // DEBUG FLAGS - Set to false to disable specific patch groups
    const bool ENABLE_PALETTE_PATCHES = true;
    const bool ENABLE_PORTRAIT_COUNT_PATCH = true;
    const bool ENABLE_PORTRAIT_MEMORY = true;   // ENABLED - Now with proper trampolines!
    const bool ENABLE_STACK_MEMORY = true;       // ENABLED - Required for CSS to work
    
    // Phase 1: Simple byte patches (easy wins)
    if (ENABLE_PALETTE_PATCHES) {
        totalPatches += ApplyPaletteBypassPatches(hGameModule);
    } else {
        WriteLog("=== Palette Bypass: DISABLED ===");
    }
    
    if (ENABLE_PORTRAIT_COUNT_PATCH) {
        totalPatches += ApplyCSSPortraitCountPatch(hGameModule);
    } else {
        WriteLog("=== Portrait Count: DISABLED ===");
    }
    
    // Phase 2: Memory hooks (complex)
    if (ENABLE_PORTRAIT_MEMORY) {
        totalPatches += ApplyPortraitMemoryExtension(hGameModule);
    } else {
        WriteLog("=== Portrait Memory Extension: DISABLED FOR TESTING ===");
    }
    
    // Phase 3: Stack memory expansion (most complex)
    if (ENABLE_STACK_MEMORY) {
        totalPatches += ApplyStackMemoryExpansion(hGameModule);
    } else {
        WriteLog("=== Stack Memory Expansion: DISABLED FOR TESTING ===");
    }
    
    char buf[256];
    sprintf(buf, "=== Total Geo Patches Applied: %d ===", totalPatches);
    WriteLog(buf);
    WriteLog("====================================");
    WriteLog("");
}

