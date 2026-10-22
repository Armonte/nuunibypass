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
    WriteLog("Pattern: '83 ?? ?? 0F 82 ?? ?? ?? ?? BE' (Geo's method)");
    WriteLog("Patch at offset +2: Change portrait limit byte");
    
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
    
    // Use Geo's pattern: 83 * * 0F 82 * * * * BE
    // Patch at offset +0x2
    BYTE* addr = PatternScanModuleIDA(hGameModule, "83 ?? ?? 0F 82 ?? ?? ?? ?? BE");
    
    if (!addr) {
        WriteLog("ERROR: CSS Portrait Count pattern not found!");
        return 0;
    }
    
    BYTE* patchAddr = addr + 0x2;
    sprintf(buf, "Found at 0x%p, patching at +2 (0x%p)", addr, patchAddr);
    WriteLog(buf);
    sprintf(buf, "  BEFORE: 0x%02X", *patchAddr);
    WriteLog(buf);
    
    if (ApplyBytePatch(patchAddr, portraitLimit, "CSS_Portrait_Count")) {
        sprintf(buf, "  AFTER: 0x%02X", *patchAddr);
        WriteLog(buf);
        
        if (displayLimit == 0 || displayLimit > 255) {
            WriteLog("CSS Portrait Count: 1/1 patch applied (32 -> UNCAPPED)");
        } else {
            sprintf(buf, "CSS Portrait Count: 1/1 patch applied (32 -> %d)", displayLimit);
            WriteLog(buf);
        }
        return 1;
    }
    
    WriteLog("ERROR: CSS Portrait Count patch failed!");
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
    WriteLog("=== Applying Portrait Memory Extension (DEBUG MODE) ===");
    WriteLog("This patch extends portrait pointer arrays to support 256 characters.");
    WriteLog("Using proper LEA instructions (not MOV) to match CheatEngine Lua implementation.");
    WriteLog("");
    WriteLog("CRITICAL: Verifying LEA instruction encoding for absolute addressing...");
    WriteLog("  Expected: 8D 05 [4-byte addr] = LEA EAX, [disp32]");
    WriteLog("  Expected: 8D 35 [4-byte addr] = LEA ESI, [disp32]");
    
    // Allocate memory for data + detours
    const int CHAR_LIMIT = 0x100;
    const int DATA_SIZE = (CHAR_LIMIT * 4);  // Portrait pointer array: 256 * 4 bytes = 1024 bytes
    const int DETOUR_SIZE = 0x1000;           // Space for detour code
    const int TOTAL_SIZE = DATA_SIZE + DETOUR_SIZE;
    
    // Allocate with EXECUTE permission (detours need to execute)
    g_portraitMemoryBase = (BYTE*)VirtualAlloc(nullptr, TOTAL_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_portraitMemoryBase) {
        WriteLog("ERROR: Failed to allocate portrait memory!");
        return 0;
    }
    
    char buf[512];
    sprintf(buf, "Allocated %d bytes at 0x%p for portrait memory", TOTAL_SIZE, g_portraitMemoryBase);
    WriteLog(buf);
    sprintf(buf, "  Portrait array: 0x%p (256 pointers × 4 bytes)", g_portraitMemoryBase);
    WriteLog(buf);
    sprintf(buf, "  Detour code area: 0x%p", g_portraitMemoryBase + DATA_SIZE);
    WriteLog(buf);
    
    // Zero out the portrait array
    memset(g_portraitMemoryBase, 0, DATA_SIZE);
    WriteLog("  Zeroed portrait array (all null pointers)");
    
    // Detour area starts after data
    BYTE* detourArea = g_portraitMemoryBase + DATA_SIZE;
    int detourOffset = 0;
    
    int successCount = 0;
    ModuleBounds bounds = GetModuleTextBounds(hGameModule);
    DWORD oldProtect;
    
    // Storage for hook addresses to use as search starting points
    BYTE* hook1Addr = nullptr;
    
    // ========================================================================
    // Hook 1: Portrait array initialization - LEA EAX,[ESI+8]
    // ========================================================================
    // Pattern: C6 ?? ?? 02 8D ?? ?? C7 ?? ?? 00 00 00 00
    // Scanner returns addr+4, pointing at 8D (LEA opcode)
    // Original: 8D 46 08 C7 46 04 00 00 00 00 (10 bytes total)
    //   Byte 0-2:  8D 46 08 = LEA EAX, [ESI+8]
    //   Byte 3-9:  C7 46 04 00 00 00 00 = MOV DWORD PTR [ESI+4], 0
    {
        WriteLog("");
        WriteLog("Hook 1: 'C6 ?? ?? 02 8D ?? ?? C7 ?? ?? 00 00 00 00'");
        const char* pattern = "C6 ?? ?? 02 8D ?? ?? C7 ?? ?? 00 00 00 00";
        BYTE* addr = PatternScanModuleIDA(hGameModule, pattern);
        hook1Addr = addr;  // Save for Hook 2's search start point
        
        if (addr) {
            BYTE* hookPoint = addr + 4;  // Points to 8D (LEA instruction)
            sprintf(buf, "  Found at 0x%p, hook point at 0x%p", addr, hookPoint);
            WriteLog(buf);
            
            // Log original bytes
            sprintf(buf, "  Original 10 bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X", 
                    hookPoint[0], hookPoint[1], hookPoint[2], hookPoint[3], hookPoint[4],
                    hookPoint[5], hookPoint[6], hookPoint[7], hookPoint[8], hookPoint[9]);
            WriteLog(buf);
            
            // Build detour in allocated memory
            BYTE* detour = detourArea + detourOffset;
            int dIdx = 0;
            
            WriteLog("  Building detour code...");
            
            // NEW LEA EAX, [absolute_address]
            // Encoding: 8D 05 [4-byte address] = LEA EAX, [disp32]
            // This is the CORRECT instruction (not MOV!)
            DWORD targetAddr = (DWORD)g_portraitMemoryBase + 8;  // +8 offset like original [ESI+8]
            detour[dIdx++] = 0x8D;  // LEA opcode
            detour[dIdx++] = 0x05;  // ModR/M byte: 00 000 101 = [disp32]
            *(DWORD*)(detour + dIdx) = targetAddr;
            dIdx += 4;
            sprintf(buf, "    [0-5] LEA: 8D 05 %02X %02X %02X %02X (LEA EAX, [0x%08X])",
                    (targetAddr) & 0xFF, (targetAddr >> 8) & 0xFF,
                    (targetAddr >> 16) & 0xFF, (targetAddr >> 24) & 0xFF, targetAddr);
            WriteLog(buf);
            
            // Copy remaining 7 bytes of original code (skip first 3 which were LEA)
            int copiedBytesStart = dIdx;
            memcpy(detour + dIdx, hookPoint + 3, 7);
            sprintf(buf, "    [6-12] Copied 7 bytes: %02X %02X %02X %02X %02X %02X %02X",
                    detour[dIdx], detour[dIdx+1], detour[dIdx+2], detour[dIdx+3],
                    detour[dIdx+4], detour[dIdx+5], detour[dIdx+6]);
            WriteLog(buf);
            dIdx += 7;
            
            // JMP back to continue execution (hookPoint + 10)
            BYTE* jmpInstrAddr = detour + dIdx;
            detour[dIdx++] = 0xE9;  // JMP rel32
            BYTE* returnAddr = hookPoint + 10;
            int32_t jmpBack = returnAddr - (jmpInstrAddr + 5);
            *(int32_t*)(detour + dIdx) = jmpBack;
            sprintf(buf, "    [13-17] JMP: E9 %02X %02X %02X %02X (offset=%d, target=0x%p)",
                    (jmpBack) & 0xFF, (jmpBack >> 8) & 0xFF,
                    (jmpBack >> 16) & 0xFF, (jmpBack >> 24) & 0xFF,
                    jmpBack, returnAddr);
            WriteLog(buf);
            dIdx += 4;
            
            sprintf(buf, "  Detour built at 0x%p, total size %d bytes", detour, dIdx);
            WriteLog(buf);
            
            // Dump complete detour bytecode for verification
            sprintf(buf, "  Complete detour bytes:");
            WriteLog(buf);
            for (int i = 0; i < dIdx; i += 8) {
                char line[256] = "    ";
                int offset = strlen(line);
                for (int j = 0; j < 8 && (i + j) < dIdx; j++) {
                    sprintf(line + offset, "%02X ", detour[i + j]);
                    offset += 3;
                }
                WriteLog(line);
            }
            
            // Overwrite original location with JMP to detour + NOPs
            WriteLog("  Installing hook at original location...");
            if (VirtualProtect(hookPoint, 10, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                hookPoint[0] = 0xE9;  // JMP rel32
                int32_t jmpToDetour = detour - (hookPoint + 5);
                *(int32_t*)(hookPoint + 1) = jmpToDetour;
                
                // NOP pad the remaining 5 bytes
                for (int i = 5; i < 10; i++) {
                    hookPoint[i] = 0x90;  // NOP
                }
                
                VirtualProtect(hookPoint, 10, oldProtect, &oldProtect);
                
                sprintf(buf, "    JMP offset: %d (0x%08X), detour at 0x%p",
                        jmpToDetour, jmpToDetour, detour);
                WriteLog(buf);
                sprintf(buf, "    Patched 10 bytes: E9 %02X %02X %02X %02X 90 90 90 90 90",
                        (jmpToDetour) & 0xFF, (jmpToDetour >> 8) & 0xFF,
                        (jmpToDetour >> 16) & 0xFF, (jmpToDetour >> 24) & 0xFF);
                WriteLog(buf);
                
                // Verify the hook was written correctly
                sprintf(buf, "    Verification read: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                        hookPoint[0], hookPoint[1], hookPoint[2], hookPoint[3], hookPoint[4],
                        hookPoint[5], hookPoint[6], hookPoint[7], hookPoint[8], hookPoint[9]);
                WriteLog(buf);
                
                detourOffset += dIdx;
                WriteLog("  Status: ✓ HOOKED SUCCESSFULLY");
                successCount++;
            } else {
                WriteLog("  ERROR: VirtualProtect failed!");
            }
        } else {
            WriteLog("  ERROR: Pattern not found!");
        }
    }
    
    // ========================================================================
    // Hook 2: Portrait array access - LEA EAX,[ESI+8]
    // ========================================================================
    // Pattern: 0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ?? ?? ?? ?? 00 00 00 00
    // Scanner returns addr+6, pointing at 8D (LEA opcode)
    // Original: 8D 46 08 C7 85 10 FD FF FF 00 00 00 00 (13 bytes total)
    //   Byte 0-2:   8D 46 08 = LEA EAX, [ESI+8] (SAME +8 offset as Hook 1!)
    //   Byte 3-12:  C7 85 10 FD FF FF 00 00 00 00 = Following instructions
    // NOTE: We search AFTER Hook 1 to avoid false positives!
    {
        WriteLog("");
        WriteLog("Hook 2: '0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ?? ?? ?? ?? 00 00 00 00'");
        const char* pattern = "0F 84 ?? ?? ?? ?? 8D ?? ?? C7 ?? ?? ?? ?? ?? 00 00 00 00";
        
        // Search starting AFTER Hook 1's location (like the Lua version does)
        BYTE* searchStart = hook1Addr ? (hook1Addr + 1) : bounds.start;
        SIZE_T searchSize = bounds.end - searchStart;
        BYTE* addr = PatternScanIDA(searchStart, searchSize, pattern);
        
        if (addr) {
            BYTE* hookPoint = addr + 6;  // Points to 8D (LEA instruction)
            sprintf(buf, "  Found at 0x%p, hook point at 0x%p", addr, hookPoint);
            WriteLog(buf);
            
            // Log original bytes
            sprintf(buf, "  Original 13 bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                    hookPoint[0], hookPoint[1], hookPoint[2], hookPoint[3], hookPoint[4],
                    hookPoint[5], hookPoint[6], hookPoint[7], hookPoint[8], hookPoint[9],
                    hookPoint[10], hookPoint[11], hookPoint[12]);
            WriteLog(buf);
            
            // Build detour
            BYTE* detour = detourArea + detourOffset;
            int dIdx = 0;
            
            WriteLog("  Building detour code...");
            
            // NEW LEA EAX, [absolute_address]
            // Encoding: 8D 05 [4-byte address] = LEA EAX, [disp32]
            // NOTE: Original instruction is ALSO [ESI+8], not [ESI+0]!
            // We need +8 offset to match (same as Hook 1)
            DWORD targetAddr = (DWORD)g_portraitMemoryBase + 8;  // +8 offset like Hook 1!
            detour[dIdx++] = 0x8D;  // LEA opcode
            detour[dIdx++] = 0x05;  // ModR/M byte: 00 000 101 = [disp32]
            *(DWORD*)(detour + dIdx) = targetAddr;
            dIdx += 4;
            sprintf(buf, "    [0-5] LEA: 8D 05 %02X %02X %02X %02X (LEA EAX, [0x%08X])",
                    (targetAddr) & 0xFF, (targetAddr >> 8) & 0xFF,
                    (targetAddr >> 16) & 0xFF, (targetAddr >> 24) & 0xFF, targetAddr);
            WriteLog(buf);
            
            // Copy remaining 10 bytes of original code (skip first 3 which were LEA)
            memcpy(detour + dIdx, hookPoint + 3, 10);
            sprintf(buf, "    [6-15] Copied 10 bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                    detour[dIdx], detour[dIdx+1], detour[dIdx+2], detour[dIdx+3], detour[dIdx+4],
                    detour[dIdx+5], detour[dIdx+6], detour[dIdx+7], detour[dIdx+8], detour[dIdx+9]);
            WriteLog(buf);
            dIdx += 10;
            
            // JMP back (hookPoint + 13)
            BYTE* jmpInstrAddr = detour + dIdx;
            detour[dIdx++] = 0xE9;  // JMP rel32
            BYTE* returnAddr = hookPoint + 13;
            int32_t jmpBack = returnAddr - (jmpInstrAddr + 5);
            *(int32_t*)(detour + dIdx) = jmpBack;
            sprintf(buf, "    [16-20] JMP: E9 %02X %02X %02X %02X (offset=%d, target=0x%p)",
                    (jmpBack) & 0xFF, (jmpBack >> 8) & 0xFF,
                    (jmpBack >> 16) & 0xFF, (jmpBack >> 24) & 0xFF,
                    jmpBack, returnAddr);
            WriteLog(buf);
            dIdx += 4;
            
            sprintf(buf, "  Detour built at 0x%p, total size %d bytes", detour, dIdx);
            WriteLog(buf);
            
            // Dump complete detour bytecode
            sprintf(buf, "  Complete detour bytes:");
            WriteLog(buf);
            for (int i = 0; i < dIdx; i += 8) {
                char line[256] = "    ";
                int offset = strlen(line);
                for (int j = 0; j < 8 && (i + j) < dIdx; j++) {
                    sprintf(line + offset, "%02X ", detour[i + j]);
                    offset += 3;
                }
                WriteLog(line);
            }
            
            // Overwrite original with JMP + NOPs
            WriteLog("  Installing hook at original location...");
            if (VirtualProtect(hookPoint, 13, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                hookPoint[0] = 0xE9;  // JMP rel32
                int32_t jmpToDetour = detour - (hookPoint + 5);
                *(int32_t*)(hookPoint + 1) = jmpToDetour;
                
                // NOP pad remaining 8 bytes
                for (int i = 5; i < 13; i++) {
                    hookPoint[i] = 0x90;
                }
                
                VirtualProtect(hookPoint, 13, oldProtect, &oldProtect);
                
                sprintf(buf, "    JMP offset: %d (0x%08X), detour at 0x%p",
                        jmpToDetour, jmpToDetour, detour);
                WriteLog(buf);
                sprintf(buf, "    Patched 13 bytes: E9 %02X %02X %02X %02X 90 90 90 90 90 90 90 90 90",
                        (jmpToDetour) & 0xFF, (jmpToDetour >> 8) & 0xFF,
                        (jmpToDetour >> 16) & 0xFF, (jmpToDetour >> 24) & 0xFF);
                WriteLog(buf);
                
                // Verify the hook
                sprintf(buf, "    Verification read: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                        hookPoint[0], hookPoint[1], hookPoint[2], hookPoint[3], hookPoint[4],
                        hookPoint[5], hookPoint[6], hookPoint[7], hookPoint[8], hookPoint[9],
                        hookPoint[10], hookPoint[11], hookPoint[12]);
                WriteLog(buf);
                
                detourOffset += dIdx;
                WriteLog("  Status: ✓ HOOKED SUCCESSFULLY");
                successCount++;
            } else {
                WriteLog("  ERROR: VirtualProtect failed!");
            }
        } else {
            WriteLog("  ERROR: Pattern not found!");
        }
    }
    
    // ========================================================================
    // Hook 3: Portrait loop control - LEA ESI + MOV EDI
    // ========================================================================
    // Pattern: C7 ?? ?? 00 00 00 00 8D ?? ?? BF ?? ?? ?? ??
    // Scanner returns addr+7, pointing at 8D (LEA ESI opcode)
    // Original: 8D 35 [4-byte addr] BF [4-byte value] (8 bytes, overlapping)
    //   First part:  8D 35 [4] = LEA ESI, [absolute_address] (6 bytes)
    //   Second part: BF [4]    = MOV EDI, immediate32 (5 bytes)
    //   Total: 8 bytes (they overlap in the pattern)
    //
    // These control the portrait processing loop:
    //   ESI = pointer to portrait array
    //   EDI = number of portraits to process
    {
        WriteLog("");
        WriteLog("Hook 3: 'C7 ?? ?? 00 00 00 00 8D ?? ?? BF ?? ?? ?? ??'");
        const char* pattern = "C7 ?? ?? 00 00 00 00 8D ?? ?? BF ?? ?? ?? ??";
        BYTE* addr = PatternScanModuleIDA(hGameModule, pattern);
        
        if (addr) {
            BYTE* hookPoint = addr + 7;  // Points to 8D (LEA ESI instruction)
            sprintf(buf, "  Found at 0x%p, hook point at 0x%p", addr, hookPoint);
            WriteLog(buf);
            
            // Log original bytes
            sprintf(buf, "  Original 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X",
                    hookPoint[0], hookPoint[1], hookPoint[2], hookPoint[3],
                    hookPoint[4], hookPoint[5], hookPoint[6], hookPoint[7]);
            WriteLog(buf);
            
            // Build detour
            BYTE* detour = detourArea + detourOffset;
            int dIdx = 0;
            
            WriteLog("  Building detour code...");
            
            // NEW LEA ESI, [absolute_address]
            // Encoding: 8D 35 [4-byte address] = LEA ESI, [disp32]
            DWORD targetAddr = (DWORD)g_portraitMemoryBase;
            detour[dIdx++] = 0x8D;  // LEA opcode
            detour[dIdx++] = 0x35;  // ModR/M byte: 00 110 101 = LEA ESI, [disp32]
            *(DWORD*)(detour + dIdx) = targetAddr;
            dIdx += 4;
            sprintf(buf, "    [0-5] LEA ESI: 8D 35 %02X %02X %02X %02X (LEA ESI, [0x%08X])",
                    (targetAddr) & 0xFF, (targetAddr >> 8) & 0xFF,
                    (targetAddr >> 16) & 0xFF, (targetAddr >> 24) & 0xFF, targetAddr);
            WriteLog(buf);
            
            // MOV EDI, CHAR_LIMIT (256)
            // Encoding: BF [4-byte value] = MOV EDI, imm32
            detour[dIdx++] = 0xBF;  // MOV EDI, imm32
            *(DWORD*)(detour + dIdx) = CHAR_LIMIT;
            dIdx += 4;
            sprintf(buf, "    [6-10] MOV EDI: BF %02X 00 00 00 (MOV EDI, 0x%X)",
                    CHAR_LIMIT & 0xFF, CHAR_LIMIT);
            WriteLog(buf);
            
            // JMP back (hookPoint + 8)
            BYTE* jmpInstrAddr = detour + dIdx;
            detour[dIdx++] = 0xE9;  // JMP rel32
            BYTE* returnAddr = hookPoint + 8;
            int32_t jmpBack = returnAddr - (jmpInstrAddr + 5);
            *(int32_t*)(detour + dIdx) = jmpBack;
            sprintf(buf, "    [11-15] JMP: E9 %02X %02X %02X %02X (offset=%d, target=0x%p)",
                    (jmpBack) & 0xFF, (jmpBack >> 8) & 0xFF,
                    (jmpBack >> 16) & 0xFF, (jmpBack >> 24) & 0xFF,
                    jmpBack, returnAddr);
            WriteLog(buf);
            dIdx += 4;
            
            sprintf(buf, "  Detour built at 0x%p, total size %d bytes", detour, dIdx);
            WriteLog(buf);
            
            // Dump complete detour bytecode
            sprintf(buf, "  Complete detour bytes:");
            WriteLog(buf);
            for (int i = 0; i < dIdx; i += 8) {
                char line[256] = "    ";
                int offset = strlen(line);
                for (int j = 0; j < 8 && (i + j) < dIdx; j++) {
                    sprintf(line + offset, "%02X ", detour[i + j]);
                    offset += 3;
                }
                WriteLog(line);
            }
            
            // Overwrite original with JMP + NOPs
            WriteLog("  Installing hook at original location...");
            if (VirtualProtect(hookPoint, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                hookPoint[0] = 0xE9;  // JMP rel32
                int32_t jmpToDetour = detour - (hookPoint + 5);
                *(int32_t*)(hookPoint + 1) = jmpToDetour;
                
                // NOP pad remaining 3 bytes
                for (int i = 5; i < 8; i++) {
                    hookPoint[i] = 0x90;
                }
                
                VirtualProtect(hookPoint, 8, oldProtect, &oldProtect);
                
                sprintf(buf, "    JMP offset: %d (0x%08X), detour at 0x%p",
                        jmpToDetour, jmpToDetour, detour);
                WriteLog(buf);
                sprintf(buf, "    Patched 8 bytes: E9 %02X %02X %02X %02X 90 90 90",
                        (jmpToDetour) & 0xFF, (jmpToDetour >> 8) & 0xFF,
                        (jmpToDetour >> 16) & 0xFF, (jmpToDetour >> 24) & 0xFF);
                WriteLog(buf);
                
                // Verify the hook
                sprintf(buf, "    Verification read: %02X %02X %02X %02X %02X %02X %02X %02X",
                        hookPoint[0], hookPoint[1], hookPoint[2], hookPoint[3],
                        hookPoint[4], hookPoint[5], hookPoint[6], hookPoint[7]);
                WriteLog(buf);
                
                detourOffset += dIdx;
                WriteLog("  Status: ✓ HOOKED SUCCESSFULLY");
                successCount++;
            } else {
                WriteLog("  ERROR: VirtualProtect failed!");
            }
        } else {
            WriteLog("  ERROR: Pattern not found!");
        }
    }
    
    WriteLog("");
    WriteLog("========================================");
    sprintf(buf, "Portrait Memory Extension: %d/3 hooks applied successfully", successCount);
    WriteLog(buf);
    WriteLog("========================================");
    
    if (successCount == 3) {
        WriteLog("✓ All portrait memory hooks installed correctly!");
        WriteLog("✓ Portrait system now supports 256 characters.");
        WriteLog("");
        WriteLog("Diagnostic Information:");
        sprintf(buf, "  - Portrait array base: 0x%p", g_portraitMemoryBase);
        WriteLog(buf);
        sprintf(buf, "  - Portrait array size: %d bytes (%d pointers)", CHAR_LIMIT * 4, CHAR_LIMIT);
        WriteLog(buf);
        sprintf(buf, "  - Detour code used: %d bytes (of %d available)", detourOffset, DETOUR_SIZE);
        WriteLog(buf);
        
        // Test memory accessibility
        WriteLog("");
        WriteLog("Memory accessibility test:");
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(g_portraitMemoryBase, &mbi, sizeof(mbi))) {
            sprintf(buf, "  - State: %s", mbi.State == MEM_COMMIT ? "COMMITTED" : "NOT COMMITTED");
            WriteLog(buf);
            sprintf(buf, "  - Protection: 0x%X %s", mbi.Protect, 
                    (mbi.Protect & PAGE_EXECUTE_READWRITE) ? "(R/W/X)" : "(other)");
            WriteLog(buf);
            sprintf(buf, "  - Region size: %d bytes", mbi.RegionSize);
            WriteLog(buf);
        }
        
        // Check if first few portrait pointers are accessible
        WriteLog("");
        WriteLog("Portrait array sample (first 8 pointers):");
        for (int i = 0; i < 8; i++) {
            DWORD* ptrSlot = (DWORD*)(g_portraitMemoryBase + (i * 4));
            sprintf(buf, "  [%d] @ 0x%p = 0x%08X", i, ptrSlot, *ptrSlot);
            WriteLog(buf);
        }
    } else {
        WriteLog("✗ WARNING: Some portrait memory hooks failed!");
        WriteLog("✗ Portraits may not work correctly.");
        sprintf(buf, "✗ Failed hooks: %d/3", 3 - successCount);
        WriteLog(buf);
    }
    
    WriteLog("========================================");
    WriteLog("");
    
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
    WriteLog("This patch redirects stack-based character arrays to custom allocated memory");
    WriteLog("and modifies x86 ModR/M bytes to change addressing modes from EBP-relative to absolute.");
    
    const int CHAR_LIMIT = 0x100;
    // Need space for two arrays: base array + offset array
    // Each character needs 4 bytes (DWORD pointer)
    // Region One: CHAR_LIMIT * 4 bytes = 0x400
    // Region Two: CHAR_LIMIT * 4 bytes = 0x400
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
    sprintf(buf, "Allocated %d bytes at 0x%p for stack memory", ALLOC_SIZE, g_stackMemoryBase);
    WriteLog(buf);
    sprintf(buf, "  Region One (base array): 0x%p", g_stackMemoryBase);
    WriteLog(buf);
    sprintf(buf, "  Region Two (offset array): 0x%p", g_stackMemoryBase + (CHAR_LIMIT * 4));
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
    WriteLog("");
    WriteLog("Step 1: Finding Region One base offset...");
    WriteLog("Pattern: '8D ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ?? ?? 3B ?? 7C ?? 8B'");
    const char* pattern1 = "8D ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ?? ?? 3B ?? 7C ?? 8B";
    BYTE* addr1 = PatternScanIDA(bounds.start, bounds.size, pattern1);
    
    if (!addr1) {
        WriteLog("  ERROR: Region One base pattern not found!");
        return 0;
    }
    
    // The pattern finds an instruction like: LEA REG, [EBP+offset]
    // The offset DWORD is at position +0x2 from the LEA opcode (8D)
    // But addr1 points to the start of the whole pattern match
    // Since the pattern starts with "8D", we need to look at the instruction structure:
    // 8D [ModR/M] [4-byte displacement]
    // The LEA is at position 0, ModR/M at position 1, displacement at position 2-5
    // But we're looking for a MOV instruction later in the pattern...
    // Let me check: Pattern is "8D * * * * * 89 * * * * * * *..."
    //               Position: 0 1 2 3 4 5  6 7 8 9...
    // So at position 9 we should have a 4-byte offset for the MOV instruction
    // Read original offset at addr1+0x9 (signed int32)
    g_origOffset1 = *(int32_t*)(addr1 + 0x9);
    sprintf(buf, "  Found at 0x%p, original offset: 0x%08X (%d)", addr1, g_origOffset1, g_origOffset1);
    WriteLog(buf);
    
    // Save this location for patching
    // The offset DWORD is at addr1+0x9, and the ModR/M byte is 2 bytes before it
    g_stackMemoryRegionOne.push_back({addr1 + 0x9, -0x2});
    sprintf(buf, "  Patch location: offset at 0x%p, ModR/M at 0x%p", addr1 + 0x9, addr1 + 0x7);
    WriteLog(buf);
    
    // ========================================================================
    // STEP 2: Find Region Two base pattern and extract original offset
    // ========================================================================
    WriteLog("");
    WriteLog("Step 2: Finding Region Two base offset...");
    WriteLog("Pattern: '89 ?? ?? ?? ?? ?? ?? 85 ?? 7E'");
    const char* pattern2 = "89 ?? ?? ?? ?? ?? ?? 85 ?? 7E";
    BYTE* addr2 = PatternScanFrom(addr1, bounds.end, ParsePattern(pattern2).bytes.data(), 
                                    ParsePattern(pattern2).mask.c_str());
    
    if (!addr2) {
        WriteLog("  ERROR: Region Two base pattern not found!");
        return 0;
    }
    
    // Pattern: 89 [ModR/M] [4-byte displacement] ...
    //          0   1       2-5
    // The offset DWORD starts at position 3 (after opcode and ModR/M)
    g_origOffset2 = *(int32_t*)(addr2 + 0x3);
    sprintf(buf, "  Found at 0x%p, original offset: 0x%08X (%d)", addr2, g_origOffset2, g_origOffset2);
    WriteLog(buf);
    
    // Save this location for patching (ModR/M is 2 bytes before offset DWORD)
    g_stackMemoryRegionTwo.push_back({addr2 + 0x3, -0x2});
    sprintf(buf, "  Patch location: offset at 0x%p, ModR/M at 0x%p", addr2 + 0x3, addr2 + 0x1);
    WriteLog(buf);
    
    // ========================================================================
    // STEP 3: Build dynamic patterns using origOffset1 (Region One)
    // ========================================================================
    WriteLog("");
    WriteLog("Step 3: Finding additional Region One references...");
    
    char offsetStr1[64];
    OffsetToByteString(g_origOffset1, offsetStr1, sizeof(offsetStr1));
    sprintf(buf, "  Offset bytes (little-endian): %s", offsetStr1);
    WriteLog(buf);
    
    // CRITICAL FIX: Lua's AoBTools scanner returns (match_address + offset_parameter)
    // In C++, PatternScan returns just the match address, so we must ADD the offset manually
    
    // Pattern: "7E ?? 8B ?? ??" + offsetBytes
    // Structure: 7E [1] 8B [1] [1] [4-byte offset]
    //            0   1   2   3   4   5 6 7 8
    // The offset bytes start at position 5
    {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "7E ?? 8B ?? ?? %s", offsetStr1);
        WriteLog("  Scanning for: '7E ?? 8B ?? ??' + offset bytes...");
        BYTE* addr = PatternScanFrom(addr2, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "    Found at 0x%p, offset bytes at +5 (0x%p)", addr, addr + 5);
            WriteLog(buf);
            // CRITICAL: Add +5 to match where Lua's scanner would point
            g_stackMemoryRegionOne.push_back({addr + 5, -0x2});
        } else {
            WriteLog("    Warning: Pattern not found");
        }
    }
    
    // Pattern: "39 ?? ??" + offsetBytes
    // Structure: 39 [1] [1] [4-byte offset]
    //            0   1   2   3 4 5 6
    // The offset bytes start at position 3
    {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "39 ?? ?? %s", offsetStr1);
        WriteLog("  Scanning for: '39 ?? ??' + offset bytes...");
        BYTE* addr = PatternScanFrom(addr2, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "    Found at 0x%p, offset bytes at +3 (0x%p)", addr, addr + 3);
            WriteLog(buf);
            // CRITICAL: Add +3 to match Lua behavior
            g_stackMemoryRegionOne.push_back({addr + 3, -0x2});
        } else {
            WriteLog("    Warning: Pattern not found");
        }
    }
    
    // ========================================================================
    // STEP 4: Build dynamic patterns using origOffset2 (Region Two)
    // ========================================================================
    WriteLog("");
    WriteLog("Step 4: Finding additional Region Two references...");
    
    char offsetStr2[64];
    OffsetToByteString(g_origOffset2, offsetStr2, sizeof(offsetStr2));
    sprintf(buf, "  Offset bytes (little-endian): %s", offsetStr2);
    WriteLog(buf);
    
    BYTE* searchStart = addr2;
    
    // Pattern: "89 ?? ??" + offsetBytes + "?? 3B"
    // Structure: 89 [1] [1] [4-byte offset] [1] 3B
    //            0   1   2   3 4 5 6         7   8
    // Offset bytes start at position 3
    {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "89 ?? ?? %s ?? 3B", offsetStr2);
        WriteLog("  Scanning for: '89 ?? ??' + offset + '?? 3B'...");
        BYTE* addr = PatternScanFrom(searchStart, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "    Found at 0x%p, offset bytes at +3 (0x%p)", addr, addr + 3);
            WriteLog(buf);
            // CRITICAL: Add +3 to match Lua behavior
            g_stackMemoryRegionTwo.push_back({addr + 3, -0x2});
            searchStart = addr + 1;
        } else {
            WriteLog("    Warning: Pattern not found");
        }
    }
    
    // Pattern: "8B ?? ??" + offsetBytes + "05"
    // Structure: 8B [1] [1] [4-byte offset] 05
    //            0   1   2   3 4 5 6         7
    // Offset bytes start at position 3
    {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "8B ?? ?? %s 05", offsetStr2);
        WriteLog("  Scanning for: '8B ?? ??' + offset + '05'...");
        BYTE* addr = PatternScanFrom(searchStart, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "    Found at 0x%p, offset bytes at +3 (0x%p)", addr, addr + 3);
            WriteLog(buf);
            // CRITICAL: Add +3 to match Lua behavior
            g_stackMemoryRegionTwo.push_back({addr + 3, -0x2});
            searchStart = addr + 1;
        } else {
            WriteLog("    Warning: Pattern not found");
        }
    }
    
    // Patterns: "8D ??" + offsetBytes + byte (multiple instances)
    // Structure: 8D [1] [4-byte offset] [suffix]
    //            0   1   2 3 4 5        6
    // Offset bytes start at position 2
    // CRITICAL: These use -0x1 for ModR/M position (different instruction encoding)
    WriteLog("  Scanning for: '8D ??' + offset + suffix patterns...");
    const char* suffixes[] = {"6A", "68", "8D", "68"};
    for (int i = 0; i < 4; i++) {
        char dynamicPattern[256];
        sprintf(dynamicPattern, "8D ?? %s %s", offsetStr2, suffixes[i]);
        sprintf(buf, "    [%d/4] Pattern: '8D ??' + offset + '%s'", i + 1, suffixes[i]);
        WriteLog(buf);
        BYTE* addr = PatternScanFrom(searchStart, bounds.end, ParsePattern(dynamicPattern).bytes.data(),
                                      ParsePattern(dynamicPattern).mask.c_str());
        if (addr) {
            sprintf(buf, "      Found at 0x%p, offset bytes at +2 (0x%p)", addr, addr + 2);
            WriteLog(buf);
            // CRITICAL: Add +2 AND use -0x1 for ModR/M position (LEA instruction encoding)
            g_stackMemoryRegionTwo.push_back({addr + 2, -0x1});
            searchStart = addr + 1;
        } else {
            WriteLog("      Warning: Pattern not found");
        }
    }
    
    // ========================================================================
    // STEP 5: Apply all patches
    // ========================================================================
    WriteLog("");
    WriteLog("Step 5: Applying all stack memory patches...");
    WriteLog("Technique: Replace stack offsets with absolute addresses and modify ModR/M bytes");
    WriteLog("ModR/M modification: Subtract 0x80 to change EBP-relative to absolute addressing");
    
    int patchCount = 0;
    DWORD oldProtect;
    
    // Patch Region One: Point to base of allocated memory
    WriteLog("");
    sprintf(buf, "Patching Region One (%d locations)...", (int)g_stackMemoryRegionOne.size());
    WriteLog(buf);
    
    for (size_t i = 0; i < g_stackMemoryRegionOne.size(); i++) {
        BYTE* patchAddr = g_stackMemoryRegionOne[i].address;  // Points to 4-byte offset DWORD
        int modRmOffset = g_stackMemoryRegionOne[i].byteOffset;  // Negative offset to ModR/M byte
        
        // Calculate ModR/M byte address (it's BEFORE the offset DWORD)
        BYTE* modRmByte = patchAddr + modRmOffset;  // modRmOffset is negative (-2 or -1)
        
        // Read original values
        DWORD origOffset = *(DWORD*)patchAddr;
        BYTE origModRm = *modRmByte;
        
        sprintf(buf, "  [%d/%d] Offset at 0x%p, ModR/M at 0x%p", 
                (int)i + 1, (int)g_stackMemoryRegionOne.size(), patchAddr, modRmByte);
        WriteLog(buf);
        sprintf(buf, "    BEFORE: Offset=0x%08X, ModR/M=0x%02X", origOffset, origModRm);
        WriteLog(buf);
        
        // Need to protect both the ModR/M byte and the offset DWORD
        // Find the range from modRmByte to patchAddr+4
        BYTE* protectStart = modRmByte;  // Start at ModR/M (which is before patchAddr)
        size_t protectSize = (patchAddr + 4) - modRmByte;  // Cover ModR/M + offset DWORD
        
        if (VirtualProtect(protectStart, protectSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // Modify ModR/M byte FIRST (subtract 0x80 to change addressing mode)
            // This changes: 8D ([EBP+disp32]) -> 0D ([disp32])
            //               8B ([EBP+disp32]) -> 0B ([disp32]), etc.
            *modRmByte = origModRm - 0x80;
            
            // Write new absolute memory address
            *(DWORD*)patchAddr = (DWORD)g_stackMemoryBase;
            
            VirtualProtect(protectStart, protectSize, oldProtect, &oldProtect);
            patchCount++;
            
            sprintf(buf, "    AFTER:  Offset=0x%08X, ModR/M=0x%02X", 
                    (DWORD)g_stackMemoryBase, *modRmByte);
            WriteLog(buf);
            sprintf(buf, "    SUCCESS: Changed addressing from EBP-relative to absolute");
            WriteLog(buf);
        } else {
            sprintf(buf, "    ERROR: VirtualProtect failed!");
            WriteLog(buf);
        }
    }
    
    // Patch Region Two: Point to base + offset for second array
    WriteLog("");
    sprintf(buf, "Patching Region Two (%d locations)...", (int)g_stackMemoryRegionTwo.size());
    WriteLog(buf);
    
    DWORD regionTwoAddr = (DWORD)g_stackMemoryBase + (CHAR_LIMIT * 4);
    sprintf(buf, "  Region Two base address: 0x%08X", regionTwoAddr);
    WriteLog(buf);
    
    for (size_t i = 0; i < g_stackMemoryRegionTwo.size(); i++) {
        BYTE* patchAddr = g_stackMemoryRegionTwo[i].address;  // Points to 4-byte offset DWORD
        int modRmOffset = g_stackMemoryRegionTwo[i].byteOffset;  // -0x2 or -0x1
        
        // Calculate ModR/M byte address
        BYTE* modRmByte = patchAddr + modRmOffset;
        
        // Read original values
        DWORD origOffset = *(DWORD*)patchAddr;
        BYTE origModRm = *modRmByte;
        
        sprintf(buf, "  [%d/%d] Offset at 0x%p, ModR/M at 0x%p (offset=%d)", 
                (int)i + 1, (int)g_stackMemoryRegionTwo.size(), patchAddr, modRmByte, modRmOffset);
        WriteLog(buf);
        sprintf(buf, "    BEFORE: Offset=0x%08X, ModR/M=0x%02X", origOffset, origModRm);
        WriteLog(buf);
        
        // Protect the range
        BYTE* protectStart = modRmByte;
        size_t protectSize = (patchAddr + 4) - modRmByte;
        
        if (VirtualProtect(protectStart, protectSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // Modify ModR/M byte (subtract 0x80)
            *modRmByte = origModRm - 0x80;
            
            // Write new absolute memory address (region two start)
            *(DWORD*)patchAddr = regionTwoAddr;
            
            VirtualProtect(protectStart, protectSize, oldProtect, &oldProtect);
            patchCount++;
            
            sprintf(buf, "    AFTER:  Offset=0x%08X, ModR/M=0x%02X", 
                    regionTwoAddr, *modRmByte);
            WriteLog(buf);
            sprintf(buf, "    SUCCESS: Changed addressing from EBP-relative to absolute");
            WriteLog(buf);
        } else {
            sprintf(buf, "    ERROR: VirtualProtect failed!");
            WriteLog(buf);
        }
    }
    
    WriteLog("");
    sprintf(buf, "Stack Memory Expansion: %d/%d patches applied successfully", 
            patchCount, (int)(g_stackMemoryRegionOne.size() + g_stackMemoryRegionTwo.size()));
    WriteLog(buf);
    
    // Verify patches by reading back
    WriteLog("");
    WriteLog("Verifying patched memory...");
    bool allValid = true;
    
    for (size_t i = 0; i < g_stackMemoryRegionOne.size(); i++) {
        DWORD readBack = *(DWORD*)g_stackMemoryRegionOne[i].address;
        DWORD expected = (DWORD)g_stackMemoryBase;
        bool valid = (readBack == expected);
        allValid = allValid && valid;
        sprintf(buf, "  Region1[%d]: 0x%08X (expected 0x%08X) %s", 
                (int)i, readBack, expected, valid ? "[OK]" : "[MISMATCH!]");
        WriteLog(buf);
    }
    
    for (size_t i = 0; i < g_stackMemoryRegionTwo.size(); i++) {
        DWORD readBack = *(DWORD*)g_stackMemoryRegionTwo[i].address;
        DWORD expected = (DWORD)g_stackMemoryBase + (CHAR_LIMIT * 4);
        bool valid = (readBack == expected);
        allValid = allValid && valid;
        sprintf(buf, "  Region2[%d]: 0x%08X (expected 0x%08X) %s", 
                (int)i, readBack, expected, valid ? "[OK]" : "[MISMATCH!]");
        WriteLog(buf);
    }
    
    if (allValid) {
        WriteLog("Verification: ALL PATCHES VALID!");
    } else {
        WriteLog("Verification: SOME PATCHES FAILED - CHECK LOG ABOVE");
    }
    
    return patchCount;
}

// ============================================================================
// PATCH 5: D Folder Bypass (Enable __St folder system)
// ============================================================================
int ApplyLanguageBypassPatches(HMODULE hGameModule) {
    WriteLog("=== Applying Language Bypass Patches (Geo's Force English) ===");
    WriteLog("Pattern: '0F ?? ?? E8 ?? ?? ?? ?? 83 ?? FF 74' (3 instances)");
    WriteLog("Patch at offset +8: Replace 4 bytes with '6A 01 58 70'");
    
    int successCount = 0;
    ModuleBounds bounds = GetModuleTextBounds(hGameModule);
    
    if (!bounds.start) {
        WriteLog("ERROR: Could not get module bounds!");
        return 0;
    }
    
    // Pattern: 0F * * E8 * * * * 83 * FF 74
    // Patch at offset +0x8 with: 6A 01 58 70
    BYTE* addr = PatternScanModuleIDA(hGameModule, "0F ?? ?? E8 ?? ?? ?? ?? 83 ?? FF 74");
    
    if (!addr) {
        WriteLog("ERROR: Language bypass pattern not found!");
        return 0;
    }
    
    char buf[256];
    
    // First instance
    BYTE* patchAddr1 = addr + 0x8;
    sprintf(buf, "Instance 1 found at 0x%p, patching at +8 (0x%p)", addr, patchAddr1);
    WriteLog(buf);
    sprintf(buf, "  BEFORE: %02X %02X %02X %02X", patchAddr1[0], patchAddr1[1], patchAddr1[2], patchAddr1[3]);
    WriteLog(buf);
    
    DWORD oldProtect;
    if (VirtualProtect(patchAddr1, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        patchAddr1[0] = 0x6A; // PUSH 1
        patchAddr1[1] = 0x01;
        patchAddr1[2] = 0x58; // POP EAX
        patchAddr1[3] = 0x70; // JO (short jump if overflow)
        VirtualProtect(patchAddr1, 4, oldProtect, &oldProtect);
        sprintf(buf, "  AFTER: %02X %02X %02X %02X", patchAddr1[0], patchAddr1[1], patchAddr1[2], patchAddr1[3]);
        WriteLog(buf);
        successCount++;
    }
    
    // Second instance
    addr = PatternScanFrom(addr + 1, bounds.end, ParsePattern("0F ?? ?? E8 ?? ?? ?? ?? 83 ?? FF 74").bytes.data(), ParsePattern("0F ?? ?? E8 ?? ?? ?? ?? 83 ?? FF 74").mask.c_str());
    if (addr) {
        BYTE* patchAddr2 = addr + 0x8;
        sprintf(buf, "Instance 2 found at 0x%p, patching at +8 (0x%p)", addr, patchAddr2);
        WriteLog(buf);
        sprintf(buf, "  BEFORE: %02X %02X %02X %02X", patchAddr2[0], patchAddr2[1], patchAddr2[2], patchAddr2[3]);
        WriteLog(buf);
        
        if (VirtualProtect(patchAddr2, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            patchAddr2[0] = 0x6A;
            patchAddr2[1] = 0x01;
            patchAddr2[2] = 0x58;
            patchAddr2[3] = 0x70;
            VirtualProtect(patchAddr2, 4, oldProtect, &oldProtect);
            sprintf(buf, "  AFTER: %02X %02X %02X %02X", patchAddr2[0], patchAddr2[1], patchAddr2[2], patchAddr2[3]);
            WriteLog(buf);
            successCount++;
        }
    }
    
    // Third instance
    addr = PatternScanFrom(addr + 1, bounds.end, ParsePattern("0F ?? ?? E8 ?? ?? ?? ?? 83 ?? FF 74").bytes.data(), ParsePattern("0F ?? ?? E8 ?? ?? ?? ?? 83 ?? FF 74").mask.c_str());
    if (addr) {
        BYTE* patchAddr3 = addr + 0x8;
        sprintf(buf, "Instance 3 found at 0x%p, patching at +8 (0x%p)", addr, patchAddr3);
        WriteLog(buf);
        sprintf(buf, "  BEFORE: %02X %02X %02X %02X", patchAddr3[0], patchAddr3[1], patchAddr3[2], patchAddr3[3]);
        WriteLog(buf);
        
        if (VirtualProtect(patchAddr3, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            patchAddr3[0] = 0x6A;
            patchAddr3[1] = 0x01;
            patchAddr3[2] = 0x58;
            patchAddr3[3] = 0x70;
            VirtualProtect(patchAddr3, 4, oldProtect, &oldProtect);
            sprintf(buf, "  AFTER: %02X %02X %02X %02X", patchAddr3[0], patchAddr3[1], patchAddr3[2], patchAddr3[3]);
            WriteLog(buf);
            successCount++;
        }
    }
    
    sprintf(buf, "Language Bypass: %d/3 patches applied (Force English Language)", successCount);
    WriteLog(buf);
    return successCount;
}

// ============================================================================
// PATCH 5: D Folder Bypass (Enable __St folder system) 
// ============================================================================
int ApplyDFolderBypassPatches(HMODULE hGameModule) {
    WriteLog("=== Applying D Folder Bypass Patches (Geo's Load Unpacked Files) ===");
    WriteLog("Pattern: 'C7 05 ?? ?? ?? ?? 00 00 00 00' (14 instances)");
    WriteLog("Patch at offset +6: Change DWORD from 0x00000000 to 0x00000001");
    
    int successCount = 0;
    ModuleBounds bounds = GetModuleTextBounds(hGameModule);
    
    if (!bounds.start) {
        WriteLog("ERROR: Could not get module bounds!");
        return 0;
    }
    
    // First, find the anchor pattern: C7 05 * * * * D0 02 00 00 C7 05 * * * * 01 00 00 00 C7 05 * * * * 00 00 00 00
    BYTE* anchor = PatternScanModuleIDA(hGameModule, "C7 05 ?? ?? ?? ?? D0 02 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00");
    
    if (!anchor) {
        WriteLog("ERROR: D folder anchor pattern not found!");
        return 0;
    }
    
    char buf[256];
    sprintf(buf, "Found anchor pattern at 0x%p", anchor);
    WriteLog(buf);
    
    // Now scan for 7 instances of "C7 05 * * * * 00 00 00 00" starting from anchor
    // Patch at offset +0x6 (the DWORD value)
    BYTE* addr = anchor;
    
    for (int i = 1; i <= 7; i++) {
        addr = PatternScanFrom(addr, bounds.end, ParsePattern("C7 05 ?? ?? ?? ?? 00 00 00 00").bytes.data(), ParsePattern("C7 05 ?? ?? ?? ?? 00 00 00 00").mask.c_str());
        if (addr) {
            DWORD* patchAddr = (DWORD*)(addr + 0x6);
            sprintf(buf, "  [Load_Unpacked_%d] Found at 0x%p, patching DWORD at +6 (0x%p)", i, addr, patchAddr);
            WriteLog(buf);
            sprintf(buf, "    BEFORE: 0x%08X", *patchAddr);
            WriteLog(buf);
            
            DWORD oldProtect;
            if (VirtualProtect(patchAddr, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                *patchAddr = 0x00000001;
                VirtualProtect(patchAddr, 4, oldProtect, &oldProtect);
                sprintf(buf, "    AFTER: 0x%08X", *patchAddr);
                WriteLog(buf);
                successCount++;
            }
            addr += 1; // Move past this match for next search
        } else {
            sprintf(buf, "  [Load_Unpacked_%d] NOT FOUND", i);
            WriteLog(buf);
            break;
        }
    }
    
    // Find the second anchor and scan for 7 more instances
    addr = PatternScanFrom(anchor + 1, bounds.end, ParsePattern("C7 05 ?? ?? ?? ?? D0 02 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00").bytes.data(), ParsePattern("C7 05 ?? ?? ?? ?? D0 02 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00").mask.c_str());
    
    if (addr) {
        sprintf(buf, "Found second anchor pattern at 0x%p", addr);
        WriteLog(buf);
        
        for (int i = 1; i <= 7; i++) {
            addr = PatternScanFrom(addr, bounds.end, ParsePattern("C7 05 ?? ?? ?? ?? 00 00 00 00").bytes.data(), ParsePattern("C7 05 ?? ?? ?? ?? 00 00 00 00").mask.c_str());
            if (addr) {
                DWORD* patchAddr = (DWORD*)(addr + 0x6);
                sprintf(buf, "  [Load_Unpacked_Unused_%d] Found at 0x%p, patching DWORD at +6 (0x%p)", i, addr, patchAddr);
                WriteLog(buf);
                sprintf(buf, "    BEFORE: 0x%08X", *patchAddr);
                WriteLog(buf);
                
                DWORD oldProtect;
                if (VirtualProtect(patchAddr, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    *patchAddr = 0x00000001;
                    VirtualProtect(patchAddr, 4, oldProtect, &oldProtect);
                    sprintf(buf, "    AFTER: 0x%08X", *patchAddr);
                    WriteLog(buf);
                    successCount++;
                }
                addr += 1;
            } else {
                sprintf(buf, "  [Load_Unpacked_Unused_%d] NOT FOUND", i);
                WriteLog(buf);
                break;
            }
        }
    }
    
    sprintf(buf, "D Folder Bypass: %d/14 MOV instructions patched (00000000 -> 00000001)", successCount);
    WriteLog(buf);
    return successCount;
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
    const bool ENABLE_PORTRAIT_MEMORY = true;   // ENABLED - 
    const bool ENABLE_STACK_MEMORY = true;       // ENABLED - Required for CSS to work
    const bool ENABLE_LANGUAGE_BYPASS = true;    // ENABLED - Geo's Force English
    const bool ENABLE_D_FOLDER_BYPASS = true;    // ENABLED - D folder runtime flag
    
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
    
    // Phase 2: Stack memory expansion (most complex) - APPLIED FIRST
    // This must come before portrait memory because portraits may depend on character arrays
    if (ENABLE_STACK_MEMORY) {
        totalPatches += ApplyStackMemoryExpansion(hGameModule);
    } else {
        WriteLog("=== Stack Memory Expansion: DISABLED FOR TESTING ===");
    }
    
    // Phase 3: Portrait memory hooks (complex) - APPLIED SECOND
    if (ENABLE_PORTRAIT_MEMORY) {
        totalPatches += ApplyPortraitMemoryExtension(hGameModule);
    } else {
        WriteLog("=== Portrait Memory Extension: DISABLED FOR TESTING ===");
    }
    
    // Phase 4: Language Bypass (Force English - fixes Steam language override)
    if (ENABLE_LANGUAGE_BYPASS) {
        totalPatches += ApplyLanguageBypassPatches(hGameModule);
    } else {
        WriteLog("=== Language Bypass: DISABLED FOR TESTING ===");
    }
    
    // Phase 5: D Folder Bypass (Enable __St folder system for mods)
    if (ENABLE_D_FOLDER_BYPASS) {
        totalPatches += ApplyDFolderBypassPatches(hGameModule);
    } else {
        WriteLog("=== D Folder Bypass: DISABLED FOR TESTING ===");
    }
    
    
    char buf[256];
    sprintf(buf, "=== Total Geo Patches Applied: %d ===", totalPatches);
    WriteLog(buf);
    WriteLog("====================================");
    WriteLog("");
}

