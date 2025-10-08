// Pattern Scanner for finding code in memory dynamically
#pragma once
#include <windows.h>

// Find a pattern in memory
// Pattern format: "E8 ?? ?? ?? ?? 84 C0 74" where ?? = wildcard
BYTE* PatternScan(BYTE* start, SIZE_T size, const BYTE* pattern, const char* mask) {
    SIZE_T patternLen = strlen(mask);

    for (SIZE_T i = 0; i < size - patternLen; i++) {
        bool found = true;
        for (SIZE_T j = 0; j < patternLen; j++) {
            if (mask[j] == 'x' && pattern[j] != start[i + j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return &start[i];
        }
    }
    return nullptr;
}

// Helper: Find pattern in entire .text section
BYTE* PatternScanModule(HMODULE hModule, const BYTE* pattern, const char* mask) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    // Find .text section
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            BYTE* start = (BYTE*)hModule + section->VirtualAddress;
            SIZE_T size = section->Misc.VirtualSize;
            return PatternScan(start, size, pattern, mask);
        }
    }
    return nullptr;
}

