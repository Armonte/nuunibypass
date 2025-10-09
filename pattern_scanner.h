// Pattern Scanner for finding code in memory dynamically
#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <sstream>

// Parse IDA-style pattern string: "83 F8 20 ?? ?? 84 C0"
// Returns vector of bytes and mask string
struct ParsedPattern {
    std::vector<BYTE> bytes;
    std::string mask;
};

inline ParsedPattern ParsePattern(const char* patternStr) {
    ParsedPattern result;
    std::stringstream ss(patternStr);
    std::string token;
    
    while (ss >> token) {
        if (token == "??" || token == "?" || token == "*") {
            result.bytes.push_back(0x00);
            result.mask += '?';
        } else {
            result.bytes.push_back((BYTE)strtoul(token.c_str(), nullptr, 16));
            result.mask += 'x';
        }
    }
    
    return result;
}

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

// Find pattern starting from a specific address (for finding multiple instances)
BYTE* PatternScanFrom(BYTE* start, BYTE* moduleEnd, const BYTE* pattern, const char* mask) {
    if (start >= moduleEnd) return nullptr;
    SIZE_T size = moduleEnd - start;
    return PatternScan(start, size, pattern, mask);
}

// Find all instances of a pattern
std::vector<BYTE*> PatternScanAll(BYTE* start, SIZE_T size, const BYTE* pattern, const char* mask) {
    std::vector<BYTE*> results;
    BYTE* current = start;
    BYTE* end = start + size;
    SIZE_T patternLen = strlen(mask);
    
    while (current < end) {
        BYTE* found = PatternScan(current, end - current, pattern, mask);
        if (!found) break;
        results.push_back(found);
        current = found + patternLen; // Continue after this match
    }
    
    return results;
}

// IDA-style pattern scan: "83 F8 20 ?? ?? 84 C0"
BYTE* PatternScanIDA(BYTE* start, SIZE_T size, const char* patternStr) {
    ParsedPattern parsed = ParsePattern(patternStr);
    return PatternScan(start, size, parsed.bytes.data(), parsed.mask.c_str());
}

// Find all instances with IDA-style pattern
std::vector<BYTE*> PatternScanAllIDA(BYTE* start, SIZE_T size, const char* patternStr) {
    ParsedPattern parsed = ParsePattern(patternStr);
    return PatternScanAll(start, size, parsed.bytes.data(), parsed.mask.c_str());
}

// Helper: Get module bounds
struct ModuleBounds {
    BYTE* start;
    BYTE* end;
    SIZE_T size;
};

ModuleBounds GetModuleTextBounds(HMODULE hModule) {
    ModuleBounds bounds = {nullptr, nullptr, 0};
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    // Find .text section
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            bounds.start = (BYTE*)hModule + section->VirtualAddress;
            bounds.size = section->Misc.VirtualSize;
            bounds.end = bounds.start + bounds.size;
            break;
        }
    }
    
    return bounds;
}

// Helper: Find pattern in entire .text section
BYTE* PatternScanModule(HMODULE hModule, const BYTE* pattern, const char* mask) {
    ModuleBounds bounds = GetModuleTextBounds(hModule);
    if (!bounds.start) return nullptr;
    return PatternScan(bounds.start, bounds.size, pattern, mask);
}

// IDA-style module scan
BYTE* PatternScanModuleIDA(HMODULE hModule, const char* patternStr) {
    ModuleBounds bounds = GetModuleTextBounds(hModule);
    if (!bounds.start) return nullptr;
    return PatternScanIDA(bounds.start, bounds.size, patternStr);
}

// Find all instances in module
std::vector<BYTE*> PatternScanModuleAllIDA(HMODULE hModule, const char* patternStr) {
    ModuleBounds bounds = GetModuleTextBounds(hModule);
    if (!bounds.start) return std::vector<BYTE*>();
    return PatternScanAllIDA(bounds.start, bounds.size, patternStr);
}

