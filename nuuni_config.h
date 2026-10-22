// NuUni Configuration System
#pragma once
#include <windows.h>
#include <cstdio>
#include <cstring>

struct NuUniConfig {
    int enable_logging;        // 0 = disabled, 1 = enabled
    int portrait_limit;        // Portrait limit (0 = uncapped, or specific value like 100)
    
    // Default values
    NuUniConfig() : enable_logging(0), portrait_limit(100) {}
};

class NuUniConfigManager {
private:
    NuUniConfig config;
    char configPath[MAX_PATH];
    
    // Trim whitespace from string
    void TrimString(char* str) {
        // Trim leading whitespace
        char* start = str;
        while (*start && (*start == ' ' || *start == '\t')) start++;
        
        // Trim trailing whitespace
        char* end = start + strlen(start) - 1;
        while (end > start && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
            *end = '\0';
            end--;
        }
        
        // Move trimmed string to beginning
        if (start != str) {
            memmove(str, start, strlen(start) + 1);
        }
    }
    
    // Parse a config line: key = value
    void ParseConfigLine(const char* line) {
        char lineCopy[256];
        strncpy(lineCopy, line, sizeof(lineCopy) - 1);
        lineCopy[sizeof(lineCopy) - 1] = '\0';
        
        // Skip comments and empty lines
        if (lineCopy[0] == '#' || lineCopy[0] == ';' || lineCopy[0] == '\0') {
            return;
        }
        
        // Find '=' separator
        char* equals = strchr(lineCopy, '=');
        if (!equals) return;
        
        *equals = '\0';
        char* key = lineCopy;
        char* value = equals + 1;
        
        TrimString(key);
        TrimString(value);
        
        // Parse known keys
        if (_stricmp(key, "log") == 0 || _stricmp(key, "logging") == 0 || _stricmp(key, "enable_logging") == 0) {
            config.enable_logging = atoi(value);
        }
        else if (_stricmp(key, "portrait_limit") == 0 || _stricmp(key, "portraits") == 0) {
            config.portrait_limit = atoi(value);
        }
    }
    
public:
    NuUniConfigManager() {
        // Get path to nuuni.ini in the same directory as the executable
        GetModuleFileNameA(NULL, configPath, MAX_PATH);
        char* lastSlash = strrchr(configPath, '\\');
        if (lastSlash) {
            *(lastSlash + 1) = '\0';
        }
        strcat(configPath, "nuuni.ini");
    }
    
    // Load config from file, create with defaults if doesn't exist
    bool LoadConfig() {
        FILE* file = fopen(configPath, "r");
        
        if (!file) {
            // File doesn't exist, create it with defaults
            return CreateDefaultConfig();
        }
        
        // Read and parse config
        char line[256];
        while (fgets(line, sizeof(line), file)) {
            ParseConfigLine(line);
        }
        
        fclose(file);
        return true;
    }
    
    // Create config file with default values
    bool CreateDefaultConfig() {
        FILE* file = fopen(configPath, "w");
        if (!file) {
            return false;
        }
        
        fprintf(file, "# NuUni Bypass Configuration\n");
        fprintf(file, "# Generated automatically - feel free to edit!\n");
        fprintf(file, "\n");
        fprintf(file, "# Enable logging to uni2_bypass.log (0 = disabled, 1 = enabled)\n");
        fprintf(file, "# Default: 0 (off) - enable for troubleshooting\n");
        fprintf(file, "log = %d\n", config.enable_logging);
        fprintf(file, "\n");
        fprintf(file, "# CSS Portrait limit (0 = uncapped, or set a specific limit)\n");
        fprintf(file, "# Default is 100 (0x64). Reduce if you have display issues.\n");
        fprintf(file, "# Examples: 32 (vanilla), 64, 100 (default), 0 (unlimited)\n");
        fprintf(file, "portrait_limit = %d\n", config.portrait_limit);
        fprintf(file, "\n");
        fprintf(file, "# Note: Changes take effect after restarting the game\n");
        
        fclose(file);
        return true;
    }
    
    // Getters
    bool IsLoggingEnabled() const { return config.enable_logging != 0; }
    int GetPortraitLimit() const { return config.portrait_limit; }
    
    // Get the actual byte value to patch (returns 0xFF for uncapped)
    BYTE GetPortraitLimitByte() const {
        if (config.portrait_limit <= 0 || config.portrait_limit > 255) {
            return 0xFF; // Uncapped
        }
        return (BYTE)config.portrait_limit;
    }
};

// Global config instance
extern NuUniConfigManager* g_Config;

// Helper to check if logging is enabled
inline bool IsLoggingEnabled() {
    return g_Config && g_Config->IsLoggingEnabled();
}

