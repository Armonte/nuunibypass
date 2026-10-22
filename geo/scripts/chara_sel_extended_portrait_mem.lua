
[ENABLE]
{$lua}
if syntaxcheck then return end

print("========================================")
print("=== Portrait Memory Extension (Lua) ===")
print("========================================")

-- Allocate memory for extended portrait system
autoAssemble([[
alloc(Char_Sel_Extended_Portrait_Memory,$1000)
registersymbol(Char_Sel_Extended_Portrait_Memory)
]])

local memAddr = getAddressSafe("Char_Sel_Extended_Portrait_Memory")
print(string.format("Allocated 0x1000 bytes at 0x%X", memAddr))

-- Initialize script namespace
core.script.charSelExtPortraitMem = {}

-- Set character limit to 256 (0x100)
core.script.charSelExtPortraitMem.charLimit = 0x100
print(string.format("Character limit: %d (0x%X)", 
    core.script.charSelExtPortraitMem.charLimit,
    core.script.charSelExtPortraitMem.charLimit))

-- Store original bytes for restoration on disable
core.script.charSelExtPortraitMem.origBytes = {}

print("")

-- ========================================
-- Patch Point 1: Portrait pointer array initialization
-- ========================================
-- Pattern: C6 * * 02 8D * * C7 * * 00 00 00 00
-- Breakdown: C6 [1] [1] 02 | 8D [1] [1] | C7 [1] [1] 00 00 00 00
--            0  1  2   3    | 4  5  6    | 7  8  9  A  B  C  D
--
-- The pattern finds: ... | LEA EAX,[ESI+8] | MOV DWORD PTR [ESI+4], 0
-- Scanner returns address+0x4, pointing AT the LEA instruction (8D opcode)
--
-- Original instruction we're replacing: 8D 46 08  (LEA EAX, [ESI+8])
--   8D = LEA opcode
--   46 = ModR/M byte (01 000 110 = [ESI+disp8])
--   08 = 8-bit displacement
--
-- We need to read 10 bytes (0xA) starting from the LEA for our detour
print("Hook 1: Searching for pattern 'C6 * * 02 8D * * C7 * * 00 00 00 00'")
local addr = AoBTools.ScanAoBTable({
    {"C6 * * 02 8D * * C7 * * 00 00 00 00", 0x4}
}, core.game.moduleAddress, core.game.moduleEndAddress)

if addr then
    print(string.format("  Found at: 0x%X (pattern match + 0x4 offset)", addr))
    
    -- Save original 10 bytes: LEA + following MOV instruction
    local origBytes = readBytes(addr, 0xA, true)
    table.insert(core.script.charSelExtPortraitMem.origBytes, origBytes)
    
    -- Log original bytes
    local hexStr = ""
    for i, b in ipairs(origBytes) do
        hexStr = hexStr .. string.format("%02X ", b)
    end
    print(string.format("  Original 10 bytes: %s", hexStr))
    
    registerSymbol("CSel_Portrait_Extension", addr, true)
    print("  ✓ Hook 1 prepared")
else
    print("  ✗ ERROR: Pattern not found!")
end
print("")

-- ========================================
-- Patch Point 2: Portrait pointer array access
-- ========================================
-- Pattern: 0F 84 * * * * 8D * * C7 * * * * * 00 00 00 00
-- Breakdown: 0F 84 [4] | 8D [1] [1] | C7 [1] [1] [5 more]
--            0  1  2-5  | 6  7  8    | 9  A  B  C-0x12
--
-- The pattern finds: JE ... | LEA EAX,[ESI] | MOV DWORD PTR [...], 0
-- Scanner returns address+0x6, pointing AT the LEA instruction (8D opcode)
--
-- Original instruction: 8D 46 00  (LEA EAX, [ESI+0] or LEA EAX, [ESI])
--   8D = LEA opcode
--   46 = ModR/M byte (01 000 110 = [ESI+disp8])
--   00 = 8-bit displacement (0)
--
-- We need to read 13 bytes (0xD) starting from the LEA
print("Hook 2: Searching for pattern '0F 84 * * * * 8D * * C7 * * * * * 00 00 00 00'")
addr = AoBTools.ScanAoBTable({
    {"0F 84 * * * * 8D * * C7 * * * * * 00 00 00 00", 0x6}
}, addr, core.game.moduleEndAddress)

if addr then
    print(string.format("  Found at: 0x%X (pattern match + 0x6 offset)", addr))
    
    -- Save original 13 bytes: LEA + following instructions
    local origBytes = readBytes(addr, 0xD, true)
    table.insert(core.script.charSelExtPortraitMem.origBytes, origBytes)
    
    -- Log original bytes
    local hexStr = ""
    for i, b in ipairs(origBytes) do
        hexStr = hexStr .. string.format("%02X ", b)
    end
    print(string.format("  Original 13 bytes: %s", hexStr))
    
    registerSymbol("CSel_Portrait_Extension_2", addr, true)
    print("  ✓ Hook 2 prepared")
else
    print("  ✗ ERROR: Pattern not found!")
end
print("")

-- ========================================
-- Patch Point 3: Portrait loop boundary check
-- ========================================
-- Pattern: C7 * * 00 00 00 00 8D * * BF * * * *
-- Breakdown: C7 [1] [1] 00 00 00 00 | 8D [1] [1] | BF [4]
--            0  1  2  3  4  5  6     | 7  8  9    | A  B-D
--
-- The pattern finds: MOV DWORD PTR [...], 0 | LEA ESI,[...] | MOV EDI, constant
-- Scanner returns address+0x7, pointing AT the LEA instruction (8D opcode)
--
-- Original bytes (8 bytes): 8D [2] BF [4]
--   8D 35 [4-byte address] = LEA ESI, [absolute_address]
--   BF [4-byte value]      = MOV EDI, immediate32
--
-- This is the loop that iterates through portraits. We need to:
--   1. Point ESI to our custom memory (LEA ESI, [our_memory])
--   2. Set EDI to our character limit (MOV EDI, 0x100)
--
-- We need to read 8 bytes starting from the LEA
print("Hook 3: Searching for pattern 'C7 * * 00 00 00 00 8D * * BF * * * *'")
addr = AoBTools.ScanAoBTable({
    {"C7 * * 00 00 00 00 8D * * BF * * * *", 0x7}
}, core.game.moduleAddress, core.game.moduleEndAddress)

if addr then
    print(string.format("  Found at: 0x%X (pattern match + 0x7 offset)", addr))
    
    -- Save original 8 bytes: LEA ESI + MOV EDI
    local origBytes = readBytes(addr, 0x8, true)
    table.insert(core.script.charSelExtPortraitMem.origBytes, origBytes)
    
    -- Log original bytes
    local hexStr = ""
    for i, b in ipairs(origBytes) do
        hexStr = hexStr .. string.format("%02X ", b)
    end
    print(string.format("  Original 8 bytes: %s", hexStr))
    
    registerSymbol("CSel_Portrait_Extension_3", addr, true)
    print("  ✓ Hook 3 prepared")
else
    print("  ✗ ERROR: Pattern not found!")
end
print("")

print("All hooks prepared, now assembling and installing...")
print("========================================")
{$asm}
// ========================================
// Assembly Section: Define labels for jumps
// ========================================
label(cselPortraitExtension)
label(cselPortraitExtension_return)
registersymbol(cselPortraitExtension)

label(cselPortraitExtension_2)
label(cselPortraitExtension_2_return)
registersymbol(cselPortraitExtension_2)

label(cselPortraitExtension_3)
label(cselPortraitExtension_3_return)
registersymbol(cselPortraitExtension_3)

// ========================================
// Extended Portrait Memory Block
// ========================================
Char_Sel_Extended_Portrait_Memory:

// ----------------------------------------
// Detour 1: Redirect portrait array pointer (initialization)
// ----------------------------------------
// This detour code lives in our custom allocated memory.
// When execution jumps here, we:
//   1. Execute a NEW LEA that points to OUR memory instead of game's memory
//   2. Execute the REMAINING original bytes (skip first 3 bytes of original LEA)
//   3. Jump back to continue normal execution
//
// Original bytes saved: 8D 46 08 C7 46 04 00 00 00 00 (10 bytes)
//   Bytes 0-2: 8D 46 08          = LEA EAX, [ESI+8] <-- We REPLACE this with our LEA
//   Bytes 3-9: C7 46 04 00 00 00 00 = MOV DWORD PTR [ESI+4], 0 <-- We KEEP and execute this
//
cselPortraitExtension:
  // NEW LEA: Point EAX to our custom memory (+8 offset to match original [ESI+8])
  lea eax,[CSel_Portrait_Extension_Memory_Pointers+8]
{$lua}
if syntaxcheck then return end
-- Dynamically insert bytes 4-9 of original instruction (the MOV that follows)
-- We skip the first 3 bytes (index 1,2,3) which were the original LEA
local str = "db "
for i,b in ipairs(core.script.charSelExtPortraitMem.origBytes[0x1]) do
    if i > 0x3 then  -- Skip first 3 bytes (Lua is 1-indexed)
      str=str..NumberToHexString(b).." "
    end
end
return str
{$asm}
  jmp cselPortraitExtension_return  // Jump back to original code after our hook

// ----------------------------------------
// Detour 2: Redirect portrait array pointer (access)
// ----------------------------------------
// Similar to Detour 1, but this time:
//   - No offset needed (original was LEA EAX, [ESI+0])
//   - 13 bytes saved total
//
// Original bytes: 8D 46 00 C7 ... (13 bytes)
//   Bytes 0-2: 8D 46 00 = LEA EAX, [ESI+0] <-- REPLACE with our LEA
//   Bytes 3-12: Following instructions <-- KEEP and execute
//
cselPortraitExtension_2:
  // NEW LEA: Point EAX to our custom memory (no offset this time)
  lea eax,[CSel_Portrait_Extension_Memory_Pointers]
{$lua}
if syntaxcheck then return end
-- Insert bytes 4-13 of original instructions
local str = "db "
for i,b in ipairs(core.script.charSelExtPortraitMem.origBytes[0x2]) do
    if i > 0x3 then  -- Skip first 3 bytes (the LEA we replaced)
      str=str..NumberToHexString(b).." "
    end
end
return str
{$asm}
  jmp cselPortraitExtension_2_return

// ----------------------------------------
// Detour 3: Set extended character limit (loop control)
// ----------------------------------------
// This detour replaces TWO instructions:
//   LEA ESI,[original_array]  -> LEA ESI,[our_array]
//   MOV EDI, original_limit   -> MOV EDI, 0x100 (our limit)
//
// These registers control the loop that processes all portraits:
//   ESI = pointer to portrait array start
//   EDI = number of portraits to process
//
cselPortraitExtension_3:
  lea esi,[CSel_Portrait_Extension_Memory_Pointers]  // Point to our memory
  mov edi,#256  // Set loop limit to 256
  jmp cselPortraitExtension_3_return

// ----------------------------------------
// Portrait Pointer Array (256 pointers, 4 bytes each = 1024 bytes)
// ----------------------------------------
CSel_Portrait_Extension_Memory_Pointers:
registersymbol(CSel_Portrait_Extension_Memory_Pointers)
{$lua}
if syntaxcheck then return end
-- Generate array of null pointers (4 bytes per character)
local str = "db "
for i=0x0,core.script.charSelExtPortraitMem.charLimit do
    str = str.."00 00 00 00 "
end
return str
{$asm}

// ========================================
// Injection Points: Overwrite original code with jumps
// ========================================
// This is where the MAGIC happens. CheatEngine's autoAssemble will:
//   1. Generate all the code above (detours, memory, etc.)
//   2. Overwrite the ORIGINAL game code at these symbols with JMP instructions
//   3. The JMP instructions redirect execution to our detours
//   4. Our detours execute and JMP back to the return labels
//
// The autoAssemble syntax "CSel_Portrait_Extension:" refers to the registered
// symbol we created earlier, which points to the original game code location.

// Patch Point 1: Overwrite 10 bytes at original location
// Original: 8D 46 08 C7 46 04 00 00 00 00
// Becomes:  E9 [4-byte rel offset] 90 90 90 90 90
//           ^JMP to detour        ^NOPs for padding
CSel_Portrait_Extension:
  jmp cselPortraitExtension      // 5-byte JMP instruction (E9 + 4-byte offset)
  nop 5                           // 5 NOPs to fill remaining 5 bytes = 10 total
cselPortraitExtension_return:     // This is where the detour jumps back to

// Patch Point 2: Overwrite 13 bytes at original location
// Original: 8D 46 00 C7 ... (13 bytes)
// Becomes:  E9 [4-byte rel offset] 90 90 90 90 90 90 90 90
CSel_Portrait_Extension_2:
  jmp cselPortraitExtension_2     // 5-byte JMP
  nop 8                            // 8 NOPs to fill = 13 total
cselPortraitExtension_2_return:

// Patch Point 3: Overwrite 8 bytes at original location
// Original: 8D 35 [4] BF [4] = 8 bytes total (6-byte LEA + 5-byte MOV, overlaps)
// Becomes:  E9 [4-byte rel offset] 90 90 90
CSel_Portrait_Extension_3:
  jmp cselPortraitExtension_3     // 5-byte JMP
  nop 3                            // 3 NOPs to fill = 8 total
cselPortraitExtension_3_return:

{$lua}
if syntaxcheck then return end

-- Verification runs AFTER autoAssemble completes
print("")
print("========================================")
print("=== Installation Complete - Verification ===")
print("========================================")

-- Verify Hook 1
local success, addr1 = pcall(getAddressSafe, "CSel_Portrait_Extension")
if success and addr1 then
    local success2, detour1 = pcall(getAddressSafe, "cselPortraitExtension")
    if success2 and detour1 then
        print("Hook 1 Verification:")
        print(string.format("  Original location: 0x%X", addr1))
        print(string.format("  Detour location:   0x%X", detour1))
        print(string.format("  JMP distance:      %d bytes (0x%X)", detour1 - addr1, detour1 - addr1))
        
        local patchedBytes1 = readBytes(addr1, 10, true)
        local hexStr1 = ""
        for i, b in ipairs(patchedBytes1) do
            hexStr1 = hexStr1 .. string.format("%02X ", b)
        end
        print(string.format("  Patched 10 bytes:  %s", hexStr1))
        
        -- Read detour code
        local detourBytes1 = readBytes(detour1, 20, true)
        local detourHex1 = ""
        for i, b in ipairs(detourBytes1) do
            detourHex1 = detourHex1 .. string.format("%02X ", b)
            if i % 8 == 0 then
                detourHex1 = detourHex1 .. "\n                     "
            end
        end
        print(string.format("  Detour code:       %s", detourHex1))
    else
        print("Hook 1: ✗ Could not get detour address")
    end
else
    print("Hook 1: ✗ Could not get original address")
end

-- Verify Hook 2
local success, addr2 = pcall(getAddressSafe, "CSel_Portrait_Extension_2")
if success and addr2 then
    local success2, detour2 = pcall(getAddressSafe, "cselPortraitExtension_2")
    if success2 and detour2 then
        print("")
        print("Hook 2 Verification:")
        print(string.format("  Original location: 0x%X", addr2))
        print(string.format("  Detour location:   0x%X", detour2))
        print(string.format("  JMP distance:      %d bytes (0x%X)", detour2 - addr2, detour2 - addr2))
        
        local patchedBytes2 = readBytes(addr2, 13, true)
        local hexStr2 = ""
        for i, b in ipairs(patchedBytes2) do
            hexStr2 = hexStr2 .. string.format("%02X ", b)
        end
        print(string.format("  Patched 13 bytes:  %s", hexStr2))
        
        -- Read detour code
        local detourBytes2 = readBytes(detour2, 24, true)
        local detourHex2 = ""
        for i, b in ipairs(detourBytes2) do
            detourHex2 = detourHex2 .. string.format("%02X ", b)
            if i % 8 == 0 then
                detourHex2 = detourHex2 .. "\n                     "
            end
        end
        print(string.format("  Detour code:       %s", detourHex2))
    else
        print("Hook 2: ✗ Could not get detour address")
    end
else
    print("Hook 2: ✗ Could not get original address")
end

-- Verify Hook 3
local success, addr3 = pcall(getAddressSafe, "CSel_Portrait_Extension_3")
if success and addr3 then
    local success2, detour3 = pcall(getAddressSafe, "cselPortraitExtension_3")
    if success2 and detour3 then
        print("")
        print("Hook 3 Verification:")
        print(string.format("  Original location: 0x%X", addr3))
        print(string.format("  Detour location:   0x%X", detour3))
        print(string.format("  JMP distance:      %d bytes (0x%X)", detour3 - addr3, detour3 - addr3))
        
        local patchedBytes3 = readBytes(addr3, 8, true)
        local hexStr3 = ""
        for i, b in ipairs(patchedBytes3) do
            hexStr3 = hexStr3 .. string.format("%02X ", b)
        end
        print(string.format("  Patched 8 bytes:   %s", hexStr3))
        
        -- Read detour code
        local detourBytes3 = readBytes(detour3, 16, true)
        local detourHex3 = ""
        for i, b in ipairs(detourBytes3) do
            detourHex3 = detourHex3 .. string.format("%02X ", b)
            if i % 8 == 0 then
                detourHex3 = detourHex3 .. "\n                     "
            end
        end
        print(string.format("  Detour code:       %s", detourHex3))
    else
        print("Hook 3: ✗ Could not get detour address")
    end
else
    print("Hook 3: ✗ Could not get original address")
end

-- Show portrait array info
local success, portraitArray = pcall(getAddressSafe, "CSel_Portrait_Extension_Memory_Pointers")
if success and portraitArray then
    print("")
    print("Portrait Array Verification:")
    print(string.format("  Array location:    0x%X", portraitArray))
    print("  First 8 pointers:")
    for i = 0, 7 do
        local ptrAddr = portraitArray + (i * 4)
        local ptrValue = readInteger(ptrAddr)
        print(string.format("    [%d] @ 0x%X = 0x%08X", i, ptrAddr, ptrValue))
    end
else
    print("✗ Could not get portrait array address")
end

print("")
print("✓ All patches installed successfully!")
print("✓ Portrait system extended to 256 characters")
print("========================================")
print("")

{$asm}

// ========================================
// DISABLE Section: Restore original bytes
// ========================================
[DISABLE]

{$lua}
if syntaxcheck then return end
print("========================================")
print("=== Disabling Portrait Memory Extension ===")
print("========================================")

-- Restore original bytes for patch point 1
print("Restoring Hook 1...")
writeBytes(getAddressSafe("CSel_Portrait_Extension"), core.script.charSelExtPortraitMem.origBytes[0x1])
print("  ✓ Hook 1 restored")
{$asm}
unregistersymbol(CSel_Portrait_Extension)
unregistersymbol(cselPortraitExtension)

{$lua}
if syntaxcheck then return end
-- Restore original bytes for patch point 2
print("Restoring Hook 2...")
writeBytes(getAddressSafe("CSel_Portrait_Extension_2"), core.script.charSelExtPortraitMem.origBytes[0x2])
print("  ✓ Hook 2 restored")
{$asm}
unregistersymbol(CSel_Portrait_Extension_2)
unregistersymbol(cselPortraitExtension_2)

{$lua}
if syntaxcheck then return end
-- Restore original bytes for patch point 3
print("Restoring Hook 3...")
writeBytes(getAddressSafe("CSel_Portrait_Extension_3"), core.script.charSelExtPortraitMem.origBytes[0x3])
print("  ✓ Hook 3 restored")
{$asm}
unregistersymbol(CSel_Portrait_Extension_3)
unregistersymbol(cselPortraitExtension_3)

{$lua}
if syntaxcheck then return end
print("Deallocating memory...")
{$asm}
unregistersymbol(CSel_Portrait_Extension_Memory_Pointers)
// Deallocate extended memory
dealloc(Char_Sel_Extended_Portrait_Memory)
{$lua}
if syntaxcheck then return end
print("✓ Portrait memory extension disabled")
print("========================================")
{$asm}
