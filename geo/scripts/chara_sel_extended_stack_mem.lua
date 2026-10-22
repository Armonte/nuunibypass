-- ========================================
-- Character Select Extended Stack Memory
-- ========================================
-- This script expands stack-based character selection memory arrays to support
-- 256 characters. Unlike the portrait memory patch, this modifies stack frame
-- offsets and ModR/M bytes to point to custom allocated memory.
--
-- Key technique: x86 instructions encode memory offsets in their ModR/M/SIB bytes.
-- When we change a stack offset (e.g., [EBP-0x1234]) to point to absolute memory,
-- we must also modify the ModR/M byte to change addressing mode.
--
-- Example instruction transformation:
--   BEFORE: 8B 8D 34 12 FF FF    MOV ECX, [EBP-0xEDCC]
--           ^^ ^^  ^^^^^^^^^^^
--           |  |   4-byte offset (stack)
--           |  ModR/M byte (8D = [EBP+disp32])
--           Opcode
--
--   AFTER:  8B 0D 00 20 3A 12    MOV ECX, [0x123A2000]
--           ^^ ^^  ^^^^^^^^^^^
--           |  |   4-byte address (absolute)
--           |  ModR/M byte (0D = [disp32], note: 8D-80=0D)
--           Opcode
--
-- The -0x80 modification changes EBP-relative addressing to absolute addressing.

[ENABLE]
{$lua}
if syntaxcheck then return end

-- Allocate 4KB for extended stack memory
autoAssemble([[
alloc(Char_Sel_Extended_Stack_Memory,$1000)
registersymbol(Char_Sel_Extended_Stack_Memory)
]])

-- Initialize script namespace
core.script.charSelExtStackMem = {}

-- Set character limit to 256 (0x100)
core.script.charSelExtStackMem.charLimit = 0x100

-- Store original stack offsets for restoration
core.script.charSelExtStackMem.origOffs = {}

-- Two memory regions: base array and offset array
core.script.charSelExtStackMem.regions = {}
core.script.charSelExtStackMem.regions.one = {}  -- Base character array
core.script.charSelExtStackMem.regions.two = {}  -- Offset character array

-- ========================================
-- STEP 1: Find Region One base pattern and extract original stack offset
-- ========================================
-- Pattern: 8D * * * * * 89 * * * * * * * 3B * 7C * 8B
-- This locates a LEA instruction followed by MOV/CMP sequence
-- At offset +0x9 is a 4-byte stack offset (the original EBP-relative offset)
local addr = AoBTools.ScanAoBTable({
    {"8D * * * * * 89 * * * * * * * 3B * 7C * 8B"}
}, core.game.moduleAddress, core.game.moduleEndAddress)

-- Read the original 32-bit signed offset from the instruction
table.insert(core.script.charSelExtStackMem.origOffs, readIntegerSigned(addr+0x9))

-- Store patch location: {address of DWORD offset, ModR/M byte position relative to offset}
-- The ModR/M byte is 2 bytes BEFORE the DWORD, hence -0x2
table.insert(core.script.charSelExtStackMem.regions.one, {addr+0x9, -0x2})

-- ========================================
-- STEP 2: Find Region Two base pattern and extract original stack offset
-- ========================================
-- Pattern: 89 * * * * * * 85 * 7E
-- This locates a MOV instruction with embedded offset
-- At offset +0x3 is the 4-byte stack offset
addr = AoBTools.ScanAoBTable({
    {"89 * * * * * * 85 * 7E"}
}, addr, core.game.moduleEndAddress)

-- Read the original offset
table.insert(core.script.charSelExtStackMem.origOffs, readIntegerSigned(addr+0x3))

-- Store patch location (ModR/M byte is 2 bytes before offset)
table.insert(core.script.charSelExtStackMem.regions.two, {addr+0x3, -0x2})

-- ========================================
-- STEP 3: Build dynamic patterns using origOffset1 to find more Region One references
-- ========================================
-- Convert the original offset to byte string (little-endian) for pattern matching
local offBytes = dwordToByteTable(core.script.charSelExtStackMem.origOffs[0x1])
local offBytesStr = " "
for i, b in ipairs(offBytes) do
    offBytesStr = offBytesStr .. NumberToHexString(b) .. " "
end

-- Pattern: "7E * 8B * *" + offsetBytes
-- The second parameter (0x5) tells scanner to return address+0x5
-- This makes the returned address point DIRECTLY at the offset bytes
addr = AoBTools.ScanAoBTable({
    {"7E * 8B * *"..offBytesStr, 0x5}
}, addr, core.game.moduleEndAddress)
-- addr now points at offset bytes, ModR/M is 2 bytes before
table.insert(core.script.charSelExtStackMem.regions.one, {addr, -0x2})

-- Pattern: "39 * *" + offsetBytes
-- Scanner returns address+0x3, pointing at offset bytes
addr = AoBTools.ScanAoBTable({
    {"39 * *"..offBytesStr, 0x3}
}, addr, core.game.moduleEndAddress)
-- addr now points at offset bytes, ModR/M is 2 bytes before
table.insert(core.script.charSelExtStackMem.regions.one, {addr, -0x2})

-- ========================================
-- STEP 4: Build dynamic patterns using origOffset2 to find more Region Two references
-- ========================================
-- Convert the second original offset to byte string
offBytes = dwordToByteTable(core.script.charSelExtStackMem.origOffs[0x2])
offBytesStr = " "
for i, b in ipairs(offBytes) do
    offBytesStr = offBytesStr .. NumberToHexString(b) .. " "
end

-- Pattern: "89 * *" + offsetBytes + "* 3B"
-- Returns address+0x3, pointing at offset bytes
addr = AoBTools.ScanAoBTable({
    {"89 * *"..offBytesStr.."* 3B", 0x3}
}, addr, core.game.moduleEndAddress)
table.insert(core.script.charSelExtStackMem.regions.two, {addr, -0x2})

-- Pattern: "8B * *" + offsetBytes + "05"
-- Returns address+0x3, pointing at offset bytes
addr = AoBTools.ScanAoBTable({
    {"8B * *"..offBytesStr.."05", 0x3}
}, addr, core.game.moduleEndAddress)
table.insert(core.script.charSelExtStackMem.regions.two, {addr, -0x2})

-- Pattern: "8D *" + offsetBytes + "6A"
-- Returns address+0x2, pointing at offset bytes
-- Note: ModR/M is only 1 byte before here (different instruction encoding)
addr = AoBTools.ScanAoBTable({
    {"8D *"..offBytesStr.."6A", 0x2}
}, addr, core.game.moduleEndAddress)
table.insert(core.script.charSelExtStackMem.regions.two, {addr, -0x1})

-- Pattern: "8D *" + offsetBytes + "68"
addr = AoBTools.ScanAoBTable({
    {"8D *"..offBytesStr.."68", 0x2}
}, addr, core.game.moduleEndAddress)
table.insert(core.script.charSelExtStackMem.regions.two, {addr, -0x1})

-- Pattern: "8D *" + offsetBytes + "8D"
addr = AoBTools.ScanAoBTable({
    {"8D *"..offBytesStr.."8D", 0x2}
}, addr, core.game.moduleEndAddress)
table.insert(core.script.charSelExtStackMem.regions.two, {addr, -0x1})

-- Pattern: "8D *" + offsetBytes + "68" (duplicate pattern, might be different instance)
addr = AoBTools.ScanAoBTable({
    {"8D *"..offBytesStr.."68", 0x2}
}, addr, core.game.moduleEndAddress)
table.insert(core.script.charSelExtStackMem.regions.two, {addr, -0x1})

-- ========================================
-- STEP 5: Apply all patches
-- ========================================
-- Get the base address of our allocated memory
addr = getAddressSafe("Char_Sel_Extended_Stack_Memory")

-- Patch all Region One locations (base array)
-- Each entry contains: {address_of_offset_dword, modrm_byte_relative_position}
for _,tbl in ipairs(core.script.charSelExtStackMem.regions.one) do
    local a = tbl[0x1]  -- Address where the 4-byte offset is stored
    local o = tbl[0x2]  -- Relative position of ModR/M byte (negative, e.g., -0x2)
    
    -- Replace the 4-byte stack offset with absolute address to our memory
    writeInteger(a, addr)
    
    -- Modify the ModR/M byte to change from EBP-relative to absolute addressing
    -- Subtracting 0x80 changes the addressing mode:
    --   8D ([EBP+disp32]) -> 0D ([disp32])
    --   8B ([EBP+disp32]) -> 0B ([disp32])  etc.
    writeByte(a+o, readByte(a+o)-0x80)
end

-- Patch all Region Two locations (offset array starts at base + charLimit*4)
for _,tbl in ipairs(core.script.charSelExtStackMem.regions.two) do
    local a = tbl[0x1]  -- Address of offset DWORD
    local o = tbl[0x2]  -- Relative position of ModR/M byte
    
    -- Point to second array region (256 * 4 bytes after base)
    writeInteger(a, addr+(core.script.charSelExtStackMem.charLimit*0x4))
    
    -- Modify ModR/M byte for absolute addressing
    writeByte(a+o, readByte(a+o)-0x80)
end
{$asm}


-- ========================================
-- DISABLE Section: Restore original instructions
-- ========================================
[DISABLE]
{$lua}
if syntaxcheck then return end

-- Restore all Region One patches
for _,tbl in ipairs(core.script.charSelExtStackMem.regions.one) do
    local a = tbl[0x1]  -- Address of offset DWORD
    local o = tbl[0x2]  -- ModR/M byte offset
    
    -- Restore original stack offset
    writeInteger(a, core.script.charSelExtStackMem.origOffs[0x1])
    
    -- Restore ModR/M byte (add back 0x80 to restore EBP-relative addressing)
    writeByte(a+o, readByte(a+o)+0x80)
end

-- Restore all Region Two patches
for _,tbl in ipairs(core.script.charSelExtStackMem.regions.two) do
    local a = tbl[0x1]  -- Address of offset DWORD
    local o = tbl[0x2]  -- ModR/M byte offset
    
    -- Restore original stack offset
    writeInteger(a, core.script.charSelExtStackMem.origOffs[0x2])
    
    -- Restore ModR/M byte
    writeByte(a+o, readByte(a+o)+0x80)
end

-- Clean up namespace
core.script.charSelExtStackMem = nil
{$asm}

// Deallocate memory
dealloc(charSelExtStackMem)
unregistersymbol(Char_Sel_Extended_Stack_Memory)