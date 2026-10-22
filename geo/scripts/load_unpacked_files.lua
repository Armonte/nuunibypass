[ENABLE]
{$lua}
if syntaxcheck then return end
core.script.loadUnpackedFiles = {}
core.script.loadUnpackedFiles.origBytes = {}
local aob = "E9 * * * * 68 * * * * 68 * * * * E8"
local vTable = {}
vTable.End = AoBTools.ScanAoBTable({
    {aob, 0x6, {AoBTools.AoBPointerType.FarAddress}}
}, core.game.moduleAddress, core.game.moduleEndAddress)
vTable.Start = AoBTools.ScanAoBTable({
    {aob, 0xB, {AoBTools.AoBPointerType.FarAddress}}
}, core.game.moduleAddress, core.game.moduleEndAddress)
vTable.Count = bShr(vTable.End - vTable.Start + 0x3, 0x2)

aob = "C7 05 * * * * D0 02 00 00 C7 05 * * * * 01 00 00 00 C7 05 * * * * 00 00 00 00"
local addr = AoBTools.ScanAoBTable({
    {aob}
}, core.game.moduleAddress, core.game.moduleEndAddress)

local symbolStr = "Load_Unpacked_Files"
for i=0x1,0x7 do
    addr = AoBTools.ScanAoBTable({
        {"C7 05 * * * * 00 00 00 00", 0x6}
    }, addr, core.game.moduleEndAddress)
    table.insert(core.script.loadUnpackedFiles.origBytes, readBytes(addr, 0x4, true))
    local symName = symbolStr
    if i > 0x1 then symName = symName .. "_" .. i end
    registerSymbol(symName, addr, true)
end

addr = AoBTools.ScanAoBTable({
    {aob}
}, addr, core.game.moduleEndAddress)

symbolStr = symbolStr.."_Unused"
for i=0x1,0x7 do
    addr = AoBTools.ScanAoBTable({
        {"C7 05 * * * * 00 00 00 00", 0x6}
    }, addr, core.game.moduleEndAddress)
    table.insert(core.script.loadUnpackedFiles.origBytes, readBytes(addr, 0x4, true))
    local symName = symbolStr
    if i > 0x1 then symName = symName .. "_" .. i end
    registerSymbol(symName, addr, true)
end
{$asm}

Load_Unpacked_Files:
  dd 01

Load_Unpacked_Files_2:
  dd 01

Load_Unpacked_Files_3:
  dd 01

Load_Unpacked_Files_4:
  dd 01

Load_Unpacked_Files_5:
  dd 01

Load_Unpacked_Files_6:
  dd 01

Load_Unpacked_Files_7:
  dd 01

Load_Unpacked_Files_Unused:
  dd 01

Load_Unpacked_Files_Unused_2:
  dd 01

Load_Unpacked_Files_Unused_3:
  dd 01

Load_Unpacked_Files_Unused_4:
  dd 01

Load_Unpacked_Files_Unused_5:
  dd 01

Load_Unpacked_Files_Unused_6:
  dd 01

Load_Unpacked_Files_Unused_7:
  dd 01


[DISABLE]
{$lua}
if syntaxcheck then return end
local symbolStr = "Load_Unpacked_Files"
for i=0x1,0x7 do
    local symName = symbolStr
    if i > 0x1 then symName = symName .. "_" .. i end
    writeBytes(getAddressSafe(symName), core.script.loadUnpackedFiles.origBytes[i])
    unregisterSymbol(symName)
end

symbolStr = symbolStr.."_Unused"
for i=0x1,0x7 do
    local symName = symbolStr
    if i > 0x1 then symName = symName .. "_" .. i end
    writeBytes(getAddressSafe(symName), core.script.loadUnpackedFiles.origBytes[i])
    unregisterSymbol(symName)
end
core.script.loadUnpackedFiles = nil
{$asm}