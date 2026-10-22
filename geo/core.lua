{$lua}
if syntaxcheck then return end
[ENABLE]
Is64Bit = targetIs64Bit() PointerSize = Is64Bit and 0x8 or 0x4
core = {} core.game = {} core.game.moduleName = process core.game.moduleAddress = getAddressSafe(core.game.moduleName) core.game.moduleSize = getModuleSize(core.game.moduleName) core.game.moduleEndAddress = core.game.moduleAddress + core.game.moduleSize core.static = {} core.script = {}
synchronize(function()
local children = MemoryRecordTools.GetChildren(memrec, true)
for i,c in ipairs(children) do
    if c.DontSave == true then
        pcall(memoryrecord_delete, c)
    else
        c.Active = false
    end
end
end)
[DISABLE]
core = nil
{$asm}