[ENABLE]
{$lua}
if syntaxcheck then return end
core.script.forceEnglishLanguage = {}
core.script.forceEnglishLanguage.origBytes = {}
local aob = "0F * * E8 * * * * 83 * FF 74"
local addr = AoBTools.ScanAoBTable({
    {aob, 0x8}
}, core.game.moduleAddress, core.game.moduleEndAddress)
table.insert(core.script.forceEnglishLanguage.origBytes, readBytes(addr, 0x4, true))
registerSymbol("Force_English_Language", addr, true)

addr = AoBTools.ScanAoBTable({
    {aob, 0x8}
}, addr, core.game.moduleEndAddress)
table.insert(core.script.forceEnglishLanguage.origBytes, readBytes(addr, 0x4, true))
registerSymbol("Force_English_Language_2", addr, true)

addr = AoBTools.ScanAoBTable({
    {aob, 0x8}
}, addr, core.game.moduleEndAddress)
table.insert(core.script.forceEnglishLanguage.origBytes, readBytes(addr, 0x4, true))
registerSymbol("Force_English_Language_3", addr, true)
{$asm}

Force_English_Language:
  db 6A 01 58 70

Force_English_Language_2:
  db 6A 01 58 70

Force_English_Language_3:
  db 6A 01 58 70

[DISABLE]
{$lua}
if syntaxcheck then return end
writeBytes(getAddressSafe("Force_English_Language"), core.script.forceEnglishLanguage.origBytes[0x1])
writeBytes(getAddressSafe("Force_English_Language_2"), core.script.forceEnglishLanguage.origBytes[0x2])
writeBytes(getAddressSafe("Force_English_Language_3"), core.script.forceEnglishLanguage.origBytes[0x2])
core.script.forceEnglishLanguage = nil
{$asm}
unregistersymbol(Force_English_Language)
unregistersymbol(Force_English_Language_2)
unregistersymbol(Force_English_Language_3)