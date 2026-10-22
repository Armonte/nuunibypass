[ENABLE]
{$lua}
if syntaxcheck then return end
local aob = "75 * 8B * * 83 * * 7C"
local addr = AoBTools.ScanAoBTable({
    {aob, 0x8}
}, core.game.moduleAddress, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes", addr, true)

addr = AoBTools.ScanAoBTable({
    {aob, 0x8}
}, addr, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes_2", addr, true)

aob = "83 * * 72 * 83 * * 83"
addr = AoBTools.ScanAoBTable({
    {aob, 0x3}
}, core.game.moduleAddress, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes_3", addr, true)

addr = AoBTools.ScanAoBTable({
    {aob, 0x3}
}, addr, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes_4", addr, true)

addr = AoBTools.ScanAoBTable({
    {aob, 0x3}
}, addr, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes_5", addr, true)

addr = AoBTools.ScanAoBTable({
    {aob, 0x3}
}, addr, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes_6", addr, true)

aob = "83 * * 7D * 83 * * 72"
addr = AoBTools.ScanAoBTable({
    {aob, 0x8}
}, core.game.moduleAddress, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes_7", addr, true)

addr = AoBTools.ScanAoBTable({
    {aob, 0x8}
}, addr, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes_8", addr, true)

addr = AoBTools.ScanAoBTable({
    {aob, 0x8}
}, addr, core.game.moduleEndAddress)
registerSymbol("Access_All_Palettes_9", addr, true)
{$asm}

Access_All_Palettes:
  db EB

Access_All_Palettes_2:
  db EB

Access_All_Palettes_3:
  db EB

Access_All_Palettes_4:
  db EB

Access_All_Palettes_5:
  db EB

Access_All_Palettes_6:
  db EB

Access_All_Palettes_7:
  db EB

Access_All_Palettes_8:
  db EB

Access_All_Palettes_9:
  db EB

[DISABLE]

Access_All_Palettes:
  db 7C

Access_All_Palettes_2:
  db 7C

Access_All_Palettes_3:
  db 72

Access_All_Palettes_4:
  db 72

Access_All_Palettes_5:
  db 72

Access_All_Palettes_6:
  db 72

Access_All_Palettes_7:
  db 72

Access_All_Palettes_8:
  db 72

Access_All_Palettes_9:
  db 72

unregistersymbol(Access_All_Palettes)
unregistersymbol(Access_All_Palettes_2)
unregistersymbol(Access_All_Palettes_3)
unregistersymbol(Access_All_Palettes_4)
unregistersymbol(Access_All_Palettes_5)
unregistersymbol(Access_All_Palettes_6)
unregistersymbol(Access_All_Palettes_7)
unregistersymbol(Access_All_Palettes_8)
unregistersymbol(Access_All_Palettes_9)