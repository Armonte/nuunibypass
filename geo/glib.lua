--- General Tools ---
GeneralTools = {}
GeneralTools.WaitCanceled = false
function GeneralTools.WaitForCondition(conditionFunc, times, delay)
    while(GeneralTools.WaitCanceled == false and times > 0 and conditionFunc() == false) do
        times = times - 1
        sleep(delay)
    end
    return conditionFunc()
end

function GeneralTools.RemoveEmptyTables(tbl)
    if not tbl and table.length(tbl) == 0x0 then return end
    for k,v in pairs(tbl) do
        if type(v) == "table" then
            if table.length(v) > 0x0 then
                GeneralTools.RemoveEmptyTables(v)
            end
            if table.length(v) == 0x0 then
                tbl[k] = nil
            end
        end
    end
end

function GeneralTools.CreateDelimitedVariable(tbl, varString, delimiter, removeStrings)
    local var = tbl
    if not delimiter then delimiter = '.' end
    local nameParts = {}
    for part in string.gmatch(varString, "([^" .. delimiter .. "]+)") do
        local partName = part
        if removeStrings then
            for i, rs in pairs(removeStrings) do
                partName = partName:gsub(rs, "")
            end
        end
        table.insert(nameParts, partName)
    end
    for i, part in ipairs(nameParts) do
        if not var[part] then var[part] = {} end
        var = var[part]
    end
    return var
end

--- Thread Tools ---
ThreadTools = {}
local function createWatcherThreadProtected(Thread, params)
    local delay = params[0x1]
    local condFunc = params[0x2]
    local func = params[0x3]
    local threadVals = params[0x4]
    while not Thread.Terminated do
        sleep(delay)
        if Thread.Terminated then return end
        local s, b = pcall(condFunc, threadVals)
        if s and b then
            local s, e = pcall(func, threadVals)
            if not s and e then print(e) end
        elseif b then
            print(b)
        end
    end
end
function ThreadTools.CreateWatcherThread(delay, condFunc, func, threadVals)
local result = nil
synchronize(function(d, cf, f, tv, r)
    r = createThread(function(Thread)
        pcall(createWatcherThreadProtected, Thread, {d, cf, f, tv})
    end)
end, delay, condFunc, func, threadVals, result)
return result
end

--- UI Tools ---
UITools = {}
local cycleFullCompact = function(sender, force)
    local state = not(compactMenuItem.Caption == 'Compact View')
    if force~=nil
        then state = not force
    end
    compactMenuItem.Caption = state and 'Compact View' or 'Full View'
    getMainForm().Splitter1.Visible = state
    getMainForm().Panel4.Visible = state
    getMainForm().Panel5.Visible = state
end
function UITools.AddCompactMenu()
    if compactMenuItem and compactMenuItem.Exists then return end
    local menuItems = getMainForm().Menu.Items
    compactMenuItem = createMenuItem(menuItems)
    menuItems.add(compactMenuItem)
    compactMenuItem.Caption = 'Compact View'
    compactMenuItem.OnClick = cycleFullCompact
    compactMenuItem.Exists = true
end
--- Executable Tools ---
ExecutableTools = {}
function ExecutableTools.ParseVTable(funcTblAddr, moduleName)
    local addr = funcTblAddr
    local funcAddr = readPointer(addr)
    local vTable = nil
    while moduleName and not isNilAddress(funcAddr) and isAddrInModule(funcAddr, moduleName) do
        local funcClassName = getNameFromAddress(funcAddr, true, true, true)
        if funcClassName and funcClassName ~= "" then
            local nameParts = {}
            for str in string.gmatch(funcClassName, "([^:. ]+)") do
                table.insert(nameParts, str)
            end
            local lastName = string.match(table.remove(nameParts), "[^+]+")
            local tmpTbl = _G
            for _,name in ipairs(nameParts) do
                if not tmpTbl[name] then
                    tmpTbl[name] = {}
                end
                tmpTbl = tmpTbl[name]
            end
            if not tmpTbl[lastName] then
                tmpTbl[lastName] = {}
                setmetatable(tmpTbl[lastName], {__index = function(table, key) return table[1] end})
            end
            table.insert(tmpTbl[lastName], funcAddr)
        end
        if not vTable then
            vTable = {}
            setmetatable(vTable, {__index = function(table, key) return table[1] end})
        end
        table.insert(vTable, funcAddr)
        addr = addr + PointerSize
        funcAddr = readPointer(addr)
    end
    return vTable
end

--- Memory Record Tools ---

MemoryRecordTools = {}

function MemoryRecordTools.Disable(memrec)
synchronize(function(mr)
    local timer = createTimer()
    timer.Interval = 0x1
    timer.OnTimer = function(timer)
        if mr then memoryrecord_unfreeze(mr) end
        timer.destroy()
    end
end, memrec)
end

function MemoryRecordTools.RefreshChildren(memrec)
synchronize(function(mr)
    for i=0,mr.Count-1 do
        local offsets = {}
        local offCount = mr.Child[i].OffsetCount
        for j=0,offCount-1 do
            offsets[j] = offsets, mr.Child[i].Offset[j]
        end
        local mrType = mr.Child[i].Type
        mr.Child[i].Address = mr.Child[i].Address
        mr.Child[i].Type = mrType
        mr.Child[i].OffsetCount = offCount
        for j=0,offCount-1 do
            mr.Child[i].Offset[j] = offsets[j]
        end
    end
end, memrec)
end
function MemoryRecordTools.DeleteChildren(memrec)
synchronize(function(mr)
    local children = MemoryRecordTools.GetChildren(mr, false)
    for i,c in ipairs(children) do
        if c~=nil then pcall(memoryrecord_delete, c) end
    end
end, memrec)
end
function MemoryRecordTools.GetChildren(memrec, recursive)
local result = {}
synchronize(function(mr, r, ret)
    if r == nil then r = false end
    local count = mr.Count
    local children = {}
    for i=0x0,mr.Count-0x1 do
        local child = mr.Child[i]
        if child ~= nil then table.insert(children, child) end
    end
    if r then
        count = #children
        for i=0x1,count do
            local cChildren = MemoryRecordTools.GetChildren(children[i], r)
            for j,cC in ipairs(cChildren) do
                if cC ~= nil then table.insert(children, cC) end
            end
        end
    end
    ret[0] = children
end, memrec, recursive, result)
return result[0]
end

function MemoryRecordTools.HotkeyActionExist(memrec, action)
local result = {}
synchronize(function(mr, a, ret)
    local hkCount = memrec.HotkeyCount
    for i=0x0,hkCount-0x1 do
        if memrec.Hotkey[i].Action == action then ret[0] = true return end
    end
    ret[0] = false
end, memrec, action, result)
return result[0]
end

--- Form Tools ---
function CreateStringInputForm(varName, formName, labelText, numbersOnly, isHex, width, height, func)
    local form = CreateBaseForm(formName, labelText, width, height)
    formVariables[varName] = nil
    local text_box = createEdit(form)
    text_box.setTop(form.Height - 60)
    text_box.Width = form.Width - 20
    text_box.anchorSideLeft.control=form
    text_box.anchorSideLeft.side=asrCenter
    if numbersOnly == true then
        text_box.Text = 0
    end
    local OK_Button = createButton(form)
    OK_Button.setTop(form.Height - 30)
    OK_Button.Width = form.Width - 20
    OK_Button.Caption = 'OK'
    OK_Button.anchorSideLeft.control=form
    OK_Button.anchorSideLeft.side=asrCenter
    local finishFunc = function()
        if numbersOnly == true then
            local num = tonumber(text_box.Text, isHex and 0x10 or 10)
            if num then
                formVariables[varName] = num
            else
                formVariables[varName] = 0
            end
        else formVariables[varName] = text_box.Text end
        if func then func(formVariables[varName], varName) end
        form.close()
    end
    text_box.onKeyDown = function(_, key) if key == 0xD then finishFunc() end end
    OK_Button.onClick = finishFunc
    form.showModal()
end
function CreateDropdownForm(varName, itemArray, formName, labelText, width, height, func)
    local form = CreateBaseForm(formName, labelText, width, height)
    formVariables[varName] = nil
    local slot_box = createComboBox(form)
    slot_box.setTop(form.Height - 30)
    slot_box.Width = form.Width - 20
    slot_box.anchorSideLeft.control=form
    slot_box.anchorSideLeft.side=asrCenter
    for _, item in ipairs(itemArray) do
        slot_box.items.add(item)
    end
    slot_box.onChange = function()
        formVariables[varName] = slot_box.ItemIndex
        if func then func(formVariables[varName], varName, itemArray[hexItemIndex]) end
        form.close()
    end
    form.showModal()
end
function CreateBaseForm(formName, labelText, width, height)
    if not width then width = 180 end
    if not height then height = 80 end
    if not formVariables then formVariables = {} end
    local form = createForm(false)
    m=getmetatable(form)
    m.__autodestroy=true
    local label = createLabel(form)
    form.centerScreen()
    form.Width = width
    form.Height = height
    label.anchorSideLeft.control=form
    label.anchorSideLeft.side=asrCenter
    label.Width = form.Width - 20
    control_setCaption(form, formName)
    control_setCaption(label, labelText)
    return form
end
--- Process Tools ---
ProcessTools = {}
function ProcessTools.GetProcessNameFromID(processId)
  local processName = nil
  local list = createStringlist()
  getProcesslist(list)
  for i = 0, list.Count-1 do
    local id, name = list.String[i]:match("([^-]*).(.*)")
    if processId == tonumber(id, 16) then
      processName = name
      break
    end
  end
  return processName
end
--- Module Tools ---
ModuleTools = {}
function ModuleTools.IsModuleNameInProcess(moduleName, PID)
    if PID == nil then PID = getOpenedProcessID() end
    local moduleList = enumModules(PID)
    local found = false
    for _,m in pairs(moduleList) do
        if moduleName:lower() == m.Name:lower() then
            found = true
            break
        end
    end
    return found
end
function ModuleTools.GetSectionList(moduleAddr)
    local baseAddress = moduleAddr
    address = baseAddress
    local magicBytesInt = readInteger(address)
    address = address + 0x4
    if (magicBytesInt == 0x00905A4D) then
        address = address + 0x38
        address = baseAddress + readInteger(address)
        magicBytesInt = readInteger(address)
        address = address + 0x4
    end
    if (magicBytesInt == 0x00004550) then
        local machineType = readSmallInteger(address)
        address = address + 0x2
        local is64Bit = machineType == 0x8664
        local numberOfSections = readSmallInteger(address)
        address = address + 0x12
        local peFormat = readSmallInteger(address)
        address = address + 0x2
        if (peFormat == 0x10B) then
            address = address + 0x1A
        else
            address = address + 0x16
        end
        local imageBase = readInteger(address)
        if (peFormat == 0x10B) then
            address = address + 0x4
        else
            imageBase = readQword(address)
            address = address + 0x8
        end
        local sectionAlignment = readInteger(address)
        address = address + 0x4
        address = address + 0x18
        local sizeOfHeaders = readInteger(address)
        address = address + 0x4
        if (is64Bit) then
            address = address + 0x2C
        else
            address = address + 0x1C
        end
        local numberOfRvaAndSizes  = readInteger(address)
        address = address + 0x4
        address = address + (numberOfRvaAndSizes * 0x8)
        local sectionTable = {}
        for i=0x1,numberOfSections do
            local name = readString(address, 0x8)
            sectionTable[name] = {}
            address = address + 0x8
            sectionTable[name].virtualSize = readInteger(address)
            address = address + 0x4
            sectionTable[name].virtualAddress = readInteger(address)
            address = address + 0x4
            sectionTable[name].sizeOfRawData  = readInteger(address)
            address = address + 0x4
            sectionTable[name].pointerToRawData = readInteger(address)
            address = address + 0x4
            sectionTable[name].pointerToRelocations = readInteger(address)
            address = address + 0x4
            sectionTable[name].pointerToLinenumbers = readInteger(address)
            address = address + 0x4
            sectionTable[name].numberOfRelocations = readSmallInteger(address)
            address = address + 0x2
            sectionTable[name].numberOfLinenumbers = readSmallInteger(address)
            address = address + 0x2
            sectionTable[name].characteristics  = readInteger(address)
            address = address + 0x4
        end
        return sectionTable
    end
end
function ModuleTools.GetModuleSizeFromSectionList(sectionList)
    local greatOff = 0
    local lastSection = nil
    for name, section in pairs(sectionList) do
        if section.virtualAddress > greatOff then
            greatOff = section.virtualAddress
            lastSection = section
        end
    end
    return lastSection.virtualAddress + lastSection.virtualSize
end
--- AoB Tools ---
AoBTools = {}
AoBTools.AoBPointerType = {}
AoBTools.AoBPointerType.NearAddress = 0x0
AoBTools.AoBPointerType.FarAddress = 0x1
AoBTools.AoBPointerType.CloseJump = 0x2
AoBTools.AoBPointerType.FarJump = 0x3
AoBTools.AoBPointerType.Offset = 0x4
AoBTools.AoBPointerType.Pointer = 0x5
AoBTools.AoBPointerType.Value = AoBTools.AoBPointerType.Offset
AoBTools.GlobalDefaultMemScanner = nil
function AoBTools.ScanAoBTable(aobTable, address, range, memscan)
    local addr = address
    local ms = memscan or AoBTools.GlobalDefaultMemScanner
    for i,tbl in ipairs(aobTable) do
        local r = range
        if tbl[4] then
            r = tbl[4]
        end
        addr = AoBTools.AoBScanRegion(tbl[1], addr, r, nil, nil, nil, ms)
        if isNilAddress(addr) then break end
        if tbl[2] then addr = addr + tbl[2] end
        if tbl[3] then
            addr = AoBTools.ReadAoBPointer(addr, tbl[3][1], tbl[3][2], tbl[3][3])
        end
    end
    return addr
end
function AoBTools.ScanAoBTables(aobTables, address, range)
    for _,aobTable in ipairs(aobTables) do
        local addr = AoBTools.ScanAoBTable(aobTable, address, range)
        if not isNilAddress(addr) then return addr end
    end
    return 0x0
end
function AoBTools.ReadAoBPointer(addr, pType, offSize, signed)
    if not offSize then offSize = 0x1 end
    if not signed then signed = false end
    if pType == AoBTools.AoBPointerType.NearAddress or
    pType == AoBTools.AoBPointerType.FarJump then
        return addr + readIntegerSigned(addr) + 0x4
    elseif pType == AoBTools.AoBPointerType.FarAddress then
        return readPointer(addr)
    elseif pType == AoBTools.AoBPointerType.CloseJump then
        return addr + readByteSigned(addr) + 0x1
    elseif pType == AoBTools.AoBPointerType.Offset then
        if offSize == 0x1 then
            return signed and readByteSigned(addr) or readBytes(addr, offSize, false)
        elseif offSize == 0x2 then
            return signed and readSmallIntegerSigned(addr) or readSmallInteger(addr)
        elseif offSize == 0x4 then
            return signed and readIntegerSigned(addr) or readInteger(addr)
        elseif offSize == 0x8 then
            return signed and readQwordSigned(addr) or readQword(addr)
        elseif offsize == -1 then
            return readPointer(addr)
        else
            return readBytes(addr, offSize, true)
        end
    elseif pType == AoBTools.AoBPointerType.Pointer then
        return readPointer(addr + readIntegerSigned(addr) + 0x4)
    end
end
function AoBTools.AoBScanModule(bytes, moduleName, memscan)
    if not moduleName then moduleName = process end
    local ms = memscan
    return AoBTools.AoBScanRegion(bytes, getAddressSafe(moduleName), getModuleSize(moduleName), nil, nil, nil, ms)
end
function AoBTools.AoBScanRegion(signature, startAddress, endAddress, aobSignaturePrivileges, alignmentType, alignmentParam, memscan)
    if not signature then return 0x0 end
    startAddress = startAddress or 0x0
    endAddress = endAddress or 0x7FFFFFFFFFFFFFFF
    index = index or 1
    local ms = memscan or AoBTools.GlobalDefaultMemScanner
    local tempScan = not ms
    if tempScan then
        ms = createMemScan()
    else
        ms.waitTillDone()
        --- ms.waittillreallydone()
    end
    if type(signature) == 'table' then
        local sig = ''
        for i, byte in ipairs(signature) do
            sig = sig..string.format('%02X', byte)
        end
        signature = sig
    end
    ms.canWriteResults = false
    ms.OnlyOneResult = true
    ms.firstScan(soExactValue, vtByteArray, nil, signature, nil, startAddress, endAddress,
                 aobSignaturePrivileges, alignmentType, alignmentParam, true, true, false, false)
    ms.waitTillDone()
    --- ms.waittillreallydone()
    local result = ms.getOnlyResult() or 0x0
    if tempScan then ms.destroy() end
    return result
end
--- Random Tools ---
RandomTools = {}
RandomTools.RandomTable = {}
math.randomseed(os.clock()*100000000000)
math.random(); math.random(); math.random()
function RandomTools.Random(from, to, t)
    if t == nil then t = RandomTools.RandomTable end
    local num = math.random(from, to)
    if t[num] then num = RandomTools.Random(from, to, t) end
    t[num] = num
    return num
end
--- General Functions ---
function isAddrInModule(addr, moduleName)
    if isNilAddress(addr) then return false end
    local moduleAddr = getAddressSafe(moduleName)
    return not isNilAddress(moduleAddr) and (addr >= moduleAddr and addr < (moduleAddr + getModuleSize(moduleName)))
end
function readPointerTable(addr, offsets)
    local offTbl = offsets
    if type(offTbl) ~= "table" then offTbl = {offsets} end
    local ptr = addr
    for _,off in ipairs(offTbl) do
        if isNilAddress(ptr) then return 0x0 end
        ptr = readPointer(ptr+off)
    end
    return ptr
end
function readQwordSigned(addr)
    local val=readQword(addr)
    return readSignedValue(val, 0x8000000000000000)
end
function readIntegerSigned(addr)
    local val=readInteger(addr)
    return readSignedValue(val, 0x80000000)
end
function readSmallIntegerSigned(addr)
    local val=readSmallInteger(addr)
    return readSignedValue(val, 0x8000)
end
function readByteSigned(addr)
    local val=readBytes(addr, 1, false)
    return readSignedValue(val, 0x80)
end
function readSignedValue(val, valSize)
    local sign=bAnd(val,valSize)
    return sign==0 and val or val-(bShl(valSize, 0x1))
end
function NumberToHexString(num)
    return string.format("%X", num)
end
function isNilPointer(addr)
    return isNilAddress(addr) or isNilAddress(readPointer(addr))
end
function isNilAddress(val)
    return not val or val == 0x0
end

--- Function Highlights ---
registerLuaFunctionHighlight("isAddrInModule")
registerLuaFunctionHighlight("readPointerTable")
registerLuaFunctionHighlight("readQwordSigned")
registerLuaFunctionHighlight("readIntegerSigned")
registerLuaFunctionHighlight("readSmallIntegerSigned")
registerLuaFunctionHighlight("readByteSigned")
registerLuaFunctionHighlight("readSignedValue")
registerLuaFunctionHighlight("isNilPointer")
registerLuaFunctionHighlight("isNilAddress")