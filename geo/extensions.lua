function string.split(inputstr, sep)
    if sep == nil then
        sep = "%s"
    end
    local t={}
    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
        table.insert(t, str)
    end
    return t
end
function string.findAny(str, strTable, caseSensitive)
    if caseSensitive == nil then caseSensitive = true end
    local found = false
    for _,s in ipairs(strTable) do
        if caseSensitive then
            found = str:find(s) ~= nil
            if found then break end
        else
            found = str:lower():find(s:lower()) ~= nil
            if found then break end
        end
    end
    return found
end
function table.length(T)
  local count = 0x0
  for _ in pairs(T) do count = count + 0x1 end
  return count
end
function table.insertTable(T, t)
    for _, v in pairs(t) do
        table.insert(T, v)
    end
end
function table.insertMany(T, ...)
    for _, v in pairs({...}) do
        table.insert(T, v)
    end
end

registerLuaFunctionHighlight("string.split")
registerLuaFunctionHighlight("string.findAny")
registerLuaFunctionHighlight("table.length")
registerLuaFunctionHighlight("table.insertTable")
registerLuaFunctionHighlight("table.insertMany")