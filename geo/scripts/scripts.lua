{$lua}
[ENABLE]
if GeneralTools.WaitForCondition(function()
    return (core ~= nil and
            core.game ~= nil and
            core.static ~= nil and
            core.script ~= nil)
        end, 60, 3000) then
    return
else
    error("Wait condition failed.")
end
[DISABLE]
{$asm}