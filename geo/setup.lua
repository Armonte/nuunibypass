{$lua}
if syntaxcheck then return end
[ENABLE]
GeneralTools.WaitCanceled = false core.setup = {} core.WatcherThreads = {}
--AoBTools.GlobalDefaultMemScanner = createMemScan()
[DISABLE]
ThreadTableTerminator(core.WatcherThreads) GeneralTools.WaitCanceled = true
--AoBTools.GlobalDefaultMemScanner.destroy()
--AoBTools.GlobalDefaultMemScanner = nil
{$asm}