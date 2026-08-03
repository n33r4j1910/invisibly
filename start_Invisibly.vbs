Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "C:\Invisibly\target\release\invisibly-daemon.exe", 0, False
WScript.Sleep 2000
WshShell.Run "C:\Invisibly\target\release\invisibly-tray.exe", 0, False