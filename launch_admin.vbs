Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell -Command ""Start-Process 'C:\Invisibly\target\release\invisibly-daemon.exe' -Verb RunAs""", 1, True