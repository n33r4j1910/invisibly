Set WshShell = CreateObject("WScript.Shell")

' Launch daemon with admin via separate script
WshShell.Run "wscript C:\Invisibly\launch_admin.vbs", 0, False

' Wait 5 seconds for daemon to initialize
WScript.Sleep 5000

' Start tray silently
WshShell.Run "C:\Invisibly\target\release\invisibly-tray.exe", 0, False

' Wait 2 seconds for tray to connect
WScript.Sleep 2000

' Show notification using PowerShell (not msg)
Dim cmd
cmd = "powershell -Command ""& {" & _
      "$wshell = New-Object -ComObject Wscript.Shell; " & _
      "$wshell.Popup('Invisibly is now protecting your PC', 5, 'Invisibly', 64)" & _
      "}"""
WshShell.Run cmd, 0, False