Set WshShell = CreateObject("WScript.Shell")

' Start daemon silently
WshShell.Run "C:\Invisibly\target\release\invisibly-daemon.exe", 0, False

' Wait 3 seconds for daemon to initialize
WScript.Sleep 3000

' Start tray silently
WshShell.Run "C:\Invisibly\target\release\invisibly-tray.exe", 0, False

' Wait 2 seconds for tray to connect
WScript.Sleep 2000

' Show notification using MsgBox (simple and reliable)
' This creates a small popup that auto-closes after 3 seconds
Dim cmd
cmd = "powershell -Command ""& {" & _
      "$wshell = New-Object -ComObject Wscript.Shell; " & _
      "$wshell.Popup('🔒 Invisibly is now protecting your PC', 3, 'Invisibly', 64)" & _
      "}"""
WshShell.Run cmd, 0, False