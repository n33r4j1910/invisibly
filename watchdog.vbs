Set WshShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")

Sub ShowNotification(message, duration)
    Dim cmd
    cmd = "powershell -Command ""& {" & _
          "$wshell = New-Object -ComObject Wscript.Shell; " & _
          "$wshell.Popup('" & message & "', " & duration & ", 'Invisibly', 64)" & _
          "}"""
    WshShell.Run cmd, 0, False
End Sub

Do While True
    Dim strQuery, colItems
    strQuery = "SELECT * FROM Win32_Process WHERE Name = 'invisibly-daemon.exe'"
    Set colItems = objWMIService.ExecQuery(strQuery)
    
    If colItems.Count = 0 Then
        ' Restart daemon with Admin privileges
        WshShell.Run "powershell -Command ""Start-Process 'C:\Invisibly\target\release\invisibly-daemon.exe' -Verb RunAs""", 0, False
        WScript.Sleep 5000
        
        ' Restart tray
        Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'invisibly-tray.exe'")
        If colItems.Count = 0 Then
            WshShell.Run "powershell -Command ""Start-Process 'C:\Invisibly\target\release\invisibly-tray.exe' -Verb RunAs""", 0, False
        End If
        
        ShowNotification "Invisibly has been automatically restarted", 5
    End If
    
    WScript.Sleep 10000
Loop