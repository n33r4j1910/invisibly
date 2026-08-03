Set WshShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")

Do While True
    Dim strQuery, colItems
    strQuery = "SELECT * FROM Win32_Process WHERE Name = 'invisibly-daemon.exe'"
    Set colItems = objWMIService.ExecQuery(strQuery)
    
    If colItems.Count = 0 Then
        WshShell.Run "C:\Invisibly\target\release\invisibly-daemon.exe", 0, False
        WScript.Sleep 5000
        Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'invisibly-tray.exe'")
        If colItems.Count = 0 Then
            WshShell.Run "C:\Invisibly\target\release\invisibly-tray.exe", 0, False
        End If
    End If
    
    WScript.Sleep 10000
Loop