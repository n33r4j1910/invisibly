Set WshShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")

Do While True
    ' Check if daemon is running
    Dim strQuery, colItems
    strQuery = "SELECT * FROM Win32_Process WHERE Name = 'invisibly-daemon.exe'"
    Set colItems = objWMIService.ExecQuery(strQuery)
    
    If colItems.Count = 0 Then
        ' Daemon is not running — restart it
        WshShell.Run "C:\Invisibly\target\release\invisibly-daemon.exe", 0, False
        WScript.Sleep 5000
        
        ' Also restart tray
        Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = 'invisibly-tray.exe'")
        If colItems.Count = 0 Then
            WshShell.Run "C:\Invisibly\target\release\invisibly-tray.exe", 0, False
        End If
    End If
    
    ' Wait 10 seconds before checking again
    WScript.Sleep 10000
Loop