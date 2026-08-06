' Invisibly - Automatic Windows Update Handler
' Fetches token dynamically from daemon

Set WshShell = CreateObject("WScript.Shell")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")

Do While True
    ' Check if Windows Update is running
    Dim strQuery, colItems
    strQuery = "SELECT * FROM Win32_Process WHERE Name = 'TrustedInstaller.exe'"
    Set colItems = objWMIService.ExecQuery(strQuery)

    If colItems.Count > 0 Then
        ' Update is running
        WScript.Sleep 60000 ' Wait 1 minute

        ' Wait until TrustedInstaller is done
        Do While True
            Dim colTI
            strQuery = "SELECT * FROM Win32_Process WHERE Name = 'TrustedInstaller.exe'"
            Set colTI = objWMIService.ExecQuery(strQuery)
            If colTI.Count = 0 Then Exit Do
            WScript.Sleep 30000 ' Check every 30 seconds
        Loop

        ' Update finished → Reset baseline
        WScript.Sleep 10000 ' Wait 10 seconds

        ' Fetch token dynamically from daemon
        Dim http, token
        Set http = CreateObject("MSXML2.XMLHTTP")
        http.open "GET", "http://127.0.0.1:12790/token", False
        http.send
        token = http.responseText

        ' Extract token from JSON
        token = Mid(token, InStr(token, """token"":""") + 10)
        token = Left(token, InStr(token, """") - 1)

        ' Reset baseline using the fetched token
        Dim cmd
        cmd = "curl -X POST http://127.0.0.1:12790/reset -H ""Authorization: Bearer " & token & """"
        WshShell.Run cmd, 0, True

        ' Log
        On Error Resume Next
        Set fso = CreateObject("Scripting.FileSystemObject")
        Set logFile = fso.OpenTextFile("C:\ProgramData\Invisibly\auto_update.log", 8, True)
        logFile.WriteLine Now & " - ✅ Baseline reset after Windows Update"
        logFile.Close
        On Error GoTo 0

        WScript.Sleep 300000 ' Wait 5 minutes before checking again
    End If

    WScript.Sleep 60000 ' Check every 1 minute
Loop