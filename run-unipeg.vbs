' Launches the Unipeg / uToken watcher with no console window.
' A plain powershell.exe action dies with 0xC000013A when the task runs
' without a desktop session; a WScript launcher with window style 0 does not.
Dim shell
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = "C:\Users\User\projects\chain-sentry"
shell.Run "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""C:\Users\User\projects\chain-sentry\watch.ps1"" -Config ""C:\Users\User\projects\chain-sentry\config\unipeg.json"" -Quiet", 0, False
