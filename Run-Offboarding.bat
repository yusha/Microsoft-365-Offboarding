@echo off
REM ============================================================
REM  Microsoft 365 Offboarding tool launcher
REM  Double-click to run the interactive script.
REM ============================================================

setlocal
set SCRIPT_DIR=%~dp0

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Invoke-M365Offboarding.ps1" %*

if errorlevel 1 (
    echo.
    echo The script reported an error. Press any key to close this window.
    pause > nul
)
