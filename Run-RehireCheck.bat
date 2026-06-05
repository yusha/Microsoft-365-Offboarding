@echo off
REM ============================================================
REM  Microsoft 365 Rehire / prior-offboarding check (read-only)
REM ============================================================

setlocal
set SCRIPT_DIR=%~dp0

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Test-M365Rehire.ps1" %*

if errorlevel 1 (
    echo.
    echo The script reported an error. Press any key to close this window.
    pause > nul
)
