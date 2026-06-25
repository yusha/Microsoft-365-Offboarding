@echo off
REM ============================================================
REM  Microsoft 365 Offboarding tool launcher
REM  Double-click to run the interactive script.
REM ============================================================

setlocal
set SCRIPT_DIR=%~dp0

REM Windows Terminal renders on the GPU and cannot be screen-captured accurately, so
REM per-step screenshots come out one step behind. If we are running under Windows
REM Terminal, relaunch in the classic console host (a new window opens) where the
REM screenshots capture correctly. No Windows setting change required.
if defined WT_SESSION (
    set "WT_SESSION="
    conhost.exe powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "%SCRIPT_DIR%Invoke-M365Offboarding.ps1" %*
    exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Invoke-M365Offboarding.ps1" %*

if errorlevel 1 (
    echo.
    echo The script reported an error. Press any key to close this window.
    pause > nul
)
