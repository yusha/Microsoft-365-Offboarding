@echo off
REM ============================================================
REM  Microsoft 365 Offboarding - DEMO (dry run)
REM
REM  Double-click to walk through all ten steps safely.
REM  This runs in dry-run / training mode: no sign-in, no
REM  modules, no tenant access, and no changes are made.
REM  A sample audit packet is written to a temp folder.
REM ============================================================

setlocal
set SCRIPT_DIR=%~dp0

REM Under Windows Terminal, relaunch in the classic console host (a new window
REM opens) so per-step screenshots capture correctly. No Windows setting change
REM required. Skipped when already running in the console host.
if defined WT_SESSION (
    set "WT_SESSION="
    conhost.exe powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "%SCRIPT_DIR%Invoke-M365Offboarding.ps1" -DryRun %*
    exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Invoke-M365Offboarding.ps1" -DryRun %*

echo.
echo Demo finished. This was a dry run - nothing was changed.
pause > nul
