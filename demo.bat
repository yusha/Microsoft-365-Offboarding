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

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Invoke-M365Offboarding.ps1" -DryRun %*

echo.
echo Demo finished. This was a dry run - nothing was changed.
pause > nul
