@echo off
rem netmon launcher: the menu itself is shown by PowerShell (netmon.ps1 -Mode Menu).
rem Keep this file next to netmon.ps1. For the desktop, create a shortcut to it (do not copy it).
title netmon

if not exist "%~dp0netmon.ps1" (
    echo netmon.ps1 not found next to this .bat: %~dp0
    echo Put a shortcut to netmon.bat on the desktop instead of a copy.
    pause
    exit /b 1
)

where pwsh >nul 2>nul
if errorlevel 1 (
    echo PowerShell 7 ^(pwsh^) not found. Install it: winget install Microsoft.PowerShell
    pause
    exit /b 1
)

pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0netmon.ps1" -Mode Menu
echo.
pause