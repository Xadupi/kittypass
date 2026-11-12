@echo off
rem Lance install.ps1 en administrateur.
net session >nul 2>&1 || (powershell -Command "Start-Process -Verb RunAs -FilePath \"%~f0\"" & exit /b)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
pause
