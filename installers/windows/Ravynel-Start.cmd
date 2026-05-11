@echo off
setlocal EnableExtensions

title Ravynel Security Launcher

set "SCRIPT_DIR=%~dp0"
set "GUI=%SCRIPT_DIR%Ravynel-Launch.pyw"

if exist "%GUI%" (
  where pythonw.exe >nul 2>nul
  if %ERRORLEVEL% EQU 0 (
    start "" pythonw.exe "%GUI%"
    exit /b 0
  )
  where pyw.exe >nul 2>nul
  if %ERRORLEVEL% EQU 0 (
    start "" pyw.exe "%GUI%"
    exit /b 0
  )
  where python.exe >nul 2>nul
  if %ERRORLEVEL% EQU 0 (
    start "" python.exe "%GUI%"
    exit /b 0
  )
)

echo Ravynel GUI launcher could not be started.
echo Install Python 3.12+ or run installers\windows\Ravynel-Launch.pyw directly.
pause
exit /b 1