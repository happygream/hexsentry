@echo off
rem hexsentry launcher for Windows.
rem   Double-click: opens the interactive menu.
rem   Drag a log file or folder onto this file: scans it.
rem Works from a clone without installing (uses .\src); an installed hexsentry works too.
setlocal
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
set "PY=python"
where python >nul 2>nul || set "PY=py"
if "%~1"=="" (
  %PY% -m hexsentry --pause menu
) else (
  %PY% -m hexsentry --pause scan %*
)
endlocal
