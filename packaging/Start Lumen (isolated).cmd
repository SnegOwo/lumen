@echo off
rem Lumen - isolated mode.
rem Every file Lumen writes goes into the "data" folder next to this script, so you can
rem delete that one folder to remove every trace. Real-time protection is switched off,
rem so it never watches a real Desktop, Documents or Downloads.

setlocal
cd /d "%~dp0"
set "LUMEN_DATA_DIR=%~dp0data"
set "LUMEN_DISABLE_REALTIME=1"
start "" "%~dp0Lumen.exe"
