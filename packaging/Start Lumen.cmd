@echo off
rem Lumen - normal mode.
rem Settings, history, the quarantine vault and the logs go to
rem   %LOCALAPPDATA%\Lumen
rem Real-time protection watches Desktop, Documents and Downloads.

setlocal
cd /d "%~dp0"
start "" "%~dp0Lumen.exe"
