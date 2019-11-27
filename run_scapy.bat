@echo off
set PYTHONPATH=%~dp0
IF "%PYTHON%" == "" set PYTHON=python3
WHERE %PYTHON% >nul 2>&1
IF %ERRORLEVEL% NEQ 0 set PYTHON=python
%PYTHON% -m scapy %*
title Scapy - dead
PAUSE