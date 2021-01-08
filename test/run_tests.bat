@echo off
set MYDIR=%~dp0..
set PWD=%MYDIR%
set PYTHONPATH=%MYDIR%
REM shift will not work with %*
set "_args=%*"
IF "%1" == "--2" (
  set PYTHON=python
  set "_args=%_args:~3%"
) ELSE IF "%1" == "--3" (
  set PYTHON=python3
  set "_args=%_args:~3%"
)
IF "%PYTHON%" == "" set PYTHON=python3
WHERE %PYTHON% >nul 2>&1
IF %ERRORLEVEL% NEQ 0 set PYTHON=python
%PYTHON% "%MYDIR%\scapy\tools\UTscapy.py" %_args%