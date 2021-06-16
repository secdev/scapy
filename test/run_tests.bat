@echo off
set MYDIR=%~dp0..
set PWD=%MYDIR%
set PYTHONPATH=%MYDIR%
REM Note: shift will not work with %*
REM ### Get args, Handle Python version ###
set "_args=%*"
IF "%1" == "-2" (
  set PYTHON=python
  set "_args=%_args:~3%"
) ELSE IF "%1" == "-3" (
  set PYTHON=python3
  set "_args=%_args:~3%"
)
IF "%PYTHON%" == "" set PYTHON=python3
WHERE %PYTHON% >nul 2>&1
IF %ERRORLEVEL% NEQ 0 set PYTHON=python
REM Reset Error level
VERIFY > nul
echo ##### Starting Unit tests #####
REM ### Check no-argument mode ###
IF "%_args%" == "" (
  REM Check for tox
  %PYTHON% -m tox --version >nul 2>&1
  IF %ERRORLEVEL% NEQ 0 (
    echo Tox not installed !
    pause
    exit 1
  )
  REM Run tox
  %PYTHON% -m tox -- -K tcpdump -K manufdb -K wireshark -K ci_only
  pause
  exit 0
)
REM ### Start UTScapy normally ###
%PYTHON% "%MYDIR%\scapy\tools\UTscapy.py" %_args%
PAUSE
