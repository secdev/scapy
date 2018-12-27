@echo off
set PYTHONPATH=%~dp0
set PYTHONDONTWRITEBYTECODE=True
if "%1"=="--nopause" (
  set nopause="True"
  python2 -m scapy
) else (
  set nopause="False"
  python2 -m scapy %*
)
if %errorlevel%==1 if NOT "%nopause%"=="True" (
   PAUSE
)
