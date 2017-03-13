@echo off
title Build scapy docs
set /P CLEAR=Clear build ? (y/n) [y] 
If /I "%CLEAR%"=="y" goto yes 
If /I "%CLEAR%"=="" goto yes 
If /I "%CLEAR%"=="n" goto no

echo Unknown answer !
PAUSE
exit

:yes
del /F /Q /S _build >nul 2>&1
echo Build cleared !
:no
mkdir _build >nul 2>&1
cd _build
mkdir html doctrees pickle >nul 2>&1
cd ..
sphinx-build -b pickle -d _build/doctrees . _build/pickle
sphinx-build -b html -d _build/doctrees . _build/html
PAUSE
