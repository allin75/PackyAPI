@echo off
setlocal
title PackyAPI Key Usage
cd /d "%~dp0"
node packy-usage-server.mjs
if errorlevel 1 pause
