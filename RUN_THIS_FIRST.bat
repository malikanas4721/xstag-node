@echo off
title XStag Pro - Install Dependencies
color 0A
echo.
echo ================================================
echo   XStag Pro - Dependency Installation
echo ================================================
echo.
echo Checking for Node.js...
where node >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Node.js is not installed or not in PATH!
    echo.
    echo Please install Node.js from: https://nodejs.org/
    echo Then run this script again.
    echo.
    pause
    exit /b 1
)

echo Node.js found!
echo.
echo Checking for dependencies...
if exist "node_modules\dotenv" (
    echo Dependencies already installed!
    echo.
    echo Starting server...
    call npm start
) else (
    echo Dependencies not found. Installing now...
    echo This may take 2-3 minutes...
    echo.
    call npm install
    if errorlevel 1 (
        echo.
        echo ================================================
        echo   INSTALLATION FAILED
        echo ================================================
        echo.
        echo Possible solutions:
        echo 1. Make sure you have internet connection
        echo 2. Try running: npm install --verbose
        echo 3. Check if Node.js is properly installed
        echo.
        pause
        exit /b 1
    )
    echo.
    echo ================================================
    echo   INSTALLATION SUCCESSFUL!
    echo ================================================
    echo.
    echo Starting server...
    call npm start
)

pause

