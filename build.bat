@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo Building Security Scanner Project
echo ========================================

set SRC_DIR=.\src\main\java
set BUILD_DIR=.\build\classes
set JAVAC_FLAGS=-encoding UTF-8 -Xlint:deprecation

echo Creating build directory...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Check if source directory exists
if not exist "%SRC_DIR%" (
    echo Source directory not found: %SRC_DIR%
    echo Please run this script from the project root directory
    pause
    exit /b 1
)

echo Finding Java source files...
set JAVA_FILE_COUNT=0
set JAVA_FILES=

:: Find all Java files and count them
for /r "%SRC_DIR%" %%f in (*.java) do (
    set /a JAVA_FILE_COUNT+=1
    set JAVA_FILES=!JAVA_FILES! "%%f"
)

if !JAVA_FILE_COUNT! equ 0 (
    echo No Java files found in %SRC_DIR%
    pause
    exit /b 1
)

echo Found !JAVA_FILE_COUNT! Java files

echo Compiling Java files...
javac %JAVAC_FLAGS% -d "%BUILD_DIR%" %JAVA_FILES%

if !errorlevel! equ 0 (
    echo Build successful!
    echo.
    echo Build summary:
    echo   - Build directory: %CD%\%BUILD_DIR%
    
    :: Count compiled classes
    set CLASS_COUNT=0
    for /r "%BUILD_DIR%" %%c in (*.class) do set /a CLASS_COUNT+=1
    echo   - Compiled classes: !CLASS_COUNT!
    
    echo   - Main classes:
    echo       * com.securityscanner.scanner.OpenAPIParserSimple
    echo       * com.securityscanner.scanner.BankingAPIScanner
) else (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build completed successfully!
echo Now you can run: run-scanner.bat [command]

pause