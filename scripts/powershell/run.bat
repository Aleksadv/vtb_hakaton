@echo off
chcp 65001 >nul

echo Starting Security Scanner...
echo ================================

set BUILD_DIR=..\build\classes
set CONFIG_FILE=scanner-config.properties
set PARSER_CLASS=com.securityscanner.scanner.OpenAPIParserSimple
set SCANNER_CLASS=com.securityscanner.scanner.BankingAPIScanner

:: Check if build exists
if not exist "%BUILD_DIR%" (
    echo Build directory not found: %BUILD_DIR%
    echo Please run build.bat first
    pause
    exit /b 1
)

:: Check if main classes exist
if not exist "%BUILD_DIR%\com\securityscanner\scanner\OpenAPIParserSimple.class" (
    echo Compiled classes not found
    echo Please run build.bat first
    pause
    exit /b 1
)

:: Check if config file exists, create default if not
if not exist "%CONFIG_FILE%" (
    echo Creating default configuration file...
    (
        echo # Security Scanner Configuration
        echo # Generated on: %date% %time%
        echo.
        echo # API Settings
        echo api.base_url=https://vbank.open.bankingapi.ru
        echo api.timeout=5000
        echo.
        echo # Scanner Settings
        echo scanner.test_endpoints=true
        echo scanner.check_security=true
        echo scanner.verbose_output=true
        echo.
        echo # Output Settings
        echo output.directory=.
        echo output.format=json
        echo.
        echo # Parser Settings
        echo parser.auto_save=true
        echo parser.analyze_security=true
    ) > "%CONFIG_FILE%"
    echo Created default config: %CONFIG_FILE%
)

echo Using config: %CONFIG_FILE%
echo.

:: Run OpenAPI Parser first
echo Step 1: Running OpenAPI Parser...
java -cp "%BUILD_DIR%" "%PARSER_CLASS%"

if not errorlevel 0 (
    echo Parser finished with warnings, continuing...
)

echo.

:: Run Security Scanner
echo Step 2: Running Security Scanner...
java -cp "%BUILD_DIR%" "%SCANNER_CLASS%"

echo.
echo Security scan completed!
echo Check generated files in current directory

pause