@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   Building Android Bytecode Obfuscator
echo ========================================
echo.

set TOOL_DIR=%~dp0
set SRC_DIR=%TOOL_DIR%src
set LIB_DIR=%TOOL_DIR%libs
set BUILD_DIR=%TOOL_DIR%build
set OUT_JAR=%TOOL_DIR%android-obfuscator.jar
set FAT_DIR=%TOOL_DIR%build\fatjar

if defined JAVA_HOME (
    set JAR_EXE=%JAVA_HOME%\bin\jar.exe
) else (
    set JAR_EXE=jar
)

echo [1/4] Collecting Java sources...

if exist "%BUILD_DIR%" rd /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
mkdir "%FAT_DIR%"

set JAVA_FILES=
for /r "%SRC_DIR%" %%f in (*.java) do (
    set "JAVA_FILES=!JAVA_FILES! %%f"
)

echo [2/4] Compiling...
javac -encoding UTF-8 -source 8 -target 8 -cp "%LIB_DIR%\*" -d "%BUILD_DIR%\obfuscator" !JAVA_FILES!

if %ERRORLEVEL% neq 0 (
    echo Compilation failed.
    pause
    exit /b 1
)
echo Compilation successful.
echo.

echo [3/4] Building fat JAR (embedding ASM libraries)...

cd /d "%FAT_DIR%"
for %%f in ("%LIB_DIR%\*.jar") do (
    "%JAR_EXE%" xf "%%f"
)

xcopy /s /y "%BUILD_DIR%\obfuscator\*" "%FAT_DIR%\" >nul

echo Main-Class: obfuscator.Main> "%BUILD_DIR%\manifest.txt"

cd /d "%FAT_DIR%"
"%JAR_EXE%" cfm "%OUT_JAR%" "%BUILD_DIR%\manifest.txt" .

echo.
echo ========================================
echo   Build Complete
echo ========================================
echo Output: %OUT_JAR%
echo.
pause
