@echo off
REM Usage: build.bat [Debug|Release] [x64|ARM64] [target]
set BUILD_TYPE=%1
if "%BUILD_TYPE%"=="" set BUILD_TYPE=Debug

set ARCH=%2
if "%ARCH%"=="" set ARCH=x64

set TARGET=%3

REM Set build directory based on architecture
if /I "%ARCH%"=="x64" (
  set BUILD_DIR=build_x64
) else if /I "%ARCH%"=="ARM64" (
  set BUILD_DIR=build_arm64
) else (
  echo Error: Architecture must be x64 or ARM64
  exit /b 1
)

set "ROOT_DIR=%CD%"
if exist sniffer_packages (
    cd sniffer_packages
)

REM Create and enter build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
cd %BUILD_DIR%

REM Generate build system (adjust generator/version as needed)
cmake .. -G "Visual Studio 17 2022" -A %ARCH% -DCMAKE_BUILD_TYPE=%BUILD_TYPE%

REM Build solution (optionally target)
if "%TARGET%"=="" (
  cmake --build . --config %BUILD_TYPE%
) else (
  cmake --build . --config %BUILD_TYPE% --target %TARGET%
)
echo Build complete (%BUILD_TYPE% %ARCH%)
echo Libraries (if any) in: %cd%\%BUILD_TYPE%

cd "%ROOT_DIR%"
