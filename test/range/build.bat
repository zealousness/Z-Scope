@echo off
REM Build script for Windows (MinGW/GCC)

set CC=gcc
set CFLAGS=-Wall -Wextra -O2 -g -std=c11 -D_GNU_SOURCE -DPLATFORM_WINDOWS
set LDFLAGS=-lpthread
set INCLUDE_DIR=include
set INTERNAL_DIR=internal
set SRC_DIR=src
set BUILD_DIR=build

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo Compiling utils.c...
%CC% %CFLAGS% -I%INCLUDE_DIR% -I%INTERNAL_DIR% -c %SRC_DIR%/utils.c -o %BUILD_DIR%/utils.o
if errorlevel 1 goto error

echo Compiling network.c...
%CC% %CFLAGS% -I%INCLUDE_DIR% -I%INTERNAL_DIR% -c %SRC_DIR%/network.c -o %BUILD_DIR%/network.o
if errorlevel 1 goto error

echo Compiling parser.c...
%CC% %CFLAGS% -I%INCLUDE_DIR% -I%INTERNAL_DIR% -c %SRC_DIR%/parser.c -o %BUILD_DIR%/parser.o
if errorlevel 1 goto error

echo Compiling plugin.c...
%CC% %CFLAGS% -I%INCLUDE_DIR% -I%INTERNAL_DIR% -c %SRC_DIR%/plugin.c -o %BUILD_DIR%/plugin.o
if errorlevel 1 goto error

echo Compiling executor.c...
%CC% %CFLAGS% -I%INCLUDE_DIR% -I%INTERNAL_DIR% -c %SRC_DIR%/executor.c -o %BUILD_DIR%/executor.o
if errorlevel 1 goto error

echo Compiling lifecycle.c...
%CC% %CFLAGS% -I%INCLUDE_DIR% -I%INTERNAL_DIR% -c %SRC_DIR%/lifecycle.c -o %BUILD_DIR%/lifecycle.o
if errorlevel 1 goto error

echo Compiling main.c...
%CC% %CFLAGS% -I%INCLUDE_DIR% -I%INTERNAL_DIR% -c %SRC_DIR%/main.c -o %BUILD_DIR%/main.o
if errorlevel 1 goto error

echo Linking...
%CC% %CFLAGS% -o %BUILD_DIR%/task_dispatcher.exe %BUILD_DIR%/utils.o %BUILD_DIR%/network.o %BUILD_DIR%/parser.o %BUILD_DIR%/plugin.o %BUILD_DIR%/executor.o %BUILD_DIR%/lifecycle.o %BUILD_DIR%/main.o %LDFLAGS%
if errorlevel 1 goto error

echo.
echo Build successful! Output: %BUILD_DIR%/task_dispatcher.exe
goto end

:error
echo.
echo Build failed!
exit /b 1

:end
