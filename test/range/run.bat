@echo off
call build.bat
if errorlevel 1 goto end

echo.
echo Running task_dispatcher...
build\task_dispatcher.exe

:end
