@echo off
rem following makes it possible to have both a development and production invocation.
rem ITM6_DEVELOP_TOOLS_PATH=  Path to development modules
rem ITM6_TOOLS_DEBUG= When developping set this to -d for interactice debug run
rem ITM6_DEBUG_TOOLS_PATH= Path to Production production modules
set TOOLS_PATH=
set TOOLS_DPATH=
set TOOLS_DEBUG=
if defined ITM6_DEBUG_TOOLS_PATH ( set TOOLS_PATH=%ITM6_DEBUG_TOOLS_PATH%)
if defined ITM6_DEVELOP_TOOLS_PATH ( set TOOLS_DPATH=%ITM6_DEVELOP_TOOLS_PATH%)
if defined ITM6_TOOLS_DEBUG ( set TOOLS_DEBUG=%ITM6_TOOLS_DEBUG%)
rem echo %ITM6_DEBUG_TOOLS_PATH%
rem echo %TOOLS_PATH%
rem echo  %ITM6_DEVELOP_TOOLS_PATH%
rem echo %TOOLS_DEBUG%
set cmds=
if exist %TOOLS_DPATH%\temsaud.pl (
set cmds=perl %TOOLS_DEBUG% %TOOLS_DPATH%\dup2do.pl %*
) else (
set cmds=perl %TOOLS_PATH%\support\itm\bin\dup2do.pl %*
)
echo %cmds%
%cmds%
