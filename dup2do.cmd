set TOOLS_PATH=
if defined ITM6_DEBUG_TOOLS_PATH ( set TOOLS_PATH=%ITM6_DEBUG_TOOLS_PATH%)
perl %TOOLS_PATH%\support\itm\bin\dup2do.pl %*
