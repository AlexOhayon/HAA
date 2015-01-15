// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#include <stdio.h>
#include <tchar.h>

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <mshtml.h>
#include <atlbase.h>
#include <oleacc.h>
#include <atlstr.h>


#include <WinHTTP.h>
#pragma comment(lib, "winhttp")

#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif
// TODO: reference additional headers your program requires here
