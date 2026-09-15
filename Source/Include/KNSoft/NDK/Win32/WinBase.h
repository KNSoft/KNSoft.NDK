#pragma once

#include "../NT/MinDef.h"

/* STARTF_HASSHELLDATA was repurposed as STARTF_USEMONITOR in NT6. */
#define STARTF_HASSHELLDATA 0x00000400
#define STARTF_USEMONITOR 0x00000400

typedef
_Function_class_(RUNDLL32_ENTRY_FN)
VOID
CALLBACK
RUNDLL32_ENTRY_FN(
    _In_ HWND hWnd,
    _In_ HINSTANCE hInst,
    _In_ LPSTR lpszCmdLine,
    _In_ int nCmdShow);
