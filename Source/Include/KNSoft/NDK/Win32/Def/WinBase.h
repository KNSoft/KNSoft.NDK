#pragma once

#include "../../NT/MinDef.h"

/* Before NT6, 0x400 has other meanings */
#if NT_VERSION_MIN < NT_VERSION_VISTA
#define STARTF_RESERVED 0x00000400
#else
#define STARTF_USEMONITOR 0x00000400
#endif

typedef
_Function_class_(RUNDLL32_ENTRY_FN)
VOID
CALLBACK
RUNDLL32_ENTRY_FN(
    _In_ HWND hWnd,
    _In_ HINSTANCE hInst,
    _In_ LPSTR lpszCmdLine,
    _In_ int nCmdShow);
