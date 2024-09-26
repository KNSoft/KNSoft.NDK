#pragma once

#include <WinUser.h>

#ifndef WM_COPYGLOBALDATA
#define WM_COPYGLOBALDATA 0x49
#endif

typedef struct _DLGTEMPLATEEX
{
    WORD        dlgVer;
    WORD        signature;
    DWORD       helpID;
    DLGTEMPLATE dlgTemplate;
} DLGTEMPLATEEX, *PDLGTEMPLATEEX;

DECLSPEC_ALIGN(4) typedef struct _DLGITEMTEMPLATEEX
{
    DWORD           helpID;
    DLGITEMTEMPLATE itemTemplate;
} DLGITEMTEMPLATEEX, *PDLGITEMTEMPLATEEX;
