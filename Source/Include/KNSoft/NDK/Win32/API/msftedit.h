#pragma once

#include "../../NT/MinDef.h"

#include <WinBase.h>
#include <tom.h>

EXTERN_C_START

WINBASEAPI
VOID
WINAPI
DisableOleinitCheck(VOID);

// https://learn.microsoft.com/zh-cn/previous-versions/windows/desktop/legacy/hh780443(v=vs.85)
WINBASEAPI
HRESULT
WINAPI
MathBuildDown(
    _Inout_ ITextRange2* prg,
    _In_ ITextStrings* pstrs,
    _In_ LONG Flags);

// https://learn.microsoft.com/zh-cn/previous-versions/windows/desktop/legacy/hh780445(v=vs.85)
WINBASEAPI
HRESULT
WINAPI
MathBuildUp(
    _Inout_ ITextRange2* prg,
    _In_ ITextStrings* pstrs,
    _In_ LONG Flags);

// https://learn.microsoft.com/zh-cn/previous-versions/windows/desktop/legacy/hh780446(v=vs.85)
WINBASEAPI
HRESULT
WINAPI
MathTranslate(
    _Inout_ ITextRange2* prg,
    _In_ LONG Flags);

// https://learn.microsoft.com/zh-cn/previous-versions/windows/desktop/legacy/hh780353(v=vs.85)
WINBASEAPI
LONG
WINAPI
GetMathAlphanumeric(
    _In_ LONG ch,
    _In_ DWORD MathStyle);

// https://learn.microsoft.com/zh-cn/previous-versions/windows/desktop/legacy/hh780354(v=vs.85)
WINBASEAPI
MANCODE
WINAPI
GetMathAlphanumericCode(
    _In_ DWORD chTrail,
    _Out_ WCHAR* pch);

EXTERN_C_END
