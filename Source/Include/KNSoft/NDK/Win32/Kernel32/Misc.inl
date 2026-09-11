#pragma once

#include "../../NDK.h"
#include "../../NT/NT.inl"

EXTERN_C_START

__inline
LCID
WINAPI
_Inline_GetThreadLocale(void)
{
    return NtReadTeb(CurrentLocale);
}

__inline
BOOL
WINAPI
_Inline_IsProcessorFeaturePresent(
    _In_ DWORD ProcessorFeature)
{
    return _Inline_RtlIsProcessorFeaturePresent(ProcessorFeature);
}

EXTERN_C_END
