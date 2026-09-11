#pragma once

#include "../../NDK.h"
#include "../../NT/NT.inl"

EXTERN_C_START

__inline
DWORD64
WINAPI
_Inline_GetEnabledXStateFeatures(VOID)
{
    ULONG64 u = _Inline_RtlGetEnabledExtendedFeatures(MAXULONGLONG);
    if (u)
    {
        return u;
    }

    /*
     * Geoff Chappell:
     * The PF_XMMI_INSTRUCTIONS_AVAILABLE feature is necessarily TRUE in x86 version 6.2 and higher,
     * and in all x64 versions.
     */
#if defined(_WIN64)
    return XSTATE_MASK_LEGACY;
#else
    return SharedUserData->ProcessorFeatures[PF_XMMI_INSTRUCTIONS_AVAILABLE] ?
        XSTATE_MASK_LEGACY :
        XSTATE_MASK_LEGACY_FLOATING_POINT;
#endif
}

/* TEB.ExtendedFeatureDisableMask is available since Server 2022 / Windows 11. */
#if (NT_VERSION_MIN >= NT_VERSION_WS2K22)
__inline
DWORD64
WINAPI
_Inline_GetThreadEnabledXStateFeatures(VOID)
{
    return _Inline_GetEnabledXStateFeatures() &
#if defined(_WIN64)
        NtReadTeb(ExtendedFeatureDisableMask)
#else
        ~XSTATE_MASK_AMX_TILE_DATA
#endif
        ;
}
#endif

EXTERN_C_END
