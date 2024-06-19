#pragma once

#include "../../NT/MinDef.h"

VOID
FORCEINLINE
NTAPI_INLINE
RtlRunOnceInitialize(
    _Out_ PRTL_RUN_ONCE RunOnce)
{
    *RunOnce = RTL_RUN_ONCE_INIT;
}

VOID
FORCEINLINE
NTAPI_INLINE
RtlInitializeSRWLock(
    _Out_ PRTL_SRWLOCK SRWLock)
{
    *SRWLock = RTL_SRWLOCK_INIT;
}
