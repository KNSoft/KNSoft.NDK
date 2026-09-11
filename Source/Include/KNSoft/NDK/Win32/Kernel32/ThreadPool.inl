#pragma once

#include "../../NDK.h"
#include "../../NT/NT.inl"

EXTERN_C_START

__inline
_Must_inspect_result_
PTP_TIMER
WINAPI
_Inline_CreateThreadpoolTimer(
    _In_ PTP_TIMER_CALLBACK pfnti,
    _Inout_opt_ PVOID pv,
    _In_opt_ PTP_CALLBACK_ENVIRON pcbe)
{
    NTSTATUS Status;
    PTP_TIMER TpTimer;

    Status = TpAllocTimer(&TpTimer, pfnti, pv, pcbe);
    if (NT_SUCCESS(Status))
    {
        return TpTimer;
    }
    _Inline_RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
    return NULL;
}

__inline
VOID
WINAPI
_Inline_SetThreadpoolTimer(
    _Inout_ PTP_TIMER pti,
    _In_opt_ PFILETIME pftDueTime,
    _In_ DWORD msPeriod,
    _In_opt_ DWORD msWindowLength)
{
    TpSetTimer(pti, (PLARGE_INTEGER)pftDueTime, msPeriod, msWindowLength);
}

__inline
VOID
WINAPI
_Inline_WaitForThreadpoolTimerCallbacks(
    _Inout_ PTP_TIMER pti,
    _In_ BOOL fCancelPendingCallbacks)
{
    TpWaitForTimer(pti, fCancelPendingCallbacks);
}

__inline
VOID
WINAPI
_Inline_CloseThreadpoolTimer(
    _Inout_ PTP_TIMER pti)
{
    TpReleaseTimer(pti);
}

EXTERN_C_END
