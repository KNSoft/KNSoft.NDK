#pragma once

#include "../../NDK.h"
#include "Kernel32.inl"

EXTERN_C_START

DECLSPEC_SELECTANY DECLSPEC_POINTERALIGN volatile PTP_TIMER _Inline_MSIdle_g_pIdleTimer = NULL;
DECLSPEC_SELECTANY DECLSPEC_POINTERALIGN volatile _IDLECALLBACK _Inline_MSIdle_g_pfnCallback = NULL;
DECLSPEC_SELECTANY BOOL _Inline_MSIdle_g_fIdleNotify;
DECLSPEC_SELECTANY BOOL _Inline_MSIdle_g_fBusyNotify;
DECLSPEC_SELECTANY DWORD _Inline_MSIdle_g_dwIdleBeginTicks;
DECLSPEC_SELECTANY DWORD _Inline_MSIdle_g_dwIdleMin;

static
VOID
SetIdleTimer(VOID)
{
    ULONG ulPeriod;

    ulPeriod = _Inline_MSIdle_g_fBusyNotify ? 4000UL : 6000UL;
    if (_Inline_MSIdle_g_pIdleTimer != NULL)
    {
        LARGE_INTEGER liDueTime;
        liDueTime.QuadPart = -10000LL * ulPeriod;
        _Inline_SetThreadpoolTimer(_Inline_MSIdle_g_pIdleTimer, (PFILETIME)&liDueTime, ulPeriod, ulPeriod);
    }
}

static
VOID
NTAPI
OnIdleTimer(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID Context,
    _Inout_ PTP_TIMER Timer)
{
    DWORD dwIdleBeginTicks = SharedUserData->LastSystemRITEventTickCount;

    if (_Inline_MSIdle_g_fBusyNotify &&
        SharedUserData->LastSystemRITEventTickCount != _Inline_MSIdle_g_dwIdleBeginTicks)
    {
        _Inline_MSIdle_g_fBusyNotify = FALSE;
        _Inline_MSIdle_g_fIdleNotify = TRUE;
        SetIdleTimer();
        if (_Inline_MSIdle_g_pfnCallback != NULL)
        {
            _Inline_MSIdle_g_pfnCallback(STATE_USER_IDLE_END);
        }
    }
    if (_Inline_MSIdle_g_fIdleNotify &&
        _Inline_GetTickCount() - dwIdleBeginTicks > 60000 * _Inline_MSIdle_g_dwIdleMin)
    {
        _Inline_MSIdle_g_fIdleNotify = FALSE;
        _Inline_MSIdle_g_fBusyNotify = TRUE;
        _Inline_MSIdle_g_dwIdleBeginTicks = dwIdleBeginTicks;
        SetIdleTimer();
        if (_Inline_MSIdle_g_pfnCallback != NULL)
        {
            _Inline_MSIdle_g_pfnCallback(STATE_USER_IDLE_BEGIN);
        }
    }
}

__inline
DWORD
WINAPI
_Inline_BeginIdleDetection(
    _IDLECALLBACK pfnCallback,
    DWORD dwIdleMin,
    DWORD dwReserved)
{
    if (dwReserved != 0)
    {
        return ERROR_INVALID_DATA;
    }
    if (_Inline_MSIdle_g_pIdleTimer == NULL)
    {
        _Inline_MSIdle_g_pIdleTimer = _Inline_CreateThreadpoolTimer(&OnIdleTimer, NULL, NULL);
        if (_Inline_MSIdle_g_pIdleTimer == NULL)
        {
            return _Inline_GetLastError();
        }
    }
    _Inline_MSIdle_g_pfnCallback = pfnCallback;
    _Inline_MSIdle_g_dwIdleMin = dwIdleMin;
    _Inline_MSIdle_g_fIdleNotify = TRUE;
    SetIdleTimer();
    return ERROR_SUCCESS;
}

__inline
BOOL
WINAPI
_Inline_EndIdleDetection(
    DWORD dwReserved)
{
    PTP_TIMER Timer;

    if (dwReserved != 0)
    {
        return FALSE;
    }
    _InterlockedExchangePointer((void* volatile*)&_Inline_MSIdle_g_pfnCallback, NULL);
    Timer = _InterlockedExchangePointer(&_Inline_MSIdle_g_pIdleTimer, NULL);
    if (Timer != NULL)
    {
        _Inline_SetThreadpoolTimer(Timer, NULL, 0, 0);
        _Inline_WaitForThreadpoolTimerCallbacks(Timer, TRUE);
        _Inline_CloseThreadpoolTimer(Timer);
    }
    return TRUE;
}

__inline
BOOL
WINAPI
_Inline_SetIdleTimeout(
    DWORD dwIdleMin,
    DWORD dwReserved)
{
    if (dwReserved != 0)
    {
        return FALSE;
    }
    if (_Inline_MSIdle_g_dwIdleMin != 0)
    {
        _Inline_MSIdle_g_dwIdleMin = dwIdleMin;
    }
    return TRUE;
}

__inline
VOID
WINAPI
_Inline_SetIdleNotify(
    BOOL fIdleNotify)
{
    _Inline_MSIdle_g_fIdleNotify = fIdleNotify;
}

__inline
VOID
WINAPI
_Inline_SetBusyNotify(
    BOOL fBusyNotify)
{
    _Inline_MSIdle_g_fBusyNotify = fBusyNotify;
}

__inline
DWORD
WINAPI
_Inline_GetIdleMinutes(
    DWORD dwReserved)
{
    if (dwReserved != 0)
    {
        return 0;
    }
    return (_Inline_GetTickCount() - SharedUserData->LastSystemRITEventTickCount) / 60000UL;
}

__inline
DWORD
WINAPI
_Inline_GetIdleSeconds(
    DWORD dwReserved)
{
    if (dwReserved != 0)
    {
        return 0;
    }
    return (_Inline_GetTickCount() - SharedUserData->LastSystemRITEventTickCount) / 1000UL;
}

EXTERN_C_END
