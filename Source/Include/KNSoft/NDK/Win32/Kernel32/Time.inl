#pragma once

#include "../../NDK.h"
#include "../../NT/NT.inl"

EXTERN_C_START

__inline
BOOL
WINAPI
_Inline_QueryPerformanceCounter(
    _Out_ LARGE_INTEGER* lpPerformanceCount)
{
#if NT_VERSION_MIN >= NT_VERSION_WIN7
    RtlQueryPerformanceCounter(lpPerformanceCount);
#else
    NtQueryPerformanceCounter(lpPerformanceCount, NULL);
#endif
    return TRUE;
}

__inline
BOOL
WINAPI
_Inline_QueryPerformanceFrequency(
    _Out_ LARGE_INTEGER* lpFrequency)
{
    _Inline_RtlQueryPerformanceFrequency(lpFrequency);
    return TRUE;
}

__inline
DWORD
WINAPI
_Inline_GetTickCount(VOID)
{
#if _WIN64
    return (ULONG)((SharedUserData->TickCountMultiplier * SharedUserData->TickCountQuad) >> 24);
#else
    REGISTER ULONG HighPart, LowPart;
    if (SharedUserData->TickCountMultiplier < 0x1000000UL)
    {
        while (TRUE)
        {
            // The kernel writes High2Time, LowPart, then High1Time. Read High1Time and LowPart with acquire
            // ordering before checking High2Time to avoid accepting a torn tick count.
            HighPart = (ULONG)ReadAcquire(&SharedUserData->TickCount.High1Time);
            LowPart = (ULONG)ReadAcquire((volatile LONG*)&SharedUserData->TickCount.LowPart);
            if (HighPart == (ULONG)ReadNoFence(&SharedUserData->TickCount.High2Time))
            {
                break;
            }
            YieldProcessor();
        }
        return (ULONG)((UInt32x32To64(SharedUserData->TickCountMultiplier, LowPart) >> 24) +
                       (UInt32x32To64(SharedUserData->TickCountMultiplier, HighPart) << 8));
    }
    return UInt32x32To64(SharedUserData->TickCountMultiplier, SharedUserData->TickCount.LowPart) >> 24;
#endif
}

__inline
ULONGLONG
WINAPI
_Inline_GetTickCount64(VOID)
{
#if _WIN64
    return (SharedUserData->TickCountMultiplier * SharedUserData->TickCountQuad) >> 24;
#else
    REGISTER ULONG HighPart, LowPart;
    while (TRUE)
    {
        // The kernel writes High2Time, LowPart, then High1Time. Read High1Time and LowPart with acquire
        // ordering before checking High2Time to avoid accepting a torn tick count.
        HighPart = (ULONG)ReadAcquire(&SharedUserData->TickCount.High1Time);
        LowPart = (ULONG)ReadAcquire((volatile LONG*)&SharedUserData->TickCount.LowPart);
        if (HighPart == (ULONG)ReadNoFence(&SharedUserData->TickCount.High2Time))
        {
            break;
        }
        YieldProcessor();
    }
    return (UInt32x32To64(SharedUserData->TickCountMultiplier, LowPart) >> 24) +
        (UInt32x32To64(SharedUserData->TickCountMultiplier, HighPart) << 8);
#endif
}

__inline
VOID
WINAPI
_Inline_GetSystemTimeAsFileTime(
    _Out_ LPFILETIME lpSystemTimeAsFileTime
)
{
#if _WIN64
    *(PULONGLONG)lpSystemTimeAsFileTime = *(PULONGLONG)&SharedUserData->SystemTime;
#else
    REGISTER ULONG HighPart;
    while (TRUE)
    {
        HighPart = SharedUserData->SystemTime.High1Time;
        if (HighPart == SharedUserData->SystemTime.High2Time)
        {
            break;
        }
        YieldProcessor();
    }
    lpSystemTimeAsFileTime->dwLowDateTime = SharedUserData->SystemTime.LowPart;
    lpSystemTimeAsFileTime->dwHighDateTime = HighPart;
#endif
}

EXTERN_C_END
