#pragma once

#include "../../NDK.h"

EXTERN_C_START

__inline
LOGICAL
NTAPI
_Inline_RtlQueryPerformanceFrequency(
    _Out_ PLARGE_INTEGER PerformanceFrequency)
{
    if (SharedUserData->NtMajorVersion > 6 ||
        SharedUserData->NtMajorVersion == 6 && SharedUserData->NtMinorVersion >= 2)
    {
        PerformanceFrequency->QuadPart = SharedUserData->QpcFrequency;
    } else
    {
        LARGE_INTEGER PerformanceCounter;
        NtQueryPerformanceCounter(&PerformanceCounter, PerformanceFrequency);
    }
    return TRUE;
}

EXTERN_C_END
