#pragma once

#include "../../NDK.h"

EXTERN_C_START

__inline
BOOLEAN
NTAPI
_Inline_RtlIsZeroMemory(
    _In_ PVOID Buffer,
    _In_ SIZE_T Length)
{
    PUCHAR Current = (PUCHAR)Buffer;

    while (((ULONG_PTR)Current & 7) != 0 && Length != 0)
    {
        if (*Current != 0)
            return FALSE;

        Current++;
        Length--;
    }

    while (Length >= sizeof(ULONG64))
    {
        if (*(PULONG64)Current != 0)
            return FALSE;

        Current += sizeof(ULONG64);
        Length -= sizeof(ULONG64);
    }

    while (Length != 0)
    {
        if (*Current != 0)
            return FALSE;

        Current++;
        Length--;
    }

    return TRUE;
}

EXTERN_C_END
