#pragma once

#include "Internal.inl"

EXTERN_C_START

_Must_inspect_result_
__inline
DWORD
WINAPI
_Inline_TlsAlloc(VOID)
{
    PPEB Peb;
    ULONG Index;
    PVOID* Slots;

    Peb = NtCurrentPeb();
    _Inline_RtlAcquirePebLock();
    while (TRUE)
    {
        Index = RtlFindClearBitsAndSet(Peb->TlsBitmap, 1, 0);
        if (Index != -1)
        {
            _Inline_RtlReleasePebLock();
            NtWriteTeb(TlsSlots[Index], NULL);
            return Index;
        }
        Slots = NtReadTeb(TlsExpansionSlots);
        if (Slots != NULL)
        {
            break;
        }
        _Inline_RtlReleasePebLock();
        Slots = (PVOID*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, TLS_EXPANSION_SLOTS * sizeof(PVOID));
        if (Slots == NULL)
        {
            goto _Fail;
        }
        NtWriteTeb(TlsExpansionSlots, Slots);
        _Inline_RtlAcquirePebLock();
    }
    Index = RtlFindClearBitsAndSet(Peb->TlsExpansionBitmap, 1, 0);
    _Inline_RtlReleasePebLock();
    if (Index != -1)
    {
        Slots[Index] = NULL;
        return Index + TLS_MINIMUM_AVAILABLE;
    }

_Fail:
    _Inline_BaseSetLastNTError(STATUS_NO_MEMORY);
    return TLS_OUT_OF_INDEXES;
}

__inline
BOOL
WINAPI
_Inline_TlsFree(
    _In_ DWORD dwTlsIndex)
{
    PPEB Peb;
    ULONG Index;
    PRTL_BITMAP Bitmap;

    Peb = NtCurrentPeb();
    Index = dwTlsIndex;
    if (dwTlsIndex >= TLS_MINIMUM_AVAILABLE)
    {
        Index = dwTlsIndex - TLS_MINIMUM_AVAILABLE;
        if (Index >= TLS_EXPANSION_SLOTS)
        {
            goto _Fail;
        }
        Bitmap = Peb->TlsExpansionBitmap;
    } else
    {
        Bitmap = Peb->TlsBitmap;
    }
    _Inline_RtlAcquirePebLock();
    if (RtlAreBitsSet(Bitmap, Index, 1) &&
        NT_SUCCESS(NtSetInformationThread(NtCurrentThread(), ThreadZeroTlsCell, &dwTlsIndex, sizeof(dwTlsIndex))))
    {
        RtlClearBits(Bitmap, Index, 1);
        _Inline_RtlReleasePebLock();
        return TRUE;
    }
    _Inline_RtlReleasePebLock();

_Fail:
    _Inline_BaseSetLastNTError(STATUS_INVALID_PARAMETER);
    return FALSE;
}

__inline
BOOL
WINAPI
_Inline_TlsSetValue(
    _In_ DWORD dwTlsIndex,
    _In_opt_ LPVOID lpTlsValue)
{
    if (dwTlsIndex < TLS_MINIMUM_AVAILABLE)
    {
        NtWriteTeb(TlsSlots[dwTlsIndex], lpTlsValue);
    } else if (dwTlsIndex < TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS)
    {
        PVOID* Slots = NtReadTeb(TlsExpansionSlots);
        if (Slots == NULL)
        {
            Slots = (PVOID*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, TLS_EXPANSION_SLOTS * sizeof(PVOID));
            if (Slots == NULL)
            {
                _Inline_BaseSetLastNTError(STATUS_NO_MEMORY);
                return FALSE;
            }
        }
        Slots[dwTlsIndex - TLS_MINIMUM_AVAILABLE] = lpTlsValue;
    } else
    {
        _Inline_BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

__inline
LPVOID
WINAPI
_Inline_TlsGetValue(
    _In_ DWORD dwTlsIndex)
{
    PVOID Value;

    if (dwTlsIndex < TLS_MINIMUM_AVAILABLE)
    {
        Value = NtReadCurrentTebPVOID(FIELD_OFFSET(TEB, TlsSlots) + dwTlsIndex * sizeof(PVOID));
    } else if (dwTlsIndex < TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS)
    {
        PVOID* Slots = NtReadTeb(TlsExpansionSlots);
        Value = Slots != NULL ? Slots[dwTlsIndex - TLS_MINIMUM_AVAILABLE] : NULL;
    } else
    {
        _Inline_BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return NULL;
    }
    if (NtReadTeb(LastErrorValue) != ERROR_SUCCESS)
    {
        NtWriteTeb(LastErrorValue, ERROR_SUCCESS);
    }
    return Value;
}

__inline
LPVOID
WINAPI
_Inline_TlsGetValue2(
    _In_ DWORD dwTlsIndex)
{
    if (dwTlsIndex < TLS_MINIMUM_AVAILABLE)
    {
        return NtReadCurrentTebPVOID(FIELD_OFFSET(TEB, TlsSlots) + dwTlsIndex * sizeof(PVOID));
    }
    dwTlsIndex -= TLS_MINIMUM_AVAILABLE;
    if (dwTlsIndex < TLS_EXPANSION_SLOTS)
    {
        PVOID* Slots = NtReadTeb(TlsExpansionSlots);
        if (Slots)
        {
            return Slots[dwTlsIndex];
        }
    }

    return NULL;
}

__inline
BOOL
WINAPI
_Inline_IsThreadAFiber(VOID)
{
    return NtCurrentTeb()->HasFiberData;
}

#if (_WIN32_WINNT >= 0x0600)

__inline
DWORD
WINAPI
_Inline_FlsAlloc(
    _In_opt_ PFLS_CALLBACK_FUNCTION lpCallback)
{
    NTSTATUS Status;
    ULONG Index;

    Status = RtlFlsAlloc(lpCallback, &Index);
    if (!NT_SUCCESS(Status))
    {
        _Inline_BaseSetLastNTError(Status);
        return FLS_OUT_OF_INDEXES;
    }
    return Index;
}

__inline
BOOL
WINAPI
_Inline_FlsFree(
    _In_ DWORD dwFlsIndex)
{
    NTSTATUS Status = RtlFlsFree(dwFlsIndex);
    if (!NT_SUCCESS(Status))
    {
        _Inline_BaseSetLastNTError(Status);
        return FALSE;
    }
    return TRUE;
}

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)

__inline
BOOL
WINAPI
_Inline_FlsSetValue(
    _In_ DWORD dwFlsIndex,
    _In_opt_ PVOID lpFlsData)
{
    NTSTATUS Status;

    Status = RtlFlsSetValue(dwFlsIndex, lpFlsData);
    if (NT_SUCCESS(Status))
    {
        return TRUE;
    };
    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

__inline
PVOID
WINAPI
_Inline_FlsGetValue(
    _In_ DWORD dwFlsIndex)
{
    NTSTATUS Status;
    PVOID Value;

    Status = RtlFlsGetValue(dwFlsIndex, &Value);
    if (NT_SUCCESS(Status))
    {
        NtWriteTeb(LastErrorValue, ERROR_SUCCESS);
        return Value;
    }
    if (Status == STATUS_MEMORY_NOT_ALLOCATED)
    {
        Status = STATUS_INVALID_PARAMETER;
    }
    _Inline_BaseSetLastNTError(Status);
    return NULL;
}

__inline
PVOID
WINAPI
_Inline_FlsGetValue2(
    _In_ DWORD dwFlsIndex)
{
    return RtlFlsGetValue2(dwFlsIndex);
}

#endif

EXTERN_C_END
