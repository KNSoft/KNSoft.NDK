#pragma once

#include "../../NDK.h"
#include "../../NT/NT.inl"

EXTERN_C_START

#pragma region Internal functions

__inline
ULONG
_Inline_BaseSetLastNTError(
    _In_ NTSTATUS Status)
{
    ULONG Error = _Inline_RtlNtStatusToDosError(Status);
    _Inline_RtlSetLastWin32Error(Error);
    return Error;
}

__inline
PLARGE_INTEGER
_Inline_BaseFormatTimeOut(
    PLARGE_INTEGER Timeout,
    _In_ ULONG Milliseconds)
{
    if (Milliseconds == INFINITE)
    {
        return NULL;
    } else
    {
        Timeout->QuadPart = Milliseconds * -10000LL;
        return Timeout;
    }
}

#pragma endregion

#pragma region Process Environment

__inline
DWORD
WINAPI
_Inline_GetCurrentThreadId(VOID)
{
    return NtCurrentThreadId();
}

__inline
DWORD
WINAPI
_Inline_GetCurrentProcessId(VOID)
{
    return NtCurrentProcessId();
}

#pragma endregion

#pragma region QPC

__inline
BOOL
WINAPI
_Inline_QueryPerformanceCounter(
    _Out_ LARGE_INTEGER* lpPerformanceCount)
{
    RtlQueryPerformanceCounter(lpPerformanceCount);
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

#pragma endregion

#pragma region Pointer encode / decode

__inline
_Ret_maybenull_
PVOID
WINAPI
_Inline_EncodePointer(
    _In_opt_ PVOID Ptr)
{
    return RtlEncodePointer(Ptr);
}

__inline
_Ret_maybenull_
PVOID
WINAPI
_Inline_DecodePointer(
    _In_opt_ PVOID Ptr)
{
    return RtlDecodePointer(Ptr);
}

__inline
_Ret_maybenull_
PVOID
WINAPI
_Inline_EncodeSystemPointer(
    _In_opt_ PVOID Ptr)
{
    return RtlEncodeSystemPointer(Ptr);
}

__inline
_Ret_maybenull_
PVOID
WINAPI
_Inline_DecodeSystemPointer(
    _In_opt_ PVOID Ptr)
{
    return RtlDecodeSystemPointer(Ptr);
}

__inline
HRESULT
WINAPI
_Inline_EncodeRemotePointer(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID Ptr,
    _Out_ PVOID* EncodedPtr)
{
    return RtlEncodeRemotePointer(ProcessHandle, Ptr, EncodedPtr);
}

__inline
HRESULT
WINAPI
_Inline_DecodeRemotePointer(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID Ptr,
    _Out_ PVOID* DecodedPtr)
{
    return RtlDecodeRemotePointer(ProcessHandle, Ptr, DecodedPtr);
}

#pragma endregion

#pragma region Critical Section

__inline
VOID
WINAPI
_Inline_InitializeCriticalSection(
    _Out_ LPCRITICAL_SECTION lpCriticalSection)
{
    RtlInitializeCriticalSection(lpCriticalSection);
}

__inline
_Must_inspect_result_
BOOL
WINAPI
_Inline_InitializeCriticalSectionAndSpinCount(
    _Out_ LPCRITICAL_SECTION lpCriticalSection,
    _In_ DWORD dwSpinCount)
{
    RtlInitializeCriticalSectionAndSpinCount(lpCriticalSection, dwSpinCount);
    return TRUE;
}

__inline
BOOL
WINAPI
_Inline_InitializeCriticalSectionEx(
    _Out_ LPCRITICAL_SECTION lpCriticalSection,
    _In_ DWORD dwSpinCount,
    _In_ DWORD Flags)
{
    NTSTATUS Status = RtlInitializeCriticalSectionEx(lpCriticalSection, dwSpinCount, Flags);
    if (!NT_SUCCESS(Status))
    {
        _Inline_BaseSetLastNTError(Status);
        return FALSE;
    }
    return TRUE;
}

__inline
DWORD
WINAPI
_Inline_SetCriticalSectionSpinCount(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection,
    _In_ DWORD dwSpinCount)
{
    return RtlSetCriticalSectionSpinCount(lpCriticalSection, dwSpinCount);
}

__inline
BOOL
WINAPI
_Inline_TryEnterCriticalSection(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection)
{
    return RtlTryEnterCriticalSection(lpCriticalSection);
}

__inline
VOID
WINAPI
_Inline_EnterCriticalSection(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection)
{
    RtlEnterCriticalSection(lpCriticalSection);
}

__inline
VOID
WINAPI
_Inline_LeaveCriticalSection(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection)
{
    _Analysis_assume_lock_held_(lpCriticalSection);
    RtlLeaveCriticalSection(lpCriticalSection);
}

__inline
VOID
WINAPI
_Inline_DeleteCriticalSection(
    _Inout_ LPCRITICAL_SECTION lpCriticalSection)
{
    RtlDeleteCriticalSection(lpCriticalSection);
}

#pragma endregion

#pragma region TLS / FLS

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
            Slots = (PVOID*)RtlAllocateHeap(NtGetProcessHeap(), HEAP_ZERO_MEMORY, TLS_EXPANSION_SLOTS * sizeof(PVOID));
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
BOOL
WINAPI
_Inline_IsThreadAFiber(VOID)
{
    return NtCurrentTeb()->HasFiberData;
}

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

#pragma endregion

#pragma region Heap

__inline
HANDLE
WINAPI
_Inline_GetProcessHeap(VOID)
{
    return NtGetProcessHeap();
}

__inline
_Ret_maybenull_
_Post_writable_byte_size_(dwBytes)
DECLSPEC_ALLOCATOR
LPVOID
WINAPI
_Inline_HeapAlloc(
    _In_ HANDLE hHeap,
    _In_ DWORD dwFlags,
    _In_ SIZE_T dwBytes)
{
    return RtlAllocateHeap(hHeap, dwFlags, dwBytes);
}

__inline
_Success_(return != 0)
_Ret_maybenull_
_Post_writable_byte_size_(dwBytes)
DECLSPEC_ALLOCATOR
LPVOID
WINAPI
_Inline_HeapReAlloc(
    _Inout_ HANDLE hHeap,
    _In_ DWORD dwFlags,
    _Frees_ptr_opt_ LPVOID lpMem,
    _In_ SIZE_T dwBytes)
{
    return RtlReAllocateHeap(hHeap, dwFlags, lpMem, dwBytes);
}

__inline
_Success_(return != FALSE)
BOOL
WINAPI
_Inline_HeapFree(
    _Inout_ HANDLE hHeap,
    _In_ DWORD dwFlags,
    __drv_freesMem(Mem) _Frees_ptr_opt_ LPVOID lpMem)
{
    return RtlFreeHeap(hHeap, dwFlags, lpMem);
}

__inline
SIZE_T
WINAPI
_Inline_HeapSize(
    _In_ HANDLE hHeap,
    _In_ DWORD dwFlags,
    _In_ LPCVOID lpMem)
{
    return RtlSizeHeap(hHeap, dwFlags, (PVOID)lpMem);
}

__inline
BOOL
WINAPI
_Inline_HeapQueryInformation(
    _In_opt_ HANDLE HeapHandle,
    _In_ HEAP_INFORMATION_CLASS HeapInformationClass,
    _Out_writes_bytes_to_opt_(HeapInformationLength, *ReturnLength) PVOID HeapInformation,
    _In_ SIZE_T HeapInformationLength,
    _Out_opt_ PSIZE_T ReturnLength)
{
    NTSTATUS Status = RtlQueryHeapInformation(HeapHandle,
                                              HeapInformationClass,
                                              HeapInformation,
                                              HeapInformationLength,
                                              ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        _Inline_BaseSetLastNTError(Status);
        return FALSE;
    }
    return TRUE;
}

__inline
BOOL
WINAPI
_Inline_HeapValidate(
    _In_ HANDLE hHeap,
    _In_ DWORD dwFlags,
    _In_opt_ LPCVOID lpMem)
{
    return RtlValidateHeap(hHeap, dwFlags, (PVOID)lpMem);
}

__inline
SIZE_T
WINAPI
_Inline_HeapCompact(
    _In_ HANDLE hHeap,
    _In_ DWORD dwFlags)
{
    return RtlCompactHeap(hHeap, dwFlags);
}

#pragma endregion

#pragma region Console

__inline
HANDLE
WINAPI
_Inline_GetStdHandle(
    _In_ DWORD nStdHandle)
{
    HANDLE StdHandle;

    if (nStdHandle == STD_INPUT_HANDLE)
    {
        if (NtCurrentPeb()->ProcessParameters->WindowFlags & STARTF_USEHOTKEY)
        {
            return NULL;
        }
        StdHandle = NtCurrentPeb()->ProcessParameters->StandardInput;
    } else if (nStdHandle == STD_OUTPUT_HANDLE)
    {
        if (NtCurrentPeb()->ProcessParameters->WindowFlags & STARTF_USEMONITOR)
        {
            return NULL;
        }
        StdHandle = NtCurrentPeb()->ProcessParameters->StandardOutput;
    } else if (nStdHandle == STD_ERROR_HANDLE)
    {
        StdHandle = NtCurrentPeb()->ProcessParameters->StandardError;
    } else
    {
        StdHandle = INVALID_HANDLE_VALUE;
    }
    if (StdHandle == INVALID_HANDLE_VALUE)
    {
        _Inline_BaseSetLastNTError(STATUS_INVALID_HANDLE);
    }
    return StdHandle;
}

__inline
BOOL
WINAPI
_Inline_SetStdHandle(
    _In_ DWORD nStdHandle,
    _In_ HANDLE hHandle)
{
    if (nStdHandle == STD_INPUT_HANDLE)
    {
        NtCurrentPeb()->ProcessParameters->StandardInput = hHandle;
    } else if (nStdHandle == STD_OUTPUT_HANDLE)
    {
        NtCurrentPeb()->ProcessParameters->StandardOutput = hHandle;
    } else if (nStdHandle == STD_ERROR_HANDLE)
    {
        NtCurrentPeb()->ProcessParameters->StandardError = hHandle;
    } else
    {
        _Inline_BaseSetLastNTError(STATUS_INVALID_HANDLE);
        return FALSE;
    }

    return TRUE;
}

#pragma endregion

#pragma region AVX

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
    return
#if !defined(_WIN64) || (NTDDI_VERSION < NTDDI_WIN8)
        !SharedUserData->ProcessorFeatures[PF_XMMI_INSTRUCTIONS_AVAILABLE] ?
        XSTATE_MASK_LEGACY_FLOATING_POINT :
#endif
        XSTATE_MASK_LEGACY;
}

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
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

#pragma endregion

__inline
_Check_return_
_Post_equals_last_error_
DWORD
WINAPI
_Inline_GetLastError(VOID)
{
    return _Inline_RtlGetLastWin32Error();
}

__inline
VOID
WINAPI
_Inline_SetLastError(
    _In_ DWORD dwErrCode)
{
    return _Inline_RtlSetLastWin32Error(dwErrCode);
}

__inline
BOOL
WINAPI
_Inline_IsProcessorFeaturePresent(
    _In_ DWORD ProcessorFeature)
{
    return ProcessorFeature < PROCESSOR_FEATURE_MAX ?
        SharedUserData->ProcessorFeatures[ProcessorFeature] :
        FALSE;
}

EXTERN_C_END
