#pragma once

#include "Internal.inl"

EXTERN_C_START

__inline
HANDLE
WINAPI
_Inline_GetProcessHeap(VOID)
{
    return RtlProcessHeap();
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

EXTERN_C_END
