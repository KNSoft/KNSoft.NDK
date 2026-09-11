#pragma once

#include "Internal.inl"

EXTERN_C_START

__inline
_Ret_maybenull_
_Post_writable_byte_size_(dwSize)
LPVOID
WINAPI
_Inline_VirtualAlloc(
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect)
{
    NTSTATUS Status;
    PVOID BaseAddress = lpAddress;
    SIZE_T RegionSize = dwSize;

    if (lpAddress != NULL && (ULONG_PTR)lpAddress < MM_ALLOCATION_GRANULARITY)
    {
        _Inline_RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* Strip the six low-order internal allocation flags, as KernelBase does. */
    Status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                     &BaseAddress,
                                     0,
                                     &RegionSize,
                                     flAllocationType & ~0x3FUL,
                                     flProtect);
    if (NT_SUCCESS(Status))
    {
        return BaseAddress;
    }

    _Inline_BaseSetLastNTError(Status);
    return NULL;
}

__inline
_Success_(return != FALSE)
BOOL
WINAPI
_Inline_VirtualFree(
    _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD dwFreeType)
{
    const DWORD PlaceholderFlags = MEM_COALESCE_PLACEHOLDERS | MEM_PRESERVE_PLACEHOLDER;
    const DWORD ValidFreeTypes = PlaceholderFlags | MEM_DECOMMIT | MEM_RELEASE;
    NTSTATUS Status;
    PVOID BaseAddress = lpAddress;
    SIZE_T RegionSize = dwSize;

    if ((dwFreeType & ~ValidFreeTypes) != 0 ||
        ((dwFreeType & (MEM_RELEASE | PlaceholderFlags)) == MEM_RELEASE && dwSize != 0))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto _Fail;
    }

    Status = NtFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, dwFreeType);
    if (Status == STATUS_USER_MAPPED_FILE)
    {
        if (!RtlFlushSecureMemoryCache(BaseAddress, RegionSize))
        {
            goto _Fail;
        }
        Status = NtFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, dwFreeType);
    }
    if (NT_SUCCESS(Status))
    {
        return TRUE;
    }

_Fail:
    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

__inline
_Success_(return != FALSE)
BOOL
WINAPI
_Inline_VirtualProtect(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flNewProtect,
    _Out_ PDWORD lpflOldProtect)
{
    NTSTATUS Status;
    PVOID BaseAddress = lpAddress;
    SIZE_T RegionSize = dwSize;

    Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                    &BaseAddress,
                                    &RegionSize,
                                    flNewProtect,
                                    lpflOldProtect);
    if (Status == STATUS_USER_MAPPED_FILE)
    {
        if (!RtlFlushSecureMemoryCache(BaseAddress, RegionSize))
        {
            goto _Fail;
        }
        Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                        &BaseAddress,
                                        &RegionSize,
                                        flNewProtect,
                                        lpflOldProtect);
    }
    if (NT_SUCCESS(Status))
    {
        return TRUE;
    }

_Fail:
    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

__inline
SIZE_T
WINAPI
_Inline_VirtualQuery(
    _In_opt_ LPCVOID lpAddress,
    _Out_writes_bytes_to_(dwLength,return) PMEMORY_BASIC_INFORMATION lpBuffer,
    _In_ SIZE_T dwLength)
{
    NTSTATUS Status;
    SIZE_T ReturnLength;

    Status = NtQueryVirtualMemory(NtCurrentProcess(),
                                  (PVOID)lpAddress,
                                  MemoryBasicInformation,
                                  lpBuffer,
                                  dwLength,
                                  &ReturnLength);
    if (NT_SUCCESS(Status))
    {
        return ReturnLength;
    }

    _Inline_BaseSetLastNTError(Status);
    return 0;
}

EXTERN_C_END
