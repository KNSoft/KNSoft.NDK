#pragma once

#include "Internal.inl"

EXTERN_C_START

__inline
_When_(lpModuleName == NULL, _Ret_notnull_)
_When_(lpModuleName != NULL, _Ret_maybenull_)
HMODULE
WINAPI
_Inline_GetModuleHandleW(
    _In_opt_ LPCWSTR lpModuleName)
{
    NTSTATUS Status;
    UNICODE_STRING DllName;
    PVOID DllHandle;

    if (lpModuleName == NULL)
    {
        return (HMODULE)NtCurrentPeb()->ImageBaseAddress;
    }

    _Inline_RtlInitUnicodeString(&DllName, lpModuleName);
    Status = _Inline_LdrGetDllHandle(NULL, NULL, &DllName, &DllHandle);
    if (NT_SUCCESS(Status))
    {
        return (HMODULE)DllHandle;
    }

    _Inline_BaseSetLastNTError(Status);
    return NULL;
}

__inline
BOOL
WINAPI
_Inline_GetModuleHandleExW(
    _In_ DWORD dwFlags,
    _In_opt_ LPCWSTR lpModuleName,
    _Out_ HMODULE* phModule)
{
    NTSTATUS Status;
    PVOID DllHandle;
    UNICODE_STRING DllName;

    if (phModule != NULL)
    {
        *phModule = NULL;
    } else
    {
        Status = STATUS_INVALID_PARAMETER_2;
        goto _Fail;
    }
    if ((dwFlags & ~(GET_MODULE_HANDLE_EX_FLAG_PIN |
                     GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT |
                     GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)) ||
        TEST_FLAGS(dwFlags, GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) ||
        (lpModuleName == NULL && (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)))
    {
        Status = STATUS_INVALID_PARAMETER_1;
        goto _Fail;
    }

    if (lpModuleName == NULL)
    {
        *phModule = (HMODULE)NtCurrentPeb()->ImageBaseAddress;
        return TRUE;
    }
    if (dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)
    {
        if (RtlPcToFileHeader((PVOID)lpModuleName, &DllHandle) == NULL)
        {
            Status = STATUS_DLL_NOT_FOUND;
            goto _Fail;
        }
    } else
    {
        _Inline_RtlInitUnicodeString(&DllName, lpModuleName);
        Status = _Inline_LdrGetDllHandle(NULL, NULL, &DllName, &DllHandle);
        if (!NT_SUCCESS(Status))
        {
            goto _Fail;
        }
    }
    if (!(dwFlags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT))
    {
        Status = LdrAddRefDll((dwFlags & GET_MODULE_HANDLE_EX_FLAG_PIN) ? LDR_ADDREF_DLL_PIN : 0, DllHandle);
        if (!NT_SUCCESS(Status))
        {
            goto _Fail;
        }
    }

    *phModule = (HMODULE)DllHandle;
    return TRUE;

_Fail:
    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

__inline
_Success_(return != 0)
_Ret_range_(1, nSize)
DWORD
WINAPI
_Inline_GetModuleFileNameW(
    _In_opt_ HMODULE hModule,
    _Out_writes_to_(nSize, ((return < nSize) ? (return +1) : nSize)) LPWSTR lpFilename,
    _In_ DWORD nSize)
{
    PVOID DllBase;
    PUNICODE_STRING ImageName;
    BOOLEAN LoaderLocked;
    PVOID Cookie;
    DWORD dwCch;
    PWCH Path;

    DllBase = _Inline_BasepMapModuleHandle(hModule, FALSE);
    if (hModule != NULL)
    {
        if (LDR_IS_RESOURCE(hModule))
        {
            _Inline_BaseSetLastNTError(STATUS_DLL_NOT_FOUND);
            return 0;
        }
    } else
    {
        PRTL_PERTHREAD_CURDIR PerThreadCurdir = (PRTL_PERTHREAD_CURDIR)NtReadTeb(NtTib.SubSystemTib);
        if (PerThreadCurdir != NULL && PerThreadCurdir->ImageName != NULL)
        {
            ImageName = PerThreadCurdir->ImageName;
            LoaderLocked = FALSE;
            goto _CopyPath;
        }
    }

    PLDR_DATA_TABLE_ENTRY HeadEntry, Entry;
    HeadEntry = CONTAINING_RECORD(NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink,
                                  LDR_DATA_TABLE_ENTRY,
                                  InLoadOrderLinks);
    Entry = HeadEntry;
    LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, NULL, &Cookie);
    LoaderLocked = TRUE;
    do
    {
        if (DllBase == Entry->DllBase)
        {
            ImageName = &Entry->FullDllName;
            goto _CopyPath;
        }
        Entry = CONTAINING_RECORD(Entry->InLoadOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    } while (Entry != HeadEntry);
    _Inline_BaseSetLastNTError(STATUS_DLL_NOT_FOUND);
    dwCch = 0;
    goto _Exit;

_CopyPath:
    Path = ImageName->Buffer;
    dwCch = ImageName->Length / sizeof(WCHAR);
    if (dwCch + 1 > nSize)
    {
        dwCch = nSize - 1;
        _Inline_RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER);
    } else
    {
        _Inline_RtlSetLastWin32Error(ERROR_SUCCESS);
    }
    if (nSize != 0)
    {
        memcpy(lpFilename, Path, dwCch * sizeof(WCHAR));
        lpFilename[dwCch] = UNICODE_NULL;
        return dwCch;
    } else
    {
        dwCch = 0;
    }
_Exit:
    if (LoaderLocked)
    {
        LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, Cookie);
    }
    return dwCch;
}

EXTERN_C_END
