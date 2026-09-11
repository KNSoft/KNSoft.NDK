#pragma once

#include "Internal.inl"
#include "Console.inl"

EXTERN_C_START

__inline
BOOL
WINAPI
_Inline_WriteFile(
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped)
{
    NTSTATUS Status;
    PVOID ApcContext;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    DWORD StdHandle = (DWORD)(DWORD_PTR)hFile;

    if (lpNumberOfBytesWritten != NULL)
    {
        *lpNumberOfBytesWritten = 0;
    }
    if (StdHandle >= STD_ERROR_HANDLE)
    {
        if (StdHandle == STD_ERROR_HANDLE)
        {
            hFile = NtCurrentPeb()->ProcessParameters->StandardError;
        } else if (StdHandle == STD_OUTPUT_HANDLE)
        {
            hFile = NtCurrentPeb()->ProcessParameters->StandardOutput;
        } else if (StdHandle == STD_INPUT_HANDLE)
        {
            hFile = NtCurrentPeb()->ProcessParameters->StandardInput;
        }
    }

    if (lpOverlapped == NULL)
    {
        Status = NtWriteFile(hFile,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             (PVOID)lpBuffer,
                             nNumberOfBytesToWrite,
                             NULL,
                             NULL);
        if (Status == STATUS_PENDING)
        {
            Status = NtWaitForSingleObject(hFile, FALSE, NULL);
            if (NT_SUCCESS(Status))
            {
                Status = IoStatusBlock.Status;
            }
        }
        if (NT_SUCCESS(Status))
        {
            if (lpNumberOfBytesWritten != NULL)
            {
                *lpNumberOfBytesWritten = (ULONG)IoStatusBlock.Information;
            }
            return TRUE;
        }
        if (NT_WARNING(Status) && lpNumberOfBytesWritten != NULL)
        {
            *lpNumberOfBytesWritten = (ULONG)IoStatusBlock.Information;
        }
    } else
    {
        lpOverlapped->Internal = STATUS_PENDING;
        ApcContext = (ULONG_PTR)lpOverlapped->hEvent & 1 ? NULL : lpOverlapped;

        /* False positive warnings, hFile and lpBuffer are assumed not NULL */
#pragma warning(disable: __WARNING_INVALID_PARAM_VALUE_1 __WARNING_INVALID_PARAM_VALUE_3)
        Status = NtWriteFile(hFile,
                             lpOverlapped->hEvent,
                             NULL,
                             ApcContext,
                             (PIO_STATUS_BLOCK)lpOverlapped,
                             (PVOID)lpBuffer,
                             nNumberOfBytesToWrite,
                             (PLARGE_INTEGER)&lpOverlapped->Offset,
                             NULL);
#pragma warning(disable: __WARNING_INVALID_PARAM_VALUE_1 __WARNING_INVALID_PARAM_VALUE_3)

        if (Status != STATUS_PENDING && !NT_ERROR(Status))
        {
            if (lpNumberOfBytesWritten != NULL)
            {
                *lpNumberOfBytesWritten = (ULONG)lpOverlapped->InternalHigh;
            }
            return TRUE;
        }
    }

    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

__inline
BOOL
WINAPI
_Inline_FlushFileBuffers(
    _In_ HANDLE hFile)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;
    DWORD StdHandle = (DWORD)(DWORD_PTR)hFile;

    if (StdHandle == STD_ERROR_HANDLE)
    {
        hFile = NtCurrentPeb()->ProcessParameters->StandardError;
    } else if (StdHandle == STD_OUTPUT_HANDLE)
    {
        hFile = NtCurrentPeb()->ProcessParameters->StandardOutput;
    } else if (StdHandle == STD_INPUT_HANDLE)
    {
        hFile = NtCurrentPeb()->ProcessParameters->StandardInput;
    }

    Status = NtFlushBuffersFile(hFile, &IoStatusBlock);
    if (NT_SUCCESS(Status))
    {
        return TRUE;
    }
    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * A successful path through the function doesn't set the _Out_ annotated parameter.
 * The original SAL annotation in Windows SDK has no _Success_ expression.
 */
#pragma warning(disable: 6101)

__inline
BOOL
WINAPI
_Inline_SetFilePointerEx(
    _In_ HANDLE hFile,
    _In_ LARGE_INTEGER liDistanceToMove,
    _Out_opt_ PLARGE_INTEGER lpNewFilePointer,
    _In_ DWORD dwMoveMethod)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_POSITION_INFORMATION FilePosition;
    FILE_STANDARD_INFORMATION FileStandard;

    if (dwMoveMethod == FILE_BEGIN)
    {
        FilePosition.CurrentByteOffset.QuadPart = liDistanceToMove.QuadPart;
    } else if (dwMoveMethod == FILE_CURRENT)
    {
        Status = NtQueryInformationFile(hFile,
                                        &IoStatusBlock,
                                        &FilePosition,
                                        sizeof(FilePosition),
                                        FilePositionInformation);
        if (!NT_SUCCESS(Status))
        {
            _Inline_BaseSetLastNTError(Status);
            return FALSE;
        }
        FilePosition.CurrentByteOffset.QuadPart += liDistanceToMove.QuadPart;
    } else if (dwMoveMethod == FILE_END)
    {
        Status = NtQueryInformationFile(hFile,
                                        &IoStatusBlock,
                                        &FileStandard,
                                        sizeof(FileStandard),
                                        FileStandardInformation);
        if (!NT_SUCCESS(Status))
        {
            _Inline_BaseSetLastNTError(Status);
            return FALSE;
        }
        FilePosition.CurrentByteOffset.QuadPart = FileStandard.EndOfFile.QuadPart + liDistanceToMove.QuadPart;
    } else
    {
        _Inline_RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (FilePosition.CurrentByteOffset.QuadPart < 0)
    {
        _Inline_RtlSetLastWin32Error(ERROR_NEGATIVE_SEEK);
        return FALSE;
    }
    Status = NtSetInformationFile(hFile,
                                  &IoStatusBlock,
                                  &FilePosition,
                                  sizeof(FilePosition),
                                  FilePositionInformation);
    if (!NT_SUCCESS(Status))
    {
        _Inline_BaseSetLastNTError(Status);
        return FALSE;
    }
    if (lpNewFilePointer != NULL)
    {
        *lpNewFilePointer = FilePosition.CurrentByteOffset;
    }

    return TRUE;
}

__inline
BOOL
WINAPI
_Inline_GetFileSizeEx(
    _In_ HANDLE hFile,
    _Out_ PLARGE_INTEGER lpFileSize)
{
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION Info;
    NTSTATUS Status;

    Status = NtQueryInformationFile(hFile, &IoStatusBlock, &Info, sizeof(Info), FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        _Inline_BaseSetLastNTError(Status);
        return FALSE;
    }

    lpFileSize->QuadPart = Info.EndOfFile.QuadPart;
    return TRUE;
}

#pragma warning(default: 6101)

__inline
BOOL
WINAPI
_Inline_CloseHandle(
    _In_ _Post_ptr_invalid_ HANDLE hObject)
{
    NTSTATUS Status;
    DWORD StdHandle;
    HANDLE PrevStdHandle;

    /* Handle standard I/O handles */
    StdHandle = (DWORD)(DWORD_PTR)hObject;
    if (StdHandle >= STD_ERROR_HANDLE && StdHandle <= STD_INPUT_HANDLE)
    {
        /* SAL marked input handle cannot be NULL, but we need to do that for clearing standard handle */
#pragma warning(disable: __WARNING_INVALID_PARAM_VALUE_1)
        if (_Inline_SetStdHandleEx(StdHandle, NULL, &PrevStdHandle))
        {
            hObject = PrevStdHandle;
        }
#pragma warning(default: __WARNING_INVALID_PARAM_VALUE_1)
    }

    // FIXME: SbExecuteProcedure...

    /* hObject seems can be NULL when reach here... */
#pragma warning(disable: __WARNING_INVALID_PARAM_VALUE_3)
    Status = NtClose(hObject);
#pragma warning(default: __WARNING_INVALID_PARAM_VALUE_3)
    if (NT_SUCCESS(Status))
    {
        return TRUE;
    }
    _Inline_BaseSetLastNTError(Status);
    return FALSE;
}

EXTERN_C_END
