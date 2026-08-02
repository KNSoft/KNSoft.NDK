#pragma once

#include "../../NDK.h"

EXTERN_C_START

#if defined(_M_X64) || defined(_M_ARM64EC)

__inline
BOOLEAN
NTAPI
_Inline_RtlIsEcCode(
    _In_ DWORD64 CodePointer)
{
    PCUCHAR EcCodeBitMap;
    DWORD64 PageIndex;
    UCHAR PageBitMask;

    if (SharedUserData->NativeProcessorArchitecture != PROCESSOR_ARCHITECTURE_ARM64 ||
        CodePointer < (DWORD64)MM_LOWEST_USER_ADDRESS)
    {
        return FALSE;
    }
    EcCodeBitMap = (PCUCHAR)NtCurrentPeb()->EcCodeBitMap;
    if (EcCodeBitMap == NULL)
    {
        return FALSE;
    }

    PageIndex = CodePointer >> PAGE_SHIFT;
    PageBitMask = (UCHAR)(1u << (PageIndex % CHAR_BIT));
    return BooleanFlagOn(EcCodeBitMap[PageIndex / CHAR_BIT], PageBitMask);
}

#else

// Extension: Provide compatibility support for x86 builds.
__inline
BOOLEAN
NTAPI
_Inline_RtlIsEcCode(
    _In_ DWORD64 CodePointer)
{
    UNREFERENCED_PARAMETER(CodePointer);
    return FALSE;
}

#endif

__inline
NTSTATUS
NTAPI
_Inline_RtlWow64GetThreadContext(
    _In_ HANDLE ThreadHandle,
    _Inout_ PWOW64_CONTEXT ThreadContext)
{
    return NtQueryInformationThread(ThreadHandle, ThreadWow64Context, ThreadContext, sizeof(WOW64_CONTEXT), NULL);
}

__inline
NTSTATUS
NTAPI
_Inline_RtlWow64SetThreadContext(
    _In_ HANDLE ThreadHandle,
    _In_ PWOW64_CONTEXT ThreadContext)
{
    return NtSetInformationThread(ThreadHandle, ThreadWow64Context, ThreadContext, sizeof(WOW64_CONTEXT));
}

EXTERN_C_END
