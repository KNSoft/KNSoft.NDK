#pragma once

#include "../../NDK.h"
#include "../../NT/NT.inl"

EXTERN_C_START

__inline
VOID
WINAPI
_Inline_InitializeSListHead(
    _Out_ PSLIST_HEADER ListHead)
{
    RtlInitializeSListHead(ListHead);
}

__inline
PSLIST_ENTRY
WINAPI
_Inline_InterlockedFlushSList(
    _Inout_ PSLIST_HEADER ListHead)
{
    return RtlInterlockedFlushSList(ListHead);
}

__inline
PSLIST_ENTRY
WINAPI
_Inline_InterlockedPopEntrySList(
    _Inout_ PSLIST_HEADER ListHead)
{
    return RtlInterlockedPopEntrySList(ListHead);
}

__inline
PSLIST_ENTRY
WINAPI
_Inline_InterlockedPushEntrySList(
    _Inout_ PSLIST_HEADER ListHead,
    _Inout_ __drv_aliasesMem PSLIST_ENTRY ListEntry)
{
    return RtlInterlockedPushEntrySList(ListHead, ListEntry);
}

__inline
PSLIST_ENTRY
WINAPI
_Inline_InterlockedPushListSList(
    _Inout_ PSLIST_HEADER ListHead,
    _Inout_ PSLIST_ENTRY List,
    _Inout_ PSLIST_ENTRY ListEnd,
    _In_ ULONG Count)
{
    return RtlInterlockedPushListSList(ListHead, List, ListEnd, Count);
}

__inline
PSLIST_ENTRY
WINAPI
_Inline_InterlockedPushListSListEx(
    _Inout_ PSLIST_HEADER ListHead,
    _Inout_ PSLIST_ENTRY List,
    _Inout_ PSLIST_ENTRY ListEnd,
    _In_ ULONG Count)
{
    return
#if NT_VERSION_MIN >= NT_VERSION_WIN8
        RtlInterlockedPushListSListEx
#else
        RtlInterlockedPushListSList
#endif
        (ListHead, List, ListEnd, Count);
}

__inline
USHORT
WINAPI
_Inline_QueryDepthSList(
    _In_ PSLIST_HEADER ListHead)
{
    return RtlQueryDepthSList(ListHead);
}

EXTERN_C_END
