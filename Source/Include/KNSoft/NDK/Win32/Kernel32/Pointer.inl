#pragma once

#include "../../NDK.h"
#include "../../NT/NT.inl"

EXTERN_C_START

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

#if (NTDDI_VERSION >= NTDDI_WIN10)

__inline
HRESULT
WINAPI
_Inline_EncodeRemotePointer(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID Ptr,
    _Out_ PVOID * EncodedPtr)
{
    return RtlEncodeRemotePointer(ProcessHandle, Ptr, EncodedPtr);
}

__inline
HRESULT
WINAPI
_Inline_DecodeRemotePointer(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID Ptr,
    _Out_ PVOID * DecodedPtr)
{
    return RtlDecodeRemotePointer(ProcessHandle, Ptr, DecodedPtr);
}

#endif

EXTERN_C_END
