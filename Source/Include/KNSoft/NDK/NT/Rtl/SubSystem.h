#pragma once

#include "../MinDef.h"
#include "../Lpc/Base.h"

EXTERN_C_START

#pragma region SMSS

NTSYSAPI
NTSTATUS
NTAPI
RtlConnectToSm(
    _In_ PUNICODE_STRING ApiPortName,
    _In_ HANDLE ApiPortHandle,
    _In_ DWORD ProcessImageType,
    _Out_ PHANDLE SmssConnection);

NTSYSAPI
NTSTATUS
NTAPI
RtlSendMsgToSm(
    _In_ HANDLE ApiPortHandle,
    _In_ PPORT_MESSAGE MessageData);

#pragma endregion phnt

#pragma region CSRSS

/* KNSoft.NDK */
NTSYSAPI
HANDLE
NTAPI
CsrGetProcessId(VOID);

/* phnt */
#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSYSAPI
NTSTATUS
NTAPI
RtlRegisterThreadWithCsrss(VOID);
#endif

#pragma endregion 

EXTERN_C_END
