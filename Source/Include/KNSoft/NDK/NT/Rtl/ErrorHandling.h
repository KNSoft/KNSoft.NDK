#pragma once

#include "../MinDef.h"

EXTERN_C_START

#pragma region Fast Fail

DECLSPEC_NORETURN
FORCEINLINE
VOID
RtlFailFast(
    _In_ ULONG Code)
{
    __fastfail(Code);
}

#pragma endregion wdm.h

#pragma region Assert

NTSYSAPI
__analysis_noreturn
VOID
NTAPI
RtlAssert(
    _In_ PVOID VoidFailedAssertion,
    _In_ PVOID VoidFileName,
    _In_ ULONG LineNumber,
    _In_opt_ PSTR MutableMessage);

#if DBG

#define ASSERT( exp ) \
    ((!(exp)) ? \
        (RtlAssert( (PVOID)#exp, (PVOID)__FILE__, __LINE__, NULL ),FALSE) : \
        TRUE)
#define ASSERTMSG( msg, exp ) \
    ((!(exp)) ? \
        (RtlAssert( (PVOID)#exp, (PVOID)__FILE__, __LINE__, (PSTR)msg ),FALSE) : \
        TRUE)
#define RTL_SOFT_ASSERT(_exp) \
    ((!(_exp)) ? \
        (DbgPrint("%s(%d): Soft assertion failed\n   Expression: %s\n", __FILE__, __LINE__, #_exp),FALSE) : \
        TRUE)
#define RTL_SOFT_ASSERTMSG(_msg, _exp) \
    ((!(_exp)) ? \
        (DbgPrint("%s(%d): Soft assertion failed\n   Expression: %s\n   Message: %s\n", __FILE__, __LINE__, #_exp, (_msg)),FALSE) : \
        TRUE)
#define RTL_VERIFY         ASSERT
#define RTL_VERIFYMSG      ASSERTMSG
#define RTL_SOFT_VERIFY    RTL_SOFT_ASSERT
#define RTL_SOFT_VERIFYMSG RTL_SOFT_ASSERTMSG

#else

#define ASSERT(exp)         ((void) 0)
#define ASSERTMSG(msg, exp) ((void) 0)
#define RTL_SOFT_ASSERT(_exp)           ((void) 0)
#define RTL_SOFT_ASSERTMSG(_msg, _exp)  ((void) 0)
#define RTL_VERIFY(exp)         ((exp) ? TRUE : FALSE)
#define RTL_VERIFYMSG(msg, exp) ((exp) ? TRUE : FALSE)
#define RTL_SOFT_VERIFY(_exp)           ((_exp) ? TRUE : FALSE)
#define RTL_SOFT_VERIFYMSG(msg, _exp)   ((_exp) ? TRUE : FALSE)

#endif // DBG

#pragma endregion wdm.h

#pragma region Exception

/* phnt */
NTSYSAPI
BOOLEAN
NTAPI
RtlDispatchException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord);

/* phnt */
NTSYSAPI
DECLSPEC_NORETURN
VOID
NTAPI
RtlRaiseStatus(
    _In_ NTSTATUS Status);

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)

/* phnt */
NTSYSAPI
VOID
NTAPI
RtlRaiseExceptionForReturnAddressHijack(VOID);

/* phnt */
NTSYSAPI
DECLSPEC_NORETURN
VOID
NTAPI
RtlRaiseNoncontinuableException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord);

#endif

#pragma endregion

#pragma region Exception Handling

NTSYSAPI
PVOID
NTAPI
RtlAddVectoredExceptionHandler(
    _In_ ULONG First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler
);

NTSYSAPI
ULONG
NTAPI
RtlRemoveVectoredExceptionHandler(
    _In_ PVOID Handle
);

NTSYSAPI
PVOID
NTAPI
RtlAddVectoredContinueHandler(
    _In_ ULONG First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler
);

NTSYSAPI
ULONG
NTAPI
RtlRemoveVectoredContinueHandler(
    _In_ PVOID Handle
);

typedef
_Function_class_(RTLP_UNHANDLED_EXCEPTION_FILTER)
ULONG
NTAPI
RTLP_UNHANDLED_EXCEPTION_FILTER(
    _In_ PEXCEPTION_POINTERS ExceptionInfo);
typedef RTLP_UNHANDLED_EXCEPTION_FILTER *PRTLP_UNHANDLED_EXCEPTION_FILTER;

NTSYSAPI
VOID
NTAPI
RtlSetUnhandledExceptionFilter(
    _In_ PRTLP_UNHANDLED_EXCEPTION_FILTER UnhandledExceptionFilter
);

// rev
NTSYSAPI
LONG
NTAPI
RtlUnhandledExceptionFilter(
    _In_ PEXCEPTION_POINTERS ExceptionPointers
);

// rev
NTSYSAPI
LONG
NTAPI
RtlUnhandledExceptionFilter2(
    _In_ PEXCEPTION_POINTERS ExceptionPointers,
    _In_ ULONG Flags
);

// rev
NTSYSAPI
LONG
NTAPI
RtlKnownExceptionFilter(
    _In_ PEXCEPTION_POINTERS ExceptionPointers
);

#pragma endregion

#pragma region Win32 Error and NTSTATUS

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
    _In_ NTSTATUS Status);

_When_(Status < 0, _Out_range_(> , 0))
_When_(Status >= 0, _Out_range_(== , 0))
NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosErrorNoTeb(
    _In_ NTSTATUS Status);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetLastNtStatus(VOID);

NTSYSAPI
ULONG
NTAPI
RtlGetLastWin32Error(VOID);

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
    _In_ NTSTATUS Status);

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32Error(
    _In_ ULONG Win32Error);

NTSYSAPI
VOID
NTAPI
RtlRestoreLastWin32Error(
    _In_ ULONG Win32Error);

#define RTL_ERRORMODE_FAILCRITICALERRORS 0x0010
#define RTL_ERRORMODE_NOGPFAULTERRORBOX 0x0020
#define RTL_ERRORMODE_NOOPENFILEERRORBOX 0x0040

NTSYSAPI
ULONG
NTAPI
RtlGetThreadErrorMode(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadErrorMode(
    _In_ ULONG NewMode,
    _Out_opt_ PULONG OldMode);

#pragma endregion phnt, with fixes by KNSoft.NDK

#pragma region WER

#if (NTDDI_VERSION >= NTDDI_WIN6)
NTSYSAPI
NTSTATUS
NTAPI
RtlReportException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ ULONG Flags);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
NTSYSAPI
NTSTATUS
NTAPI
RtlReportExceptionEx(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ ULONG Flags,
    _In_ PLARGE_INTEGER Timeout);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN6)
NTSYSAPI
NTSTATUS
NTAPI
RtlWerpReportException(
    _In_ ULONG ProcessId,
    _In_ HANDLE CrashReportSharedMem,
    _In_ ULONG Flags,
    _Out_ PHANDLE CrashVerticalProcessHandle);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)
NTSYSAPI
NTSTATUS
NTAPI
RtlReportSilentProcessExit(
    _In_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus);
#endif

#pragma endregion phnt

EXTERN_C_END
