#pragma once

#include "../MinDef.h"

EXTERN_C_START

#pragma region Fast Fail

/**
 * The RtlFailFast routine brings down the caller immediately in the event that critical corruption has been detected. No exception handlers are invoked.
 *
 * \param Code A FAST_FAIL_* symbolic constant from winnt.h or wdm.h that indicates the reason for process termination.
 * \return None. There is no return from this routine.
 * \remarks The routine is shared with user mode and kernel mode. In user mode, the process is terminated, whereas in kernel mode, a KERNEL_SECURITY_CHECK_FAILURE bug check is raised.
 */
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

/**
 * The RtlAssert routine reports an assertion failure and prompts the debugger or user for a response.
 *
 * \param VoidFailedAssertion A pointer to the null-terminated ANSI expression that failed.
 * \param VoidFileName A pointer to the null-terminated ANSI source file name.
 * \param LineNumber The source line number at which the assertion failed.
 * \param MutableMessage An optional pointer to a null-terminated ANSI message associated with the assertion.
 * \return This function does not return a value.
 * \remarks Depending on the selected response, the routine can return, break into the debugger, or terminate the
 * current thread or process.
 */
NTSYSAPI
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
/**
 * Dispatches an exception to the registered exception handlers for the current thread.
 *
 * \param ExceptionRecord A pointer to the exception record. The dispatcher can update its flags while processing the
 * exception.
 * \param ContextRecord A pointer to the processor context for the exception. An exception handler can modify this
 * context.
 * \return TRUE if the exception was handled; otherwise, FALSE.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlDispatchException(
    _Inout_ PEXCEPTION_RECORD ExceptionRecord,
    _Inout_ PCONTEXT ContextRecord);

/* phnt */
/**
 * Raises an exception whose exception code is the specified NTSTATUS value.
 *
 * \param Status The NTSTATUS value to raise as an exception.
 * \return This function does not return.
 */
_Analysis_noreturn_
NTSYSAPI
DECLSPEC_NORETURN
VOID
NTAPI
RtlRaiseStatus(
    _In_ NTSTATUS Status);

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)

/* phnt */
/**
 * Terminates the calling process immediately by raising a fast-fail exception when a return address hijack is detected.
 *
 * \details This function is typically invoked by security mitigations, such as Hardware-enforced Stack Protection
 * (Intel CET / Shadow Stack),
 * upon detecting an inconsistency between the expected and actual return addresses on the stack.
 * It internally triggers a fatal exception (typically STATUS_STACK_BUFFER_OVERRUN) and does not return to the caller.
 */
NTSYSAPI
VOID
NTAPI
RtlRaiseExceptionForReturnAddressHijack(VOID);

/* phnt */
/**
 * Captures a processor context and raises the supplied noncontinuable exception.
 *
 * \param ExceptionRecord A pointer to the exception record to dispatch or raise. If its exception address is NULL, the
 * routine supplies the caller's return address.
 * \param ContextRecord A pointer to a context record that receives the captured processor state.
 * \param FirstChance TRUE to dispatch the exception directly as a first-chance exception; FALSE to raise it through the
 * system service.
 * \return The status returned by the selected exception path if execution resumes.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRaiseNoncontinuableException(
    _Inout_ PEXCEPTION_RECORD ExceptionRecord,
    _Out_ PCONTEXT ContextRecord,
    _In_ BOOLEAN FirstChance);

#endif

#pragma endregion

#pragma region Exception Handling

/**
 * Registers a vectored exception handler.
 * 
 * @param First If this parameter is TRUE, the handler is the first handler in the list.
 * @param Handler A pointer to the vectored exception handler to be called.
 * @return A handle to the vectored exception handler.
 * @see https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler
 */
NTSYSAPI
PVOID
NTAPI
RtlAddVectoredExceptionHandler(
    _In_ ULONG First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler);

/**
 * Removes a vectored exception handler.
 * 
 * @param Handle A handle to the vectored exception handler to remove.
 * @return The function returns 0 if the handler is removed, or -1 if the handler is not found.
 * @see https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-removevectoredexceptionhandler
 */
NTSYSAPI
ULONG
NTAPI
RtlRemoveVectoredExceptionHandler(
    _In_ PVOID Handle);

/**
 * Registers a vectored continue handler.
 * 
 * @param First If this parameter is TRUE, the handler is the first handler in the list.
 * @param Handler A pointer to the vectored exception handler to be called.
 * @return A handle to the vectored continue handler.
 * @see https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredcontinuehandler
 */
NTSYSAPI
PVOID
NTAPI
RtlAddVectoredContinueHandler(
    _In_ ULONG First,
    _In_ PVECTORED_EXCEPTION_HANDLER Handler);

/**
 * Removes a vectored continue handler.
 * 
 * @param Handle A handle to the vectored continue handler to remove.
 * @return The function returns 0 if the handler is removed, or -1 if the handler is not found.
 * @see https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-removevectoredcontinuehandler
 */
NTSYSAPI
ULONG
NTAPI
RtlRemoveVectoredContinueHandler(
    _In_ PVOID Handle);

typedef
_Function_class_(RTLP_UNHANDLED_EXCEPTION_FILTER)
LONG
NTAPI
RTLP_UNHANDLED_EXCEPTION_FILTER(
/**
 * Pointer to an RTLP_UNHANDLED_EXCEPTION_FILTER callback.
 */
    _In_ PEXCEPTION_POINTERS ExceptionInfo);
typedef RTLP_UNHANDLED_EXCEPTION_FILTER *PRTLP_UNHANDLED_EXCEPTION_FILTER;

/**
 * The RtlSetUnhandledExceptionFilter routine registers a top-level unhandled exception filter for the process.
 *
 * \param UnhandledExceptionFilter An optional pointer to the unhandled exception filter callback.
 */
NTSYSAPI
VOID
NTAPI
RtlSetUnhandledExceptionFilter(
    _In_opt_ PRTLP_UNHANDLED_EXCEPTION_FILTER UnhandledExceptionFilter);

// rev
/**
 * The RtlUnhandledExceptionFilter routine is the default filter that handles exceptions not handled by any other
 * filter.
 *
 * \param ExceptionPointers A pointer to the EXCEPTION_POINTERS structure that describes the exception.
 * \return An exception disposition value, such as EXCEPTION_CONTINUE_SEARCH or EXCEPTION_EXECUTE_HANDLER.
 */
NTSYSAPI
LONG
NTAPI
RtlUnhandledExceptionFilter(
    _In_ PEXCEPTION_POINTERS ExceptionPointers);

// rev
/**
 * The RtlUnhandledExceptionFilter2 routine is the default filter that handles exceptions not handled by any other
 * filter, with additional control flags.
 *
 * \param ExceptionPointers A pointer to the EXCEPTION_POINTERS structure that describes the exception.
 * \param Flags Flags that control the filtering behavior.
 * \return An exception disposition value, such as EXCEPTION_CONTINUE_SEARCH or EXCEPTION_EXECUTE_HANDLER.
 */
NTSYSAPI
LONG
NTAPI
RtlUnhandledExceptionFilter2(
    _In_ PEXCEPTION_POINTERS ExceptionPointers,
    _In_ ULONG Flags);

// rev
/**
 * The RtlKnownExceptionFilter routine examines an exception against the set of known exceptions and returns the
 * appropriate disposition.
 *
 * \param ExceptionPointers A pointer to the EXCEPTION_POINTERS structure that describes the exception.
 * \return An exception disposition value, such as EXCEPTION_CONTINUE_SEARCH or EXCEPTION_EXECUTE_HANDLER.
 */
NTSYSAPI
LONG
NTAPI
RtlKnownExceptionFilter(
    _In_ PEXCEPTION_POINTERS ExceptionPointers);

#pragma endregion

#pragma region Win32 Error and NTSTATUS

/**
 * The RtlNtStatusToDosErrorNoTeb routine converts the specified NTSTATUS code to the corresponding Windows (Win32)
 * error code without updating the thread environment block (TEB).
 *
 * \param Status The NTSTATUS code to convert.
 * \return ULONG The corresponding Windows error code.
 */
_When_(Status < 0, _Out_range_(>, 0))
_When_(Status >= 0, _Out_range_(==, 0))
NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosErrorNoTeb(
    _In_ NTSTATUS Status);

_When_(Status < 0, _Out_range_(>, 0))
_When_(Status >= 0, _Out_range_(==, 0))
NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
    _In_ NTSTATUS Status);

/**
 * The RtlGetLastNtStatus routine returns the NTSTATUS code of the last error recorded for the calling thread.
 *
 * \return NTSTATUS The last NTSTATUS code recorded for the calling thread.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetLastNtStatus(VOID);

/**
 * The RtlGetLastWin32Error routine returns the Windows (Win32) error code of the last error recorded for the calling
 * thread.
 *
 * \return LONG The last Windows error code recorded for the calling thread.
 */
_Check_return_
_Post_equals_last_error_
NTSYSAPI
ULONG
NTAPI
RtlGetLastWin32Error(VOID);

/**
 * The RtlSetLastWin32Error routine sets the Windows (Win32) error code of the last error for the calling thread.
 *
 * \param Win32Error The Windows error code to record as the last error.
 */
NTSYSAPI
VOID
NTAPI
RtlSetLastWin32Error(
    _In_ ULONG Win32Error);

/**
 * The RtlRestoreLastWin32Error routine restores the calling thread's last Windows (Win32) error code without side
 * effects.
 *
 * \param Win32Error The Windows error code to restore as the last error.
 */
NTSYSAPI
VOID
NTAPI
RtlRestoreLastWin32Error(
    _In_ ULONG Win32Error);

/**
 * The RtlSetLastWin32ErrorAndNtStatusFromNtStatus routine sets the calling thread's last error, recording both the
 * specified NTSTATUS code and its equivalent Windows (Win32) error code.
 *
 * \param Status The NTSTATUS code to record as the last error.
 */
NTSYSAPI
VOID
NTAPI
RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
    _In_ NTSTATUS Status);

/*
 * Error code conversion (NOT translation) Win32 Error/NTSTATUS/HRESULT 
 * HRESULT_FROM_WIN32 / NTSTATUS_FROM_WIN32 / HRESULT_FROM_NT
 */

/**
 * Process error mode flags used by RtlGetThreadErrorMode and RtlSetThreadErrorMode.
 */
#define RTL_ERRORMODE_FAILCRITICALERRORS 0x0010
#define RTL_ERRORMODE_NOGPFAULTERRORBOX 0x0020
#define RTL_ERRORMODE_NOOPENFILEERRORBOX 0x0040

/**
 * The RtlGetThreadErrorMode routine returns the error mode for the calling thread.
 *
 * \return ULONG The current thread error mode flags.
 */
NTSYSAPI
ULONG
NTAPI
RtlGetThreadErrorMode(VOID);

/**
 * The RtlSetThreadErrorMode routine sets the error mode for the calling thread.
 *
 * \param NewMode The new thread error mode flags to set.
 * \param OldMode An optional pointer to a variable that receives the previous thread error mode.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadErrorMode(
    _In_ ULONG NewMode,
    _Out_opt_ PULONG OldMode);

#pragma endregion phnt, with fixes by KNSoft.NDK

#pragma region WER

/**
 * The RtlReportException routine reports an exception to Windows Error Reporting (WER).
 *
 * \param ExceptionRecord A pointer to the exception record describing the exception.
 * \param ContextRecord A pointer to the context record captured at the time of the exception.
 * \param Flags Flags that control how the exception is reported.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlReportException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ ULONG Flags);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
/**
 * The RtlReportExceptionEx routine reports an exception to Windows Error Reporting (WER) for the specified
 * process and thread.
 *
 * \param ExceptionRecord A pointer to the exception record describing the exception.
 * \param ContextRecord A pointer to the context record captured at the time of the exception.
 * \param Flags Flags that control how the exception is reported.
 * \param ProcessHandle An optional handle to the process for which the exception is reported.
 * \param ThreadHandle An optional handle to the thread for which the exception is reported.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlReportExceptionEx(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ ULONG Flags,
    _In_opt_ HANDLE ProcessHandle,
    _In_opt_ HANDLE ThreadHandle
    );
#endif

/**
 * The RtlWerpReportException routine submits an exception report for the specified process to Windows Error Reporting
 * (WER).
 *
 * \param ProcessId The identifier of the process for which the exception is reported.
 * \param CrashReportSharedMem A handle to the shared memory section containing the crash report data.
 * \param Entries An optional array of crash report entry pointers.
 * \param EntryCount The number of entries in the Entries array.
 * \param Flags Flags that control how the exception is reported.
 * \param CrashVerticalProcessHandle A pointer to a variable that receives a handle to the WER vertical process.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWerpReportException(
    _In_ ULONG ProcessId,
    _In_ HANDLE CrashReportSharedMem,
    _In_reads_opt_(EntryCount) const ULONG_PTR *Entries,
    _In_ ULONG EntryCount,
    _In_ ULONG Flags,
    _Out_ PHANDLE CrashVerticalProcessHandle
    );

/**
 * The RtlReportSilentProcessExit routine reports a silent process exit for the specified process.
 *
 * \param ProcessHandle A handle to the process that is exiting.
 * \param ExitStatus The exit status of the process.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlReportSilentProcessExit(
    _In_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus);

#pragma endregion phnt

EXTERN_C_END
