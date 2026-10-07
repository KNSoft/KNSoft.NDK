#pragma once

#include "../MinDef.h"
#include "../Io/Info.h"
#include "../Ex/Wnf.h"
#include "../Ps/Basic.h"

#include <minwinbase.h>

EXTERN_C_START

#pragma region Enclave

// RtlCallEnclave
/**
 * The RtlCallEnclave routine calls a routine inside a VBS enclave.
 *
 * \param Routine The address of the routine to call within the enclave.
 * \param Reserved Reserved; must be NULL.
 * \param Flags Call flags controlling the enclave transition.
 * \param ReturnValue Receives the value returned by the enclave routine.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCallEnclave(
    _In_ PVOID Routine,
    _In_opt_ PVOID Reserved,
    _In_ ULONG Flags,
    _Out_ PVOID *ReturnValue
    );

// RtlCallEnclaveReturn
/**
 * The RtlCallEnclaveReturn routine returns control from an enclave call back to the host.
 *
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCallEnclaveReturn(
    VOID
    );

// RtlEnclaveCallDispatchReturn
/**
 * The RtlEnclaveCallDispatchReturn routine returns control from an enclave dispatch call back to the host.
 *
 * \param EnclaveTarget The enclave target address associated with the dispatch.
 * \param LeafRoutine An optional leaf routine to invoke on return.
 * \param LeafNumber The enclave leaf number.
 * \param DispatchContext On input the current dispatch context; receives the updated context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlEnclaveCallDispatchReturn(
    _In_ PVOID EnclaveTarget,
    _In_opt_ PVOID LeafRoutine,
    _In_ ULONG LeafNumber,
    _Inout_opt_ PVOID *DispatchContext
    );

#pragma endregion

#pragma region Atom

// RtlInitializeAtomPackage
/**
 * The RtlInitializeAtomPackage routine initializes the process-wide atom package.
 *
 * \param Callback An optional callback invoked by the atom package.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeAtomPackage(
    _In_opt_ PVOID Callback
    );

#pragma endregion

/* phnt */

#pragma region Thread Profiling

// rev
/**
 * The RtlEnableThreadProfiling routine enables thread profiling on the specified thread.
 *
 * \param ThreadHandle The handle to the thread on which you want to enable profiling. This must be the current thread.
 * \param Flags To receive thread profiling data such as context switch count, set this parameter to THREAD_PROFILING_FLAG_DISPATCH; otherwise, set to 0.
 * \param HardwareCounters To receive hardware performance counter data, set this parameter to a bitmask that identifies the hardware counters to collect.
 * \param PerformanceDataHandle An opaque handle that you use when calling the RtlReadThreadProfilingData and RtlDisableThreadProfiling functions.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-enablethreadprofiling
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlEnableThreadProfiling(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG Flags,
    _In_ ULONG64 HardwareCounters,
    _Out_ PVOID* PerformanceDataHandle);

// rev
/**
 * The RtlDisableThreadProfiling routine disables thread profiling.
 *
 * \param PerformanceDataHandle The handle that the RtlEnableThreadProfiling function returned.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-querythreadprofiling
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDisableThreadProfiling(
    _In_ PVOID PerformanceDataHandle);

// rev
/**
 * The RtlQueryThreadProfiling routine determines whether thread profiling is enabled for the specified thread.
 *
 * \param ThreadHandle The handle to the thread on which you want to enable profiling. This must be the current thread.
 * \param Enabled Is TRUE if thread profiling is enabled for the specified thread; otherwise, FALSE.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-querythreadprofiling
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryThreadProfiling(
    _In_ HANDLE ThreadHandle,
    _Out_ PBOOLEAN Enabled);

// rev
/**
 * The RtlReadThreadProfilingData routine reads the specified profiling data associated with the thread.
 *
 * \param PerformanceDataHandle The handle that the RtlEnableThreadProfiling function returned.
 * \param Flags One or more flags set when you called the RtlEnableThreadProfiling function that specify the counter data to read.
 * \param PerformanceData A PERFORMANCE_DATA structure that contains the thread profiling and hardware counter data.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readthreadprofilingdata
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlReadThreadProfilingData(
    _In_ HANDLE PerformanceDataHandle,
    _In_ ULONG Flags,
    _Out_ PPERFORMANCE_DATA PerformanceData);

#pragma endregion

#pragma region Timer

/**
 * Creates a queue for timers.
 *
 * \param TimerQueueHandle A pointer to a variable that receives the handle to the newly created timer queue.
 * \return NTSTATUS Successful or errant status.
 * \remarks Timer-queue timers are lightweight objects that enable you to specify a callback function to be called at a specified time.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueue
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateTimerQueue(
    _Out_ PHANDLE TimerQueueHandle);

// WAITORTIMERCALLBACKFUNC
typedef _Function_class_(RTL_TIMER_CALLBACK)
VOID NTAPI RTL_TIMER_CALLBACK(
    _In_ PVOID Parameter,
    _In_ BOOLEAN TimerOrWaitFired
    );
/**
 * Pointer to an RTL_TIMER_CALLBACK callback.
 */
typedef RTL_TIMER_CALLBACK *PRTL_TIMER_CALLBACK;

/**
 * Creates a timer-queue timer.
 *
 * \param TimerQueueHandle A handle to the timer queue. This handle is returned by a previous call to RtlCreateTimerQueue.
 * \param Handle A pointer to a variable that receives the handle to the newly created timer-queue timer.
 * \param Function A pointer to the callback function to be executed when the timer expires.
 * \param Context A pointer to a variable to be passed to the callback function.
 * \param DueTime The amount of time in milliseconds relative to the current time that must elapse before the timer is signaled for the first time.
 * \param Period The period of the timer in milliseconds. If this value is zero, the timer is signaled once; otherwise, it is signaled periodically.
 * \param Flags The flags that control the behavior of the timer. This parameter can be zero or one of the following values:
 * WT_EXECUTEDEFAULT, WT_EXECUTEONLYONCE, WT_EXECUTELONGFUNCTION, WT_EXECUTEINTIMERTHREAD, WT_EXECUTEINPERSISTENTTHREAD, WT_TRANSFER_IMPERSONATION.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueuetimer
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateTimer(
    _In_ HANDLE TimerQueueHandle,
    _Out_ PHANDLE Handle,
    _In_ PRTL_TIMER_CALLBACK Function,
    _In_opt_ PVOID Context,
    _In_ ULONG DueTime,
    _In_ ULONG Period,
    _In_ ULONG Flags);

/**
 * The RtlSetTimer routine creates a timer within a timer queue.
 *
 * \param TimerQueueHandle A handle to the timer queue.
 * \param Handle Receives a handle to the newly created timer.
 * \param Function The callback invoked when the timer expires.
 * \param Context An optional context value passed to the callback.
 * \param DueTime The time, in milliseconds, before the timer first expires.
 * \param Period The period, in milliseconds, for recurring expiration; zero for one-shot.
 * \param Flags Flags controlling timer behavior.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetTimer(
    _In_ HANDLE TimerQueueHandle,
    _Out_ PHANDLE Handle,
    _In_ PRTL_TIMER_CALLBACK Function,
    _In_opt_ PVOID Context,
    _In_ ULONG DueTime,
    _In_ ULONG Period,
    _In_ ULONG Flags);

/**
 * The RtlUpdateTimer routine changes the due time and period of an existing timer.
 *
 * \param TimerQueueHandle A handle to the timer queue that owns the timer.
 * \param TimerHandle A handle to the timer to update.
 * \param DueTime The new time, in milliseconds, before the timer first fires.
 * \param Period The new period, in milliseconds, between subsequent firings, or zero for a one-shot timer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUpdateTimer(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE TimerHandle,
    _In_ ULONG DueTime,
    _In_ ULONG Period);

/**
 * Flag requesting that timer deletion block until pending callbacks complete.
 */
#define RTL_TIMER_DELETE_WAIT_FOR_COMPLETION ((HANDLE)(LONG_PTR)-1)

/**
 * The RtlDeleteTimer routine deletes a timer from a timer queue, optionally waiting for pending callbacks to complete.
 *
 * \param TimerQueueHandle A handle to the timer queue that owns the timer.
 * \param TimerToCancel A handle to the timer to delete.
 * \param Event An optional handle to an event signaled when the timer is deleted, or
 * RTL_TIMER_DELETE_WAIT_FOR_COMPLETION to wait for completion.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteTimer(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE TimerToCancel,
    _In_opt_ HANDLE Event // optional: RTL_TIMER_DELETE_WAIT_FOR_COMPLETION
);

/**
 * The RtlDeleteTimerQueue routine deletes a timer queue and all of the timers it contains.
 *
 * \param TimerQueueHandle A handle to the timer queue to delete.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteTimerQueue(
    _In_ HANDLE TimerQueueHandle);

/**
 * The RtlDeleteTimerQueueEx routine deletes a timer queue and all of its timers, optionally waiting for pending
 * callbacks to complete.
 *
 * \param TimerQueueHandle A handle to the timer queue to delete.
 * \param Event An optional handle to an event signaled when the queue is deleted, or a sentinel value to wait for
 * completion.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteTimerQueueEx(
    _In_ HANDLE TimerQueueHandle,
    _In_opt_ HANDLE Event);

#pragma endregion

#pragma region QPC

// rev
/**
 * The RtlQueryPerformanceCounter routine retrieves the current value of the performance counter, which is a high resolution (<1us) time stamp that can be used for time-interval measurements.
 *
 * \param PerformanceCounter A pointer to a variable that receives the current performance-counter value, in counts.
 * \return Returns TRUE if the function succeeds, otherwise FALSE. On systems that run Windows XP or later, the function will always succeed and will thus never return zero.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter
 */
NTSYSAPI
LOGICAL
NTAPI
RtlQueryPerformanceCounter(
    _Out_ PLARGE_INTEGER PerformanceCounter);

// rev
/**
 * The RtlQueryPerformanceFrequency routine retrieves the frequency of the performance counter. The frequency of the performance counter is fixed at system boot and is consistent across all processors.
 * Therefore, the frequency need only be queried upon application initialization, and the result can be cached.
 *
 * \param PerformanceFrequency A pointer to a variable that receives the current performance-counter frequency, in counts per second.
 * \return Returns TRUE if the function succeeds, otherwise FALSE. On systems that run Windows XP or later, the function will always succeed and will thus never return zero.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency
 */
NTSYSAPI
LOGICAL
NTAPI
RtlQueryPerformanceFrequency(
    _Out_ PLARGE_INTEGER PerformanceFrequency);

#pragma endregion

#pragma region Transactions

/**
 * The RtlGetCurrentTransaction routine returns the transaction handle associated with the calling thread.
 *
 * \return HANDLE A handle to the current transaction, or NULL if no transaction is active.
 */
NTSYSAPI
HANDLE
NTAPI
RtlGetCurrentTransaction(
    VOID
    );

/**
 * The RtlSetCurrentTransaction routine associates the specified transaction handle with the calling thread.
 *
 * \param TransactionHandle An optional handle to the transaction to associate with the current thread, or NULL to clear
 * the current transaction.
 * \return `TRUE` if the transaction was set, otherwise `FALSE`.
 */
NTSYSAPI
LOGICAL
NTAPI
RtlSetCurrentTransaction(
    _In_opt_ HANDLE TransactionHandle);

#pragma endregion

#pragma region Pointer Encode/Decode

/**
 * The RtlEncodePointer routine encodes the specified pointer. Encoded pointers can be used to provide another layer of protection for pointer values.
 *
 * \param Ptr The system pointer to be encoded.
 * \return The function returns the encoded pointer.
 * \sa https://learn.microsoft.com/en-us/previous-versions/bb432254(v=vs.85)
 */
NTSYSAPI
_Ret_maybenull_
PVOID
NTAPI
RtlEncodePointer(
    _In_opt_ PVOID Ptr);

/**
 * The RtlDecodePointer routine decodes a pointer that was previously encoded with RtlEncodePointer.
 *
 * \param Ptr The system pointer to be decoded.
 * \return The function returns the decoded pointer.
 * \sa https://learn.microsoft.com/en-us/previous-versions/bb432242(v=vs.85)
 */
NTSYSAPI
_Ret_maybenull_
PVOID
NTAPI
RtlDecodePointer(
    _In_opt_ PVOID Ptr);

/**
 * The RtlEncodeSystemPointer routine encodes the specified pointer with a system-specific value.
 * Encoded pointers can be used to provide another layer of protection for pointer values.
 *
 * \param Ptr The system pointer to be encoded.
 * \return The function returns the encoded pointer.
 * \sa https://learn.microsoft.com/en-us/previous-versions/bb432255(v=vs.85)
 */
NTSYSAPI
_Ret_maybenull_
PVOID
NTAPI
RtlEncodeSystemPointer(
    _In_opt_ PVOID Ptr);

/**
 * The RtlDecodeSystemPointer routine decodes a pointer that was previously encoded with RtlEncodeSystemPointer.
 *
 * \param Ptr The pointer to be decoded.
 * \return The function returns the decoded pointer.
 * \sa https://learn.microsoft.com/en-us/previous-versions/bb432243(v=vs.85)
 */
NTSYSAPI
_Ret_maybenull_
PVOID
NTAPI
RtlDecodeSystemPointer(
    _In_opt_ PVOID Ptr);

#if (NTDDI_VERSION >= NTDDI_WIN10)

// rev
/**
 * The RtlEncodeRemotePointer routine encodes the specified pointer of the specified process.
 * Encoded pointers can be used to provide another layer of protection for pointer values.
 *
 * \param ProcessHandle Handle to the remote process that owns the pointer.
 * \param Pointer The pointer to be encoded.
 * \param EncodedPointer The encoded pointer.
 * \return HRESULT Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/previous-versions/dn877135(v=vs.85)
 */
NTSYSAPI
HRESULT
NTAPI
RtlEncodeRemotePointer(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID Pointer,
    _Out_ PVOID* EncodedPointer);

// rev
/**
 * The RtlDecodeRemotePointer routine decodes a pointer in a specified process that was previously
 * encoded with RtlEncodePointer or RtlEncodeRemotePointer.
 *
 * \param ProcessHandle Handle to the remote process that owns the pointer.
 * \param Pointer The pointer to be decoded.
 * \param DecodedPointer The decoded pointer.
 * \return HRESULT Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/previous-versions/dn877133(v=vs.85)
 */
NTSYSAPI
HRESULT
NTAPI
RtlDecodeRemotePointer(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID Pointer,
    _Out_ PVOID* DecodedPointer);

#endif

#pragma endregion

#pragma region Session

/**
 * The RtlGetCurrentServiceSessionId routine returns the service session identifier associated with the current process.
 *
 * \return ULONG The current service session identifier, or zero if none is assigned.
 */
NTSYSAPI
ULONG
NTAPI
RtlGetCurrentServiceSessionId(VOID);

/**
 * The RtlGetActiveConsoleId routine returns the session identifier of the currently active console session.
 *
 * \return ULONG The identifier of the active console session.
 */
NTSYSAPI
ULONG
NTAPI
RtlGetActiveConsoleId(VOID);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
/**
 * The RtlGetConsoleSessionForegroundProcessId routine returns the process identifier of the foreground process in the
 * active console session.
 *
 * \return LONGLONG The process identifier of the console session's foreground process.
 */
NTSYSAPI
LONGLONG
NTAPI
RtlGetConsoleSessionForegroundProcessId(VOID);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
/**
 * Contains properties describing a session.
 */
typedef struct _RTL_SESSION_PROPERTIES
{
    ULONG IsCurrentSessionId;
} RTL_SESSION_PROPERTIES, *PRTL_SESSION_PROPERTIES;

/**
 * The RtlGetSessionProperties routine retrieves the properties of the specified session.
 *
 * \param SessionId The identifier of the session to query.
 * \param SessionProperties A pointer to an RTL_SESSION_PROPERTIES structure that receives the session properties.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSessionProperties(
    _In_ ULONG SessionId,
    _Out_ PRTL_SESSION_PROPERTIES SessionProperties);
#endif

#pragma endregion

#pragma region Lock/Unlock TEB/Stack/Module Section

/**
 * The RtlLockCurrentThread routine locks the current thread to prevent it from being suspended or terminated during a
 * critical operation.
 *
 * \return NTSTATUS Successful or errant status.
 */
_Acquires_lock_(NtCurrentThread())
NTSYSAPI
NTSTATUS
NTAPI
RtlLockCurrentThread(VOID);

/**
 * The RtlUnlockCurrentThread routine releases a lock previously acquired by RtlLockCurrentThread on the current thread.
 *
 * \return NTSTATUS Successful or errant status.
 */
_Releases_lock_(NtCurrentThread())
NTSYSAPI
NTSTATUS
NTAPI
RtlUnlockCurrentThread(VOID);

/**
 * The RtlLockModuleSection routine locks the image section containing the specified address into the working set.
 *
 * \param Address An address within the module section to lock.
 * \return NTSTATUS Successful or errant status.
 */
_Acquires_lock_(Address)
NTSYSAPI
NTSTATUS
NTAPI
RtlLockModuleSection(
    _In_ PVOID Address);

/**
 * The RtlUnlockModuleSection routine unlocks the image section containing the specified address.
 *
 * \param Address An address within the module section to unlock.
 * \return NTSTATUS Successful or errant status.
 */
_Releases_lock_(Address)
NTSYSAPI
NTSTATUS
NTAPI
RtlUnlockModuleSection(
    _In_ PVOID Address);

#pragma endregion

#pragma region Place Holder

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)

/**
 * The RtlIsCloudFilesPlaceholder routine determines whether a file or directory is a Cloud Files placeholder, based on
 * its attributes and reparse tag.
 *
 * \param FileAttributes The file attributes of the file or directory.
 * \param ReparseTag The reparse tag (or EaSize) of the file or directory.
 * \return Returns `TRUE` if the file or directory is a Cloud Files placeholder, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtliscloudfilesplaceholder
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsCloudFilesPlaceholder(
    _In_ ULONG FileAttributes,
    _In_ ULONG ReparseTag);

/**
 * The RtlIsPartialPlaceholder routine determines whether a file or directory is a partial Cloud Files placeholder,
 * based on its attributes and reparse tag.
 *
 * \param FileAttributes The file attributes of the file or directory.
 * \param ReparseTag The reparse tag (or EaSize) of the file or directory.
 * \return Returns `TRUE` if the file or directory is a partial placeholder, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlispartialplaceholder
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsPartialPlaceholder(
    _In_ ULONG FileAttributes,
    _In_ ULONG ReparseTag);

/**
 * The RtlIsPartialPlaceholderFileHandle routine determines whether the file referenced by a handle is a partial
 * placeholder.
 *
 * \param FileHandle A handle to the file to test. The handle must have at least FILE_READ_ATTRIBUTES access.
 * \param IsPartialPlaceholder A pointer to a variable that receives whether the file is a partial placeholder.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlispartialplaceholderfilehandle
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIsPartialPlaceholderFileHandle(
    _In_ HANDLE FileHandle,
    _Out_ PBOOLEAN IsPartialPlaceholder);

/**
 * The RtlIsPartialPlaceholderFileInfo routine determines whether file information describes a partial cloud-files
 * placeholder.
 *
 * \param InfoBuffer A buffer containing file information of the specified class.
 * \param InfoClass The file information class of the data in InfoBuffer.
 * \param IsPartialPlaceholder Receives TRUE if the file is a partial placeholder.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIsPartialPlaceholderFileInfo(
    _In_ PVOID InfoBuffer,
    _In_ FILE_INFORMATION_CLASS InfoClass,
    _Out_ PBOOLEAN IsPartialPlaceholder);

#undef PHCM_MAX
/**
 * Process placeholder compatibility mode values.
 */
#define PHCM_APPLICATION_DEFAULT ((CHAR)0)
#define PHCM_DISGUISE_PLACEHOLDERS ((CHAR)1)
#define PHCM_EXPOSE_PLACEHOLDERS ((CHAR)2)
#define PHCM_MAX ((CHAR)2)

/**
 * Error values returned by the placeholder compatibility mode routines.
 */
#define PHCM_ERROR_INVALID_PARAMETER ((CHAR)-1)
#define PHCM_ERROR_NO_TEB ((CHAR)-2)

/**
 * The RtlQueryThreadPlaceholderCompatibilityMode routine returns the placeholder compatibility mode for the current
 * thread.
 *
 * \return CHAR The current thread placeholder compatibility mode.
 */
NTSYSAPI
CHAR
NTAPI
RtlQueryThreadPlaceholderCompatibilityMode(VOID);

/**
 * The RtlSetThreadPlaceholderCompatibilityMode routine sets the placeholder compatibility mode for the current thread.
 *
 * \param Mode The placeholder compatibility mode to set.
 * \return CHAR The previous thread placeholder compatibility mode.
 */
NTSYSAPI
CHAR
NTAPI
RtlSetThreadPlaceholderCompatibilityMode(
    _In_ CHAR Mode);

#endif

#undef PHCM_MAX
/**
 * Extended (thread-level) placeholder compatibility mode values.
 */
#define PHCM_DISGUISE_FULL_PLACEHOLDERS ((CHAR)3)
#define PHCM_MAX ((CHAR)3)
#define PHCM_ERROR_NO_PEB ((CHAR)-3)

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)

/**
 * The RtlQueryProcessPlaceholderCompatibilityMode routine returns the placeholder compatibility mode for the current
 * process.
 *
 * \return CHAR The current process placeholder compatibility mode.
 */
NTSYSAPI
CHAR
NTAPI
RtlQueryProcessPlaceholderCompatibilityMode(VOID);

/**
 * The RtlSetProcessPlaceholderCompatibilityMode routine sets the placeholder compatibility mode for the current
 * process.
 *
 * \param Mode The placeholder compatibility mode to set.
 * \return CHAR The previous process placeholder compatibility mode.
 */
NTSYSAPI
CHAR
NTAPI
RtlSetProcessPlaceholderCompatibilityMode(
    _In_ CHAR Mode);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
/**
 * The RtlIsNonEmptyDirectoryReparsePointAllowed routine determines whether a reparse point identified by the specified
 * tag is allowed on a non-empty directory.
 *
 * \param ReparseTag The reparse tag to test.
 * \return Returns `TRUE` if the reparse tag is allowed on a non-empty directory, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsNonEmptyDirectoryReparsePointAllowed(
    _In_ ULONG ReparseTag);
#endif

#pragma endregion

#pragma region AppX

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlAppxIsFileOwnedByTrustedInstaller routine determines whether the file referenced by a handle is owned by the
 * TrustedInstaller.
 *
 * \param FileHandle A handle to the file to test.
 * \param IsFileOwnedByTrustedInstaller A pointer to a variable that receives whether the file is owned by the
 * TrustedInstaller.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAppxIsFileOwnedByTrustedInstaller(
    _In_ HANDLE FileHandle,
    _Out_ PBOOLEAN IsFileOwnedByTrustedInstaller);
#endif

// Windows Internals book
/**
 * Package claim flags describing a packaged application activation token.
 */
#define PSM_ACTIVATION_TOKEN_PACKAGED_APPLICATION       0x00000001UL // AppX package format
#define PSM_ACTIVATION_TOKEN_SHARED_ENTITY              0x00000002UL // Shared token, multiple binaries in the same package
#define PSM_ACTIVATION_TOKEN_FULL_TRUST                 0x00000004UL // Trusted (Centennial), converted Win32 application
#define PSM_ACTIVATION_TOKEN_NATIVE_SERVICE             0x00000008UL // Packaged service created by SCM
//#define PSM_ACTIVATION_TOKEN_DEVELOPMENT_APP          0x00000010UL
/**
 * Additional package claim and activation token flags.
 */
#define PSM_ACTIVATION_TOKEN_MULTIPLE_INSTANCES_ALLOWED 0x00000010UL
#define PSM_ACTIVATION_TOKEN_BREAKAWAY_INHIBITED        0x00000020UL // Cannot create non-packaged child processes
#define PSM_ACTIVATION_TOKEN_RUNTIME_BROKER             0x00000040UL // rev
#define PSM_ACTIVATION_TOKEN_UNIVERSAL_CONSOLE          0x00000200UL // rev
#define PSM_ACTIVATION_TOKEN_WIN32ALACARTE_PROCESS      0x00010000UL // rev

// PackageOrigin appmodel.h
//#define PackageOrigin_Unknown           0
//#define PackageOrigin_Unsigned          1
//#define PackageOrigin_Inbox             2
//#define PackageOrigin_Store             3
//#define PackageOrigin_DeveloperUnsigned 4
//#define PackageOrigin_DeveloperSigned   5
//#define PackageOrigin_LineOfBusiness    6

/**
 * Constants describing minimum system application claim values.
 */
#define PSMP_MINIMUM_SYSAPP_CLAIM_VALUES 2
#define PSMP_MAXIMUM_SYSAPP_CLAIM_VALUES 4

/**
 * Describes the package claim (origin and flags) associated with a process.
 */
typedef struct _PS_PKG_CLAIM
{
    ULONG Flags;  // PSM_ACTIVATION_TOKEN_*
    ULONG Origin; // PackageOrigin
} PS_PKG_CLAIM, *PPS_PKG_CLAIM;

// private // WIN://BGKD
/**
 * Identifies the background activation type of a packaged application.
 */
typedef enum _PSM_ACTIVATE_BACKGROUND_TYPE
{
  PsmActNotBackground = 0,
  PsmActMixedHost = 1,
  PsmActPureHost = 2,
  PsmActSystemHost = 3,
  PsmActInvalidType = 4,
} PSM_ACTIVATE_BACKGROUND_TYPE;

#if (NTDDI_VERSION >= NTDDI_WIN10)
/**
 * The RtlQueryPackageClaims routine retrieves the package claims associated with a token, including the package full
 * name, application identifier, and attributes.
 *
 * \param TokenHandle A handle to the token to query.
 * \param PackageFullName An optional buffer that receives the package full name.
 * \param PackageSize An optional pointer to the size, in bytes, of the PackageFullName buffer; updated with the
 * required or written size.
 * \param AppId An optional buffer that receives the application identifier.
 * \param AppIdSize An optional pointer to the size, in bytes, of the AppId buffer; updated with the required or written
 * size.
 * \param DynamicId An optional pointer to a variable that receives the dynamic package identifier.
 * \param PkgClaim An optional pointer to a PS_PKG_CLAIM structure that receives the package claim.
 * \param AttributesPresent An optional pointer to a variable that receives the mask of attributes present.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPackageClaims(
    _In_ HANDLE TokenHandle,
    _Out_writes_bytes_to_opt_(*PackageSize, *PackageSize) PWSTR PackageFullName,
    _Inout_opt_ PSIZE_T PackageSize,
    _Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
    _Inout_opt_ PSIZE_T AppIdSize,
    _Out_opt_ PGUID DynamicId,
    _Out_opt_ PPS_PKG_CLAIM PkgClaim,
    _Out_opt_ PULONG64 AttributesPresent);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlQueryPackageIdentity routine retrieves the package identity associated with a token, including the package
 * full name and application identifier.
 *
 * \param TokenHandle A handle to the token to query.
 * \param PackageFullName A buffer that receives the package full name.
 * \param PackageSize A pointer to the size, in bytes, of the PackageFullName buffer; updated with the required or
 * written size.
 * \param AppId An optional buffer that receives the application identifier.
 * \param AppIdSize An optional pointer to the size, in bytes, of the AppId buffer; updated with the required or written
 * size.
 * \param Packaged An optional pointer to a variable that receives whether the token belongs to a packaged application.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPackageIdentity(
    _In_ HANDLE TokenHandle,
    _Out_writes_bytes_to_(*PackageSize, *PackageSize) PWSTR PackageFullName,
    _Inout_ PSIZE_T PackageSize,
    _Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
    _Inout_opt_ PSIZE_T AppIdSize,
    _Out_opt_ PBOOLEAN Packaged);
#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
/**
 * The RtlQueryPackageIdentityEx routine retrieves the package identity associated with a token, with additional dynamic
 * identifier and flag outputs.
 *
 * \param TokenHandle A handle to the token to query.
 * \param PackageFullName A buffer that receives the package full name.
 * \param PackageSize A pointer to the size, in bytes, of the PackageFullName buffer; updated with the required or
 * written size.
 * \param AppId An optional buffer that receives the application identifier.
 * \param AppIdSize An optional pointer to the size, in bytes, of the AppId buffer; updated with the required or written
 * size.
 * \param DynamicId An optional pointer to a variable that receives the dynamic package identifier.
 * \param Flags An optional pointer to a variable that receives package identity flags.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPackageIdentityEx(
    _In_ HANDLE TokenHandle,
    _Out_writes_bytes_to_(*PackageSize, *PackageSize) PWSTR PackageFullName,
    _Inout_ PSIZE_T PackageSize,
    _Out_writes_bytes_to_opt_(*AppIdSize, *AppIdSize) PWSTR AppId,
    _Inout_opt_ PSIZE_T AppIdSize,
    _Out_opt_ PGUID DynamicId,
    _Out_opt_ PULONG64 Flags);
#endif

#pragma endregion

#pragma region Wnf

#if (NTDDI_VERSION >= NTDDI_WIN10)

/**
 * Constant used to derive a WNF state name key.
 */
#define WNF_STATE_KEY 0x41C64E6DA3BC0074

/**
 * The RtlEqualWnfChangeStamps routine determines whether two WNF change stamps are equal.
 *
 * \param ChangeStamp1 The first WNF change stamp to compare.
 * \param ChangeStamp2 The second WNF change stamp to compare.
 * \return Returns `TRUE` if the change stamps are equal, otherwise `FALSE`.
 */
_Must_inspect_result_
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualWnfChangeStamps(
    _In_ WNF_CHANGE_STAMP ChangeStamp1,
    _In_ WNF_CHANGE_STAMP ChangeStamp2
);

_Always_(_Post_satisfies_(return == STATUS_NO_MEMORY || return == STATUS_RETRY || return == STATUS_SUCCESS))
typedef _Function_class_(WNF_USER_CALLBACK)
NTSTATUS NTAPI WNF_USER_CALLBACK(
    _In_ WNF_STATE_NAME StateName,
    _In_ WNF_CHANGE_STAMP ChangeStamp,
    _In_opt_ PWNF_TYPE_ID TypeId,
    _In_opt_ PVOID CallbackContext,
    _In_reads_bytes_opt_(Length) const VOID* Buffer,
    _In_ ULONG Length
);
/**
 * Pointer to a WNF_USER_CALLBACK callback.
 */
typedef WNF_USER_CALLBACK *PWNF_USER_CALLBACK;

/**
 * The RtlQueryWnfStateData routine retrieves the current data for a WNF state name via a user callback.
 *
 * \param ChangeStamp Receives the change stamp of the current state data.
 * \param StateName The WNF state name to query.
 * \param Callback The callback invoked with the current state data.
 * \param CallbackContext An optional context value passed to the callback.
 * \param TypeId An optional type identifier describing the state data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryWnfStateData(
    _Out_ PWNF_CHANGE_STAMP ChangeStamp,
    _In_ WNF_STATE_NAME StateName,
    _In_ PWNF_USER_CALLBACK Callback,
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PWNF_TYPE_ID TypeId
);

/**
 * The RtlPublishWnfStateData routine publishes new state data for a WNF state name.
 *
 * \param StateName The WNF state name to publish to.
 * \param TypeId An optional pointer to the type identifier that describes the data format.
 * \param Buffer An optional pointer to the buffer that contains the state data to publish.
 * \param Length The size, in bytes, of the data in Buffer.
 * \param ExplicitScope An optional pointer to the explicit scope in which to publish the data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlPublishWnfStateData(
    _In_ WNF_STATE_NAME StateName,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_reads_bytes_opt_(Length) const VOID * Buffer,
    _In_opt_ ULONG Length,
    _In_opt_ const VOID * ExplicitScope
);

/**
 * Pointer to an opaque WNF_USER_SUBSCRIPTION structure.
 */
typedef struct WNF_USER_SUBSCRIPTION *PWNF_USER_SUBSCRIPTION;

/**
 * Flag controlling WNF serialization group creation.
 */
#define WNF_CREATE_SERIALIZATION_GROUP_FLAG 0x00000001L

/**
 * The RtlSubscribeWnfStateChangeNotification routine subscribes to change notifications for a WNF state name.
 *
 * \param SubscriptionHandle Receives the subscription handle.
 * \param StateName The WNF state name to subscribe to.
 * \param ChangeStamp The change stamp from which to begin receiving notifications.
 * \param Callback The callback invoked when the state changes.
 * \param CallbackContext An optional context value passed to the callback.
 * \param TypeId An optional type identifier describing the state data.
 * \param SerializationGroup An optional serialization group for ordering callbacks.
 * \param Flags Flags controlling the subscription.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSubscribeWnfStateChangeNotification(
    _Out_ PWNF_USER_SUBSCRIPTION* SubscriptionHandle,
    _In_ WNF_STATE_NAME StateName,
    _In_ WNF_CHANGE_STAMP ChangeStamp,
    _In_ PWNF_USER_CALLBACK Callback,
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PCWNF_TYPE_ID TypeId,
    _In_opt_ ULONG SerializationGroup,
    _In_ ULONG Flags
);

/**
 * The RtlUnsubscribeWnfStateChangeNotification routine removes a WNF state change notification subscription.
 *
 * \param SubscriptionHandle A pointer to the user subscription to remove.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnsubscribeWnfStateChangeNotification(
    _In_ PWNF_USER_SUBSCRIPTION SubscriptionHandle
);

/**
 * The RtlWnfDllUnloadCallback routine cancels any WNF subscriptions owned by a module as it is unloaded.
 *
 * \param DllBase The base address of the module being unloaded.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlWnfDllUnloadCallback(
    _In_ PVOID DllBase
);

#endif

#pragma endregion

#pragma region Unload Event Trace

/**
 * Maximum number of module unload event trace records retained.
 */
#define RTL_UNLOAD_EVENT_TRACE_NUMBER 64

// private
/**
 * The RTL_UNLOAD_EVENT_TRACE structure contains information about modules unloaded by the current process.
 *
 * \sa https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetunloadeventtrace
 */
typedef struct _RTL_UNLOAD_EVENT_TRACE
{
    PVOID BaseAddress;   // Base address of dll
    SIZE_T SizeOfImage;  // Size of image
    ULONG Sequence;      // Sequence number for this event
    ULONG TimeDateStamp; // Time and date of image
    ULONG CheckSum;      // Image checksum
    WCHAR ImageName[32]; // Image name
    ULONG Version[2];
} RTL_UNLOAD_EVENT_TRACE, *PRTL_UNLOAD_EVENT_TRACE;

typedef struct _RTL_UNLOAD_EVENT_TRACE64
{
    VOID* POINTER_64 BaseAddress;
    ULONGLONG SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
    ULONG Version[2];
} RTL_UNLOAD_EVENT_TRACE64, *PRTL_UNLOAD_EVENT_TRACE64;

/**
 * 32-bit form of a module unload event trace record.
 */
typedef struct _RTL_UNLOAD_EVENT_TRACE32
{
    VOID* POINTER_32 BaseAddress;
    ULONG SizeOfImage;
    ULONG Sequence;
    ULONG TimeDateStamp;
    ULONG CheckSum;
    WCHAR ImageName[32];
    ULONG Version[2];
} RTL_UNLOAD_EVENT_TRACE32, *PRTL_UNLOAD_EVENT_TRACE32;

/**
 * The RtlGetUnloadEventTrace routine enables the dump code to get the unloaded module information from Ntdll.dll for storage in the minidump.
 *
 * \return A pointer to an array of unload events.
 * \sa https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetunloadeventtrace
 */
NTSYSAPI
PRTL_UNLOAD_EVENT_TRACE
NTAPI
RtlGetUnloadEventTrace(VOID);

/**
 * The RtlGetUnloadEventTraceEx routine retrieves the size and location of the dynamically unloaded module list for the current process.
 *
 * \param ElementSize A pointer to a variable that contains the size of an element in the list.
 * \param ElementCount A pointer to a variable that contains the number of elements in the list.
 * \param EventTrace A pointer to an array of RTL_UNLOAD_EVENT_TRACE structures.
 * \return A pointer to an array of unload events.
 * \sa https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetunloadeventtraceex
 */
NTSYSAPI
PRTL_UNLOAD_EVENT_TRACE
NTAPI
RtlGetUnloadEventTraceEx(
    _Out_ PULONG * ElementSize,
    _Out_ PULONG * ElementCount,
    _Out_ PVOID * EventTrace // works across all processes
);

#pragma endregion

#pragma region State Isolation

/**
 * Identifies whether a state location resides in the registry or the file system.
 */
typedef enum _STATE_LOCATION_TYPE
{
    LocationTypeRegistry,
    LocationTypeFileSystem,
    LocationTypeMaximum
} STATE_LOCATION_TYPE, *PSTATE_LOCATION_TYPE;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)

/**
 * The RtlIsStateSeparationEnabled routine determines whether OS state separation is enabled on the current system.
 *
 * \return Returns `TRUE` if state separation is enabled, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsStateSeparationEnabled(VOID);

/**
 * The RtlGetPersistedStateLocation routine resolves the persisted state storage location for a source identifier.
 *
 * \param SourceID A pointer to the null-terminated source identifier.
 * \param CustomValue An optional pointer to a custom value that refines the location.
 * \param DefaultPath An optional pointer to a default path used when no persisted location is configured.
 * \param StateLocationType The STATE_LOCATION_TYPE that selects the class of location to resolve.
 * \param TargetPath An optional buffer that receives the resolved location path.
 * \param BufferLengthIn The size, in bytes, of the TargetPath buffer.
 * \param BufferLengthOut An optional pointer to a variable that receives the required or written length, in bytes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetPersistedStateLocation(
    _In_ PCWSTR SourceID,
    _In_opt_ PCWSTR CustomValue,
    _In_opt_ PCWSTR DefaultPath,
    _In_ STATE_LOCATION_TYPE StateLocationType,
    _Out_writes_bytes_to_opt_(BufferLengthIn, *BufferLengthOut) PWCHAR TargetPath,
    _In_ ULONG BufferLengthIn,
    _Out_opt_ PULONG BufferLengthOut);

#endif

#pragma region Property Store

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)

/**
 * The RtlQueryPropertyStore routine retrieves the value associated with a key in the process property store.
 *
 * \param Key The key whose value is retrieved.
 * \param Context A pointer to a variable that receives the value associated with the key.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryPropertyStore(
    _In_ ULONG_PTR Key,
    _Out_ PULONG_PTR Context);

/**
 * The RtlRemovePropertyStore routine removes a key and its value from the process property store.
 *
 * \param Key The key to remove.
 * \param Context A pointer to a variable that receives the value that was associated with the key.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRemovePropertyStore(
    _In_ ULONG_PTR Key,
    _Out_ PULONG_PTR Context);

/**
 * The RtlCompareExchangePropertyStore routine atomically compares and exchanges the value associated with a key in the
 * process property store.
 *
 * \param Key The key whose value is exchanged.
 * \param Comperand A pointer to the value that the current value is compared against.
 * \param Exchange An optional pointer to the value to store if the comparison succeeds.
 * \param Context A pointer to a variable that receives the previous value associated with the key.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCompareExchangePropertyStore(
    _In_ ULONG_PTR Key,
    _In_ PULONG_PTR Comperand,
    _In_opt_ PULONG_PTR Exchange,
    _Out_ PULONG_PTR Context);

#endif

#pragma endregion

#pragma region Thread Pool (Old)

/**
 * The RtlRegisterWait routine directs a wait thread in the thread pool to wait on the object.
 *
 * \param WaitHandle A pointer to a variable that receives a wait handle on return.
 * Note that a wait handle cannot be used in functions that require an object handle.
 * \param Handle A handle to the object. If this handle is closed while the wait is
 * still pending, the function's behavior is undefined. The handle must have SYNCHRONIZE access.
 * \param Function A pointer to the callback routine invoked when the object is signaled or the wait times out.
 * \param Context Optional value that is passed to the callback function.
 * \param Milliseconds The time-out interval, in milliseconds.
 * \param Flags Flags that control the behavior of the wait handle.
 * \return NTSTATUS Successful or errant status.
 * \remarks The wait thread queues the specified callback function to the thread pool
 * when the specified object is in the signaled state or the time-out interval elapses.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerwaitforsingleobject
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRegisterWait(
    _Out_ PHANDLE WaitHandle,
    _In_ HANDLE Handle,
    _In_ WAITORTIMERCALLBACKFUNC Function,
    _In_opt_ PVOID Context,
    _In_ ULONG Milliseconds,
    _In_ ULONG Flags);

/**
 * The RtlDeregisterWait routine cancels a registered wait operation issued by the RtlRegisterWait function.
 *
 * \param WaitHandle The wait handle
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-unregisterwait
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeregisterWait(
    _In_ HANDLE WaitHandle);

/**
 * Flag requesting that wait deregistration block until pending callbacks complete.
 */
#define RTL_WAITER_DEREGISTER_WAIT_FOR_COMPLETION ((HANDLE)(LONG_PTR)-1)

/**
 * Releases all resources used by a wait object.
 *
 * @param WaitHandle The access mask that specifies the granted access rights.
 * @param CompletionEvent Optional completion event for wait callback completion.
 * @remarks RTL_WAITER_DEREGISTER_WAIT_FOR_COMPLETION: blocking wait for wait callback completion.
 * NULL: non-blocking wait for wait callback completion.
 * EventHandle: caller wait for wait callback completion.
 * @return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDeregisterWaitEx(
    _In_ HANDLE WaitHandle,
    _In_opt_ HANDLE CompletionEvent // optional: RTL_WAITER_DEREGISTER_WAIT_FOR_COMPLETION
);

// WORKERCALLBACKFUNC
typedef _Function_class_(RTL_WORK_CALLBACK)
VOID NTAPI RTL_WORK_CALLBACK(
    _In_ PVOID ThreadParameter
    );
/**
 * Pointer to an RTL_WORK_CALLBACK callback.
 */
typedef RTL_WORK_CALLBACK* PRTL_WORK_CALLBACK;

/**
 * The RtlQueueWorkItem routine queues a work item for execution by a thread-pool worker thread.
 *
 * \param Function The callback to execute.
 * \param Context An optional context value passed to the callback.
 * \param Flags Flags controlling execution (for example, WT_EXECUTELONGFUNCTION).
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueueWorkItem(
    _In_ PRTL_WORK_CALLBACK Function,
    _In_opt_ PVOID Context,
    _In_ ULONG Flags);

// APC_CALLBACK_FUNCTION
typedef _Function_class_(RTL_OVERLAPPED_COMPLETION_ROUTINE)
VOID NTAPI RTL_OVERLAPPED_COMPLETION_ROUTINE(
    _In_ NTSTATUS StatusCode,
    _In_ PVOID Context1,
    _In_ PVOID Context2
    );
/**
 * Pointer to an RTL_OVERLAPPED_COMPLETION_ROUTINE callback.
 */
typedef RTL_OVERLAPPED_COMPLETION_ROUTINE* PRTL_OVERLAPPED_COMPLETION_ROUTINE;

/**
 * Associates the I/O completion port owned by the thread pool with the specified file handle.
 * On completion of an I/O request involving this file, a non-I/O worker thread will execute the specified callback function.
 *
 * \param FileHandle A handle to the file or device for which to set the I/O completion callback.
 * \param Function A pointer to the callback function to be executed when an I/O operation completes.
 * \param Flags Reserved; must be zero.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-bindiocompletioncallback
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetIoCompletionCallback(
    _In_ HANDLE FileHandle,
    _In_ PRTL_OVERLAPPED_COMPLETION_ROUTINE Function,
    _In_ ULONG Flags);

typedef
_Function_class_(RTL_START_POOL_THREAD)
NTSTATUS
NTAPI
RTL_START_POOL_THREAD(
/**
 * Pointer to an RTL_START_POOL_THREAD callback.
 */
    _In_ PUSER_THREAD_START_ROUTINE Function,
    _In_ PVOID Parameter,
    _Out_ PHANDLE ThreadHandle);
typedef RTL_START_POOL_THREAD *PRTL_START_POOL_THREAD;

typedef
_Function_class_(RTL_EXIT_POOL_THREAD)
NTSTATUS
NTAPI
RTL_EXIT_POOL_THREAD(
/**
 * Pointer to an RTL_EXIT_POOL_THREAD callback.
 */
    _In_ NTSTATUS ExitStatus);
typedef RTL_EXIT_POOL_THREAD *PRTL_EXIT_POOL_THREAD;

/**
 * The RtlSetThreadPoolStartFunc routine registers the callbacks used to start and exit worker threads in the RTL thread
 * pool.
 *
 * \param StartPoolThread A pointer to the routine that starts a pool thread.
 * \param ExitPoolThread A pointer to the routine that exits a pool thread.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetThreadPoolStartFunc(
    _In_ PRTL_START_POOL_THREAD StartPoolThread,
    _In_ PRTL_EXIT_POOL_THREAD ExitPoolThread);

#pragma endregion

/**
 * Revision number of the import table hashing scheme.
 */
#define RTL_IMPORT_TABLE_HASH_REVISION 1

/**
 * The RtlComputeImportTableHash routine computes a hash of the import table of the image referenced by the specified
 * file handle.
 *
 * \param FileHandle A handle to the image file whose import table is hashed.
 * \param Hash A buffer that receives the 16-byte computed hash.
 * \param ImportTableHashRevision The import table hash revision. This value must be 1.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlComputeImportTableHash(
    _In_ HANDLE FileHandle,
    _Out_writes_bytes_(16) PUCHAR Hash,
    _In_ ULONG ImportTableHashRevision);

/**
 * The RtlComputeCrc32 routine computes the CRC32 checksum for a buffer, allowing for incremental computation by providing a partial CRC value.
 *
 * \param PartialCrc The initial CRC32 value. Use 0 for a new computation, or the result of a previous call to continue CRC calculation over additional data.
 * \param Buffer Pointer to the buffer containing the data to compute the CRC32 for.
 * \param Length The length, in bytes, of the buffer.
 * \return The computed CRC32 value.
 */
NTSYSAPI
ULONG32
NTAPI
RtlComputeCrc32(
    _In_ ULONG32 PartialCrc,
    _In_ PVOID Buffer,
    _In_ ULONG Length);

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)
NTSYSAPI
ULONG_PTR
NTAPI
RtlGetReturnAddressHijackTarget(VOID);
#endif


// RtlCancelTimer
/**
 * The RtlCancelTimer routine cancels a timer previously created in a timer queue.
 *
 * \param TimerQueueHandle A handle to the timer queue that owns the timer.
 * \param Handle A handle to the timer to cancel.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCancelTimer(
    _In_ HANDLE TimerQueueHandle,
    _In_ HANDLE Handle
    );

// RtlAllocateWnfSerializationGroup
/**
 * The RtlAllocateWnfSerializationGroup routine allocates a WNF serialization group used to order state change
 * notifications.
 *
 * \return ULONG The identifier of the allocated WNF serialization group.
 */
NTSYSAPI
ULONG
NTAPI
RtlAllocateWnfSerializationGroup(
    VOID
    );

// RtlQueryWnfMetaNotification
/**
 * The RtlQueryWnfMetaNotification routine queries meta-notification information for a WNF state name.
 *
 * \param Result A pointer to a variable that receives the query result.
 * \param NameInfoClass The WNF_STATE_NAME_INFORMATION class that selects the information to query.
 * \param StateName The WNF state name to query.
 * \param ExplicitScope An optional pointer to the explicit scope SID for the query.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryWnfMetaNotification(
    _Out_ PULONG Result,
    _In_ WNF_STATE_NAME_INFORMATION NameInfoClass,
    _In_ WNF_STATE_NAME StateName,
    _In_opt_ PCSID ExplicitScope
    );

// RtlQueryWnfStateDataWithExplicitScope
/**
 * The RtlQueryWnfStateDataWithExplicitScope routine retrieves the state data for a WNF state name within an explicit
 * scope, decoding it with a caller-supplied type decoder.
 *
 * \param ChangeStamp A pointer to a variable that receives the change stamp of the returned data.
 * \param StateName The WNF state name to query.
 * \param ExplicitScope An optional pointer to the explicit scope for the query.
 * \param TypeDecoder A pointer to a callback that decodes the raw state data into the caller's buffer.
 * \param CallbackContext A caller-defined value passed to the type decoder callback.
 * \param TypeId An optional pointer to the type identifier that describes the data format.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryWnfStateDataWithExplicitScope(
    _Out_ PWNF_CHANGE_STAMP ChangeStamp,
    _In_ WNF_STATE_NAME StateName,
    _In_opt_ const VOID *ExplicitScope,
    _In_ PWNF_USER_CALLBACK TypeDecoder,
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PCWNF_TYPE_ID TypeId
    );

// RtlUnsubscribeWnfNotificationWaitForCompletion
/**
 * The RtlUnsubscribeWnfNotificationWaitForCompletion routine removes a WNF notification subscription and waits for any
 * in-progress callbacks to complete.
 *
 * \param SubscriptionHandle A handle to the WNF notification subscription to remove.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnsubscribeWnfNotificationWaitForCompletion(
    _In_ HANDLE SubscriptionHandle
    );

// RtlUnsubscribeWnfNotificationWithCompletionCallback
/**
 * The RtlUnsubscribeWnfNotificationWithCompletionCallback routine cancels a WNF subscription and invokes a completion
 * callback once cancellation finishes.
 *
 * \param SubscriptionHandle The subscription handle to cancel.
 * \param CompletionCallback An optional callback invoked when cancellation completes.
 * \param CompletionContext An optional context value passed to the completion callback.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnsubscribeWnfNotificationWithCompletionCallback(
    _In_ HANDLE SubscriptionHandle,
    _In_opt_ PVOID CompletionCallback,
    _In_opt_ PVOID CompletionContext
    );
EXTERN_C_END
