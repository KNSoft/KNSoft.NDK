/*
 * Component-Based Servicing private core exports.
 */

#pragma once

#include "CbsApi.h"

EXTERN_C_START

#ifndef CBSCOREAPI
#define CBSCOREAPI DECLSPEC_IMPORT
#endif

#define CBS_CORE_STARTUP_OPTION_UNKNOWN1 0x1
#define CBS_CORE_STARTUP_OPTION_RECOVERY 0x2
#define CBS_CORE_STARTUP_OPTION_SAFE_MODE 0x4

typedef enum _CBS_CORE_STATE
{
    CbsCoreStateRequireRebootCallback = 0,
    CbsCoreStateRevokeShutdownProcessing = 1,
    CbsCoreStateUnknown2 = 2,
    CbsCoreStateIsRebootRequiredCallback = 3,
    CbsCoreStateAnticipateShutdownProcessingNeeded = 4,
    CbsCoreStateRegisterWinlogonNotification = 5,
    CbsCoreStateUnregisterWinlogonNotification = 6,
    CbsCoreStateFinalizeExecutionEngine = 7,
    CbsCoreStateSetOnline = 8,
    CbsCoreStateTrustedInstallerNotifyAllPendedOperationsCanceled = 9,
    CbsCoreStateWaitForOutstandingSessions = 10
} CBS_CORE_STATE, *PCBS_CORE_STATE;

typedef enum _CBS_SESSION_NOTIFICATION
{
    CbsSessionNotificationAllowLogon = 1,
    CbsSessionNotificationWait = 2,
    CbsSessionNotificationWaitWithMessage = 3,
    CbsSessionNotificationRestart = 4
} CBS_SESSION_NOTIFICATION, *PCBS_SESSION_NOTIFICATION;

typedef
HRESULT
(WINAPI *PCBS_CORE_LOCK_PROCESS_CALLBACK)(
    _In_ ULONG Options);

typedef
VOID
(WINAPI *PCBS_CORE_CALLBACK)(
    VOID);

typedef
BOOL
(WINAPI *PCBS_CORE_IS_REBOOT_REQUIRED_CALLBACK)(
    VOID);

typedef
HRESULT
(WINAPI *PCBS_CORE_ANTICIPATE_SHUTDOWN_PROCESSING_CALLBACK)(
    VOID);

typedef
VOID
(WINAPI *PCBS_CORE_UNREGISTER_WINLOGON_NOTIFICATION_CALLBACK)(
    _In_ ULONG Value);

typedef
VOID
(WINAPI *PCBS_CORE_LOG_CALLBACK)(
    _In_ ULONG Level,
    _In_ PCSTR Message);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreEnsureNoStartupProcessing(
    _In_ BOOL SafeMode);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreFinalizeShutdownProcessing(
    VOID);

CBSCOREAPI
HRESULT
WINAPI
CbsCorePrepareShutdownProcessing(
    _In_ ITrustedInstallerService* Service,
    _In_ ULONG Options);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreServiceIdleProcessing(
    _In_ BOOL Enable,
    _Out_ PBOOL Completed);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreShutdownProcessing(
    _In_ ITrustedInstallerService* Service,
    _In_ BOOL SafeMode);

CBSCOREAPI
HRESULT
WINAPI
CbsCreateSessionNotify(
    _In_ ITrustedInstallerService* Service,
    _In_ ULONG Options,
    _Out_ CBS_SESSION_NOTIFICATION* Notification,
    _Outptr_result_maybenull_ PWSTR* ProgressMessage);

CBSCOREAPI
HRESULT
WINAPI
CbsCreateSessionNotifyFinalize(
    VOID);

CBSCOREAPI
HRESULT
WINAPI
CbsCreateSessionNotifyInitialize(
    VOID);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreFinalize(
    VOID);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreGetActiveOfflineSession(
    _Outptr_ ICbsSession** Session);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreInitialize(
    _In_ IMalloc* Allocator,
    _In_ PCBS_CORE_LOCK_PROCESS_CALLBACK LockProcess,
    _In_ PCBS_CORE_CALLBACK UnlockProcess,
    _In_ PCBS_CORE_CALLBACK InstanceCreated,
    _In_ PCBS_CORE_CALLBACK InstanceDestroyed,
    _In_opt_ PCBS_CORE_CALLBACK RequireShutdownNow,
    _In_ PCBS_CORE_CALLBACK RequireShutdownProcessing,
    _Outptr_ IClassFactory** ClassFactory);

CBSCOREAPI
BOOL
WINAPI
CbsCoreIsExecutionEngineIdle(
    VOID);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreLoadComponentStore(
    VOID);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreNotifyAllowingUserLogin(
    VOID);

CBSCOREAPI
VOID
WINAPI
CbsCoreSetCustomLogging(
    _In_opt_ PCBS_CORE_LOG_CALLBACK Callback);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreSetState(
    _In_ CBS_CORE_STATE State,
    _In_ ULONG_PTR Value);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreStartupProcessing(
    _In_ BOOL SafeMode);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreStartupProcessingEx(
    _In_ UINT Options);

CBSCOREAPI
HRESULT
WINAPI
CbsCoreStopIdleProcessing(
    VOID);

CBSCOREAPI
HRESULT
WINAPI
CreateCbsRegBackupHelper(
    _Outptr_ ICbsRegBackupHelper** Helper);

CBSCOREAPI
HRESULT
WINAPI
SetRebootInProgressFlag(
    VOID);

CBSCOREAPI
VOID
WINAPI
SetTestMode(
    _In_ BOOL Enabled);

EXTERN_C_END
