#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * The RtlImpersonateSelf routine begins impersonation of the security context of the calling process on the current
 * thread.
 *
 * \param ImpersonationLevel The SECURITY_IMPERSONATION_LEVEL at which to impersonate.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlImpersonateSelf(
    _In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

/**
 * The RtlImpersonateSelfEx routine begins impersonation of the calling process's security context on the current
 * thread, with additional access and an optional returned token.
 *
 * \param ImpersonationLevel The SECURITY_IMPERSONATION_LEVEL at which to impersonate.
 * \param AdditionalAccess An optional additional access mask to request on the impersonation token.
 * \param ThreadToken An optional pointer to a variable that receives a handle to the impersonation token.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlImpersonateSelfEx(
    _In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    _In_opt_ ACCESS_MASK AdditionalAccess,
    _Out_opt_ PHANDLE ThreadToken);

/**
 * The RtlAdjustPrivilege routine enables or disables a privilege in the token of the current thread or process.
 *
 * \param Privilege The identifier of the privilege to adjust.
 * \param Enable If `TRUE`, the privilege is enabled; if `FALSE`, it is disabled.
 * \param Client If `TRUE`, the privilege is adjusted in the current thread's impersonation token; otherwise in the
 * process token.
 * \param WasEnabled A pointer to a variable that receives the previous enabled state of the privilege.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAdjustPrivilege(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled);

/**
 * Flags for RtlAcquirePrivilege.
 */
#define RTL_ACQUIRE_PRIVILEGE_REVERT 0x00000001
#define RTL_ACQUIRE_PRIVILEGE_PROCESS 0x00000002

/**
 * The RtlAcquirePrivilege routine temporarily enables one or more privileges on the current thread.
 *
 * \param Privilege An array of privilege identifiers to enable.
 * \param NumPriv The number of privileges in the array.
 * \param Flags Flags controlling how the privileges are acquired.
 * \param ReturnedState Receives an opaque state pointer to pass to RtlReleasePrivilege.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAcquirePrivilege(
    _In_ PULONG Privilege,
    _In_ ULONG NumPriv,
    _In_ ULONG Flags,
    _Out_ PVOID* ReturnedState);

/**
 * The RtlReleasePrivilege routine restores privileges previously enabled with RtlAcquirePrivilege.
 *
 * \param StatePointer The state pointer returned by RtlAcquirePrivilege.
 */
NTSYSAPI
VOID
NTAPI
RtlReleasePrivilege(
    _In_ PVOID StatePointer);

/**
 * The RtlRemovePrivileges routine removes from a token all privileges except those in a caller-supplied keep list.
 *
 * \param TokenHandle A handle to the token from which privileges are removed.
 * \param PrivilegesToKeep A pointer to an array of privilege identifiers to retain.
 * \param PrivilegeCount The number of entries in the PrivilegesToKeep array.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRemovePrivileges(
    _In_ HANDLE TokenHandle,
    _In_ PULONG PrivilegesToKeep,
    _In_ ULONG PrivilegeCount);

#if (NTDDI_VERSION >= NTDDI_WIN8)

/**
 * The RtlCheckTokenMembership routine determines whether a specified SID is enabled in the given token.
 *
 * \param TokenHandle An optional handle to an impersonation token; if NULL, the token of the current thread is used.
 * \param SidToCheck A pointer to the SID whose membership is checked.
 * \param IsMember A pointer to a variable that receives whether the SID is enabled in the token.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckTokenMembership(
    _In_opt_ HANDLE TokenHandle,
    _In_ PSID SidToCheck,
    _Out_ PBOOLEAN IsMember);

// RtlCheckTokenMembershipEx Flags
#define CTMF_INCLUDE_APPCONTAINER 0x00000001UL
#define CTMF_INCLUDE_LPAC 0x00000002UL
#define CTMF_VALID_FLAGS (CTMF_INCLUDE_APPCONTAINER | CTMF_INCLUDE_LPAC)

/**
 * The RtlCheckTokenMembershipEx routine determines whether a specified SID is enabled in the given token, with control
 * over the evaluation flags.
 *
 * \param TokenHandle An optional handle to the token to test; if NULL, the token of the current thread is used.
 * \param SidToCheck A pointer to the SID whose membership is checked.
 * \param Flags A combination of CTMF_ flags that control how membership is evaluated.
 * \param IsMember A pointer to a variable that receives whether the SID is enabled in the token.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckTokenMembershipEx(
    _In_opt_ HANDLE TokenHandle,
    _In_ PSID SidToCheck,
    _In_ ULONG Flags, // CTMF_VALID_FLAGS
    _Out_ PBOOLEAN IsMember);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
/**
 * The RtlGetTokenNamedObjectPath routine retrieves the named object path associated with a token.
 *
 * \param TokenHandle A handle to the token to query.
 * \param Sid An optional pointer to a SID used to compute the object path.
 * \param ObjectPath A pointer to a UNICODE_STRING that receives the object path. The caller frees it with
 * RtlFreeUnicodeString.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetTokenNamedObjectPath(
    _In_ HANDLE TokenHandle,
    _In_opt_ PSID Sid,
    _Out_ PUNICODE_STRING ObjectPath // RtlFreeUnicodeString
);
#endif

EXTERN_C_END
