#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* phnt */

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlCheckTokenCapability routine determines whether a token has the specified capability, identified by its SID.
 *
 * \param TokenHandle An optional handle to the token to test; if NULL, the token of the current thread or process is
 * used.
 * \param CapabilitySidToCheck A pointer to the capability SID to check.
 * \param HasCapability A pointer to a variable that receives whether the token has the capability.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckTokenCapability(
    _In_opt_ HANDLE TokenHandle,
    _In_ PSID CapabilitySidToCheck,
    _Out_ PBOOLEAN HasCapability);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10)
/**
 * The RtlCapabilityCheck routine determines whether a token has the capability identified by name.
 *
 * \param TokenHandle An optional handle to the token to test; if NULL, the token of the current thread or process is
 * used.
 * \param CapabilityName A pointer to the Unicode string that names the capability to check.
 * \param HasCapability A pointer to a variable that receives whether the token has the capability.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCapabilityCheck(
    _In_opt_ HANDLE TokenHandle,
    _In_ PUNICODE_STRING CapabilityName,
    _Out_ PBOOLEAN HasCapability);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlGetAppContainerNamedObjectPath routine retrieves the named object path for an app container.
 *
 * \param TokenHandle An optional handle to the app container token.
 * \param AppContainerSid An optional pointer to the app container SID.
 * \param RelativePath If `TRUE`, the returned path is relative to the app container root; otherwise it is absolute.
 * \param ObjectPath A pointer to a UNICODE_STRING that receives the object path. The caller frees it with
 * RtlFreeUnicodeString.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetAppContainerNamedObjectPath(
    _In_opt_ HANDLE TokenHandle,
    _In_opt_ PSID AppContainerSid,
    _In_ BOOLEAN RelativePath,
    _Out_ PUNICODE_STRING ObjectPath // RtlFreeUnicodeString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
/**
 * The RtlGetAppContainerParent routine retrieves the parent app container SID of the specified app container SID.
 *
 * \param AppContainerSid A pointer to the child app container SID.
 * \param AppContainerSidParent A pointer to a variable that receives the parent app container SID. The caller frees it
 * with RtlFreeSid.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetAppContainerParent(
    _In_ PSID AppContainerSid,
    _Out_ PSID* AppContainerSidParent // RtlFreeSid
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10)
/**
 * The RtlCheckSandboxedToken routine determines whether the specified token is sandboxed.
 *
 * \param TokenHandle An optional handle to the token to test; if NULL, the token of the current thread or process is
 * used.
 * \param IsSandboxed A pointer to a variable that receives whether the token is sandboxed.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCheckSandboxedToken(
    _In_opt_ HANDLE TokenHandle,
    _Out_ PBOOLEAN IsSandboxed);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)
/**
 * The RtlQueryTokenHostIdAsUlong64 routine retrieves the package host identifier associated with a token as a 64-bit
 * value.
 *
 * \param TokenHandle A handle to the token to query.
 * \param HostId A pointer to a variable that receives the package host identifier (WIN://PKGHOSTID).
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryTokenHostIdAsUlong64(
    _In_ HANDLE TokenHandle,
    _Out_ PULONG64 HostId // (WIN://PKGHOSTID)
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
/**
 * The RtlIsParentOfChildAppContainer routine determines whether one app container SID is the parent of another.
 *
 * \param ParentAppContainerSid A pointer to the candidate parent app container SID.
 * \param ChildAppContainerSid A pointer to the candidate child app container SID.
 * \return Returns `TRUE` if the first SID is the parent of the second, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsParentOfChildAppContainer(
    _In_ PSID ParentAppContainerSid,
    _In_ PSID ChildAppContainerSid);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)

/**
 * The RtlIsCapabilitySid routine determines whether the specified SID is a capability SID.
 *
 * \param Sid A pointer to the SID to test.
 * \return Returns `TRUE` if the SID is a capability SID, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsCapabilitySid(
    _In_ PSID Sid);

/**
 * The RtlIsPackageSid routine determines whether the specified SID is a package (app container) SID.
 *
 * \param Sid A pointer to the SID to test.
 * \return Returns `TRUE` if the SID is a package SID, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsPackageSid(
    _In_ PSID Sid);

#endif

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
/**
 * The RtlIsValidProcessTrustLabelSid routine determines whether the specified SID is a valid process trust label SID.
 *
 * \param Sid A pointer to the SID to test.
 * \return Returns `TRUE` if the SID is a valid process trust label SID, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsValidProcessTrustLabelSid(
    _In_ PSID Sid);
#endif

/**
 * Identifies the type of an AppContainer security identifier.
 */
typedef enum _APPCONTAINER_SID_TYPE
{
    NotAppContainerSidType,
    ChildAppContainerSidType,
    ParentAppContainerSidType,
    InvalidAppContainerSidType,
    MaxAppContainerSidType
} APPCONTAINER_SID_TYPE, *PAPPCONTAINER_SID_TYPE;

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
/**
 * The RtlGetAppContainerSidType routine returns the type classification of an app container SID.
 *
 * \param AppContainerSid A pointer to the app container SID to classify.
 * \param AppContainerSidType A pointer to a variable that receives the APPCONTAINER_SID_TYPE value.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetAppContainerSidType(
    _In_ PSID AppContainerSid,
    _Out_ PAPPCONTAINER_SID_TYPE AppContainerSidType);
#endif


// RtlCapabilityCheckForSingleSessionSku
/**
 * The RtlCapabilityCheckForSingleSessionSku routine determines whether a token holds the specified capability on a
 * single-session SKU.
 *
 * \param TokenHandle A handle to the access token to inspect.
 * \param CapabilityName The name of the capability to check.
 * \param IsCapable Receives TRUE if the token has the capability.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCapabilityCheckForSingleSessionSku(
    _In_ PVOID TokenHandle,
    _In_ PCUNICODE_STRING CapabilityName,
    _Out_ PBOOLEAN IsCapable
    );
EXTERN_C_END
