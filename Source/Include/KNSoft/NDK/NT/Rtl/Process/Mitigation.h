#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Identifies an image mitigation policy category.
 */
typedef enum _IMAGE_MITIGATION_POLICY
{
    ImageDepPolicy, // RTL_IMAGE_MITIGATION_DEP_POLICY
    ImageAslrPolicy, // RTL_IMAGE_MITIGATION_ASLR_POLICY
    ImageDynamicCodePolicy, // RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY
    ImageStrictHandleCheckPolicy, // RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY
    ImageSystemCallDisablePolicy, // RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
    ImageMitigationOptionsMask,
    ImageExtensionPointDisablePolicy, // RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
    ImageControlFlowGuardPolicy, // RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY
    ImageSignaturePolicy, // RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY
    ImageFontDisablePolicy, // RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY
    ImageImageLoadPolicy, // RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY
    ImagePayloadRestrictionPolicy, // RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY
    ImageChildProcessPolicy, // RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY
    ImageSehopPolicy, // RTL_IMAGE_MITIGATION_SEHOP_POLICY
    ImageHeapPolicy, // RTL_IMAGE_MITIGATION_HEAP_POLICY
    ImageUserShadowStackPolicy, // RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY
    ImageRedirectionTrustPolicy, // RTL_IMAGE_MITIGATION_REDIRECTION_TRUST_POLICY
    ImageUserPointerAuthPolicy, // RTL_IMAGE_MITIGATION_USER_POINTER_AUTH_POLICY
    MaxImageMitigationPolicy
} IMAGE_MITIGATION_POLICY;

// rev
/**
 * Describes the state of an image mitigation policy option.
 */
typedef union _RTL_IMAGE_MITIGATION_POLICY
{
    struct
    {
        ULONG64 AuditState : 2;
        ULONG64 AuditFlag : 1;
        ULONG64 EnableAdditionalAuditingOption : 1;
        ULONG64 Reserved : 60;
    };
    struct
    {
        ULONG64 PolicyState : 2;
        ULONG64 AlwaysInherit : 1;
        ULONG64 EnableAdditionalPolicyOption : 1;
        ULONG64 AuditReserved : 60;
    };
} RTL_IMAGE_MITIGATION_POLICY, *PRTL_IMAGE_MITIGATION_POLICY;

// rev
/**
 * Describes the Data Execution Prevention (DEP) mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_DEP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY Dep;
} RTL_IMAGE_MITIGATION_DEP_POLICY, *PRTL_IMAGE_MITIGATION_DEP_POLICY;

// rev
/**
 * Describes the Address Space Layout Randomization (ASLR) mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_ASLR_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY ForceRelocateImages;
    RTL_IMAGE_MITIGATION_POLICY BottomUpRandomization;
    RTL_IMAGE_MITIGATION_POLICY HighEntropyRandomization;
} RTL_IMAGE_MITIGATION_ASLR_POLICY, *PRTL_IMAGE_MITIGATION_ASLR_POLICY;

// rev
/**
 * Describes the dynamic code mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockDynamicCode;
} RTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY, *PRTL_IMAGE_MITIGATION_DYNAMIC_CODE_POLICY;

// rev
/**
 * Describes the strict handle-check mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY StrictHandleChecks;
} RTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY, *PRTL_IMAGE_MITIGATION_STRICT_HANDLE_CHECK_POLICY;

// rev
/**
 * Describes the system-call-disable mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockWin32kSystemCalls;
} RTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY, *PRTL_IMAGE_MITIGATION_SYSTEM_CALL_DISABLE_POLICY;

// rev
/**
 * Describes the extension-point-disable mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisableExtensionPoints;
} RTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, *PRTL_IMAGE_MITIGATION_EXTENSION_POINT_DISABLE_POLICY;

// rev
/**
 * Describes the Control Flow Guard (CFG) mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY ControlFlowGuard;
    RTL_IMAGE_MITIGATION_POLICY StrictControlFlowGuard;
} RTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY, *PRTL_IMAGE_MITIGATION_CONTROL_FLOW_GUARD_POLICY;

// rev
/**
 * Describes the binary signature (code integrity) mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockNonMicrosoftSignedBinaries;
    RTL_IMAGE_MITIGATION_POLICY EnforceSigningOnModuleDependencies;
} RTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY, *PRTL_IMAGE_MITIGATION_BINARY_SIGNATURE_POLICY;

// rev
/**
 * Describes the font-disable mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisableNonSystemFonts;
} RTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY, *PRTL_IMAGE_MITIGATION_FONT_DISABLE_POLICY;

// rev
/**
 * Describes the image-load mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockRemoteImageLoads;
    RTL_IMAGE_MITIGATION_POLICY BlockLowLabelImageLoads;
    RTL_IMAGE_MITIGATION_POLICY PreferSystem32;
} RTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY, *PRTL_IMAGE_MITIGATION_IMAGE_LOAD_POLICY;

// rev
/**
 * Describes the payload restriction mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY EnableExportAddressFilter;
    RTL_IMAGE_MITIGATION_POLICY EnableExportAddressFilterPlus;
    RTL_IMAGE_MITIGATION_POLICY EnableImportAddressFilter;
    RTL_IMAGE_MITIGATION_POLICY EnableRopStackPivot;
    RTL_IMAGE_MITIGATION_POLICY EnableRopCallerCheck;
    RTL_IMAGE_MITIGATION_POLICY EnableRopSimExec;
    WCHAR EafPlusModuleList[512]; // 19H1
} RTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY, *PRTL_IMAGE_MITIGATION_PAYLOAD_RESTRICTION_POLICY;

// rev
/**
 * Describes the child-process creation mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY DisallowChildProcessCreation;
} RTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY, *PRTL_IMAGE_MITIGATION_CHILD_PROCESS_POLICY;

// rev
/**
 * Describes the Structured Exception Handling Overwrite Protection (SEHOP) mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_SEHOP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY Sehop;
} RTL_IMAGE_MITIGATION_SEHOP_POLICY, *PRTL_IMAGE_MITIGATION_SEHOP_POLICY;

// rev
/**
 * Describes the heap mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_HEAP_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY TerminateOnHeapErrors;
} RTL_IMAGE_MITIGATION_HEAP_POLICY, *PRTL_IMAGE_MITIGATION_HEAP_POLICY;

// rev
/**
 * Describes the user-mode shadow stack (CET) mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY UserShadowStack;
    RTL_IMAGE_MITIGATION_POLICY SetContextIpValidation;
    RTL_IMAGE_MITIGATION_POLICY BlockNonCetBinaries;
} RTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY, *PRTL_IMAGE_MITIGATION_USER_SHADOW_STACK_POLICY;

// rev
/**
 * Describes the redirection trust mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_REDIRECTION_TRUST_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY BlockUntrustedRedirections;
} RTL_IMAGE_MITIGATION_REDIRECTION_TRUST_POLICY, *PRTL_IMAGE_MITIGATION_REDIRECTION_TRUST_POLICY;

// rev
/**
 * Describes the user-mode pointer authentication mitigation policy for an image.
 */
typedef struct _RTL_IMAGE_MITIGATION_USER_POINTER_AUTH_POLICY
{
    RTL_IMAGE_MITIGATION_POLICY PointerAuthUserIp;
} RTL_IMAGE_MITIGATION_USER_POINTER_AUTH_POLICY, *PRTL_IMAGE_MITIGATION_USER_POINTER_AUTH_POLICY;

// rev
/**
 * Identifies the configured state of an image mitigation option.
 */
typedef enum _RTL_IMAGE_MITIGATION_OPTION_STATE
{
    RtlMitigationOptionStateNotConfigured,
    RtlMitigationOptionStateOn,
    RtlMitigationOptionStateOff,
    RtlMitigationOptionStateForce,
    RtlMitigationOptionStateOption
} RTL_IMAGE_MITIGATION_OPTION_STATE;

/**
 * Mask and shift values for image mitigation option states.
 */
#define RTL_IMAGE_MITIGATION_OPTION_STATEMASK 3UL
#define RTL_IMAGE_MITIGATION_OPTION_FORCEMASK 4UL
#define RTL_IMAGE_MITIGATION_OPTION_OPTIONMASK 8UL

// rev from PROCESS_MITIGATION_FLAGS
/**
 * Flags controlling how image mitigation policies are queried or applied.
 */
#define RTL_IMAGE_MITIGATION_FLAG_RESET 0x1
#define RTL_IMAGE_MITIGATION_FLAG_REMOVE 0x2
#define RTL_IMAGE_MITIGATION_FLAG_OSDEFAULT 0x4
#define RTL_IMAGE_MITIGATION_FLAG_AUDIT 0x8

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)

/**
 * The RtlQueryImageMitigationPolicy routine queries an image mitigation policy for an executable image or the
 * system-wide defaults.
 *
 * \param ImagePath The path of the image to query, or NULL for the system-wide defaults.
 * \param Policy The mitigation policy to query.
 * \param Flags Flags controlling the query.
 * \param Buffer A buffer that receives the policy data.
 * \param BufferSize The size, in bytes, of Buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryImageMitigationPolicy(
    _In_opt_ PCWSTR ImagePath, // NULL for system-wide defaults
    _In_ IMAGE_MITIGATION_POLICY Policy,
    _In_ ULONG Flags,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize);

/**
 * The RtlSetImageMitigationPolicy routine sets an image mitigation policy for an executable image or the system-wide
 * defaults.
 *
 * \param ImagePath The path of the image to configure, or NULL for the system-wide defaults.
 * \param Policy The mitigation policy to set.
 * \param Flags Flags controlling the operation.
 * \param Buffer A buffer containing the policy data to apply.
 * \param BufferSize The size, in bytes, of Buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetImageMitigationPolicy(
    _In_opt_ PCWSTR ImagePath, // NULL for system-wide defaults
    _In_ IMAGE_MITIGATION_POLICY Policy,
    _In_ ULONG Flags,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize);

#endif

EXTERN_C_END
