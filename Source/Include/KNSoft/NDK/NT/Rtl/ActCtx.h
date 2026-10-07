#pragma once

#include "../MinDef.h"
#include "../Sxs.h"
#include "Process/EnvironmentBlock.h"

#define _USE_FULL_PROC_THREAD_ATTRIBUTE
#include <WinBase.h>

EXTERN_C_START

/* phnt */

/**
 * Sentinel handle values and flags for activation contexts.
 */
#define INVALID_ACTIVATION_CONTEXT ((HANDLE)(LONG_PTR)-1)
#define ACTCTX_PROCESS_DEFAULT ((HANDLE)(LONG_PTR)0)
#define ACTCTX_EMPTY ((HANDLE)(LONG_PTR)-3)
#define ACTCTX_SYSTEM_DEFAULT ((HANDLE)(LONG_PTR)-4)
#define IS_SPECIAL_ACTCTX(x) (((((LONG_PTR)(x)) - 1) | 7) == -1)

// private
/**
 * The RtlGetActiveActivationContext routine retrieves the activation context that is currently active on the calling
 * thread.
 *
 * \param ActivationContext A pointer to a variable that receives the active activation context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetActiveActivationContext(
    _Out_ PACTIVATION_CONTEXT ActivationContext
    );

// private
/**
 * The RtlAddRefActivationContext routine increments the reference count of an activation context.
 *
 * \param ActivationContext A pointer to the activation context.
 */
NTSYSAPI
VOID
NTAPI
RtlAddRefActivationContext(
    _In_ PACTIVATION_CONTEXT ActivationContext
    );

// private
/**
 * The RtlReleaseActivationContext routine decrements the reference count of an activation context, releasing it when
 * the count reaches zero.
 *
 * \param ActivationContext A pointer to the activation context.
 */
NTSYSAPI
VOID
NTAPI
RtlReleaseActivationContext(
    _In_ PACTIVATION_CONTEXT ActivationContext
    );

// private
/**
 * The RtlZombifyActivationContext routine marks an activation context as a zombie, releasing its resources while
 * keeping the object alive.
 *
 * \param ActivationContext A pointer to the activation context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlZombifyActivationContext(
    _In_ PACTIVATION_CONTEXT ActivationContext
    );

// private
/**
 * The RtlIsActivationContextActive routine determines whether the specified activation context is currently active.
 *
 * \param ActivationContext A pointer to the activation context.
 * \return `TRUE` if the activation context is active, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsActivationContextActive(
    _In_ PACTIVATION_CONTEXT ActivationContext
    );

// private
/**
 * The RtlActivateActivationContext routine activates an activation context on the calling thread.
 *
 * \param Flags Reserved. Must be zero.
 * \param ActivationContext A pointer to the activation context to activate.
 * \param Cookie A pointer to a variable that receives a cookie used to deactivate the context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlActivateActivationContext(
    _Reserved_ ULONG Flags,
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _Out_ PULONG_PTR Cookie
    );

/**
 * Flag for RtlActivateActivationContextEx.
 */
#define RTL_ACTIVATE_ACTIVATION_CONTEXT_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION 0x00000001

// private
/**
 * The RtlActivateActivationContextEx routine activates an activation context on the specified thread.
 *
 * \param Flags Flags that control the activation.
 * \param Teb A pointer to the thread environment block (TEB) of the thread on which to activate the context.
 * \param ActivationContext A pointer to the activation context to activate.
 * \param Cookie A pointer to a variable that receives a cookie used to deactivate the context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlActivateActivationContextEx(
    _In_ ULONG Flags,
    _In_ PTEB Teb,
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _Out_ PULONG_PTR Cookie
    );

/**
 * Flag for RtlDeactivateActivationContext.
 */
#define RTL_DEACTIVATE_ACTIVATION_CONTEXT_FLAG_FORCE_EARLY_DEACTIVATION 0x00000001

// private
/**
 * The RtlDeactivateActivationContext routine deactivates an activation context previously activated on the calling
 * thread.
 *
 * \param Flags Flags that control the deactivation.
 * \param Cookie The cookie returned when the activation context was activated.
 */
NTSYSAPI
VOID
NTAPI
RtlDeactivateActivationContext(
    _In_ ULONG Flags,
    _In_ ULONG_PTR Cookie
    );

// private
/**
 * The RtlCreateActivationContext routine creates an activation context from the supplied activation context data.
 *
 * \param Flags Reserved; must be zero.
 * \param ActivationContextData The activation context data used to build the context.
 * \param ExtraBytes An optional number of extra bytes to allocate with the context.
 * \param NotificationRoutine An optional routine that receives activation context notifications.
 * \param NotificationContext An optional context value passed to the notification routine.
 * \param ActivationContext Receives the newly created activation context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateActivationContext(
    _Reserved_ ULONG Flags,
    _In_ PACTIVATION_CONTEXT_DATA ActivationContextData,
    _In_opt_ ULONG ExtraBytes,
    _In_opt_ PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine,
    _In_opt_ PVOID NotificationContext,
    _Out_ PACTIVATION_CONTEXT *ActivationContext
    );

/**
 * Flags for the activation context section search routines.
 */
#define FIND_ACTIVATION_CONTEXT_SECTION_KEY_RETURN_ACTIVATION_CONTEXT 0x00000001
#define FIND_ACTIVATION_CONTEXT_SECTION_KEY_RETURN_FLAGS 0x00000002
#define FIND_ACTIVATION_CONTEXT_SECTION_KEY_RETURN_ASSEMBLY_METADATA 0x00000004

// private
/**
 * The RtlFindActivationContextSectionString routine searches an activation context for a string entry in the specified
 * section.
 *
 * \param Flags Flags that control the search.
 * \param ExtensionGuid An optional pointer to the extension GUID that identifies a custom section.
 * \param SectionId The identifier of the section to search (ACTIVATION_CONTEXT_SECTION_*).
 * \param StringToFind A pointer to the string to find.
 * \param ReturnedData A pointer to a structure that receives the located section data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFindActivationContextSectionString(
    _In_ ULONG Flags,
    _In_opt_ PCGUID ExtensionGuid,
    _In_ ULONG SectionId, // ACTIVATION_CONTEXT_SECTION_*
    _In_ PUNICODE_STRING StringToFind,
    _Inout_ PACTCTX_SECTION_KEYED_DATA ReturnedData
    );

// private
/**
 * The RtlFindActivationContextSectionGuid routine searches an activation context for a GUID entry in the specified
 * section.
 *
 * \param Flags Flags that control the search.
 * \param ExtensionGuid An optional pointer to the extension GUID that identifies a custom section.
 * \param SectionId The identifier of the section to search (ACTIVATION_CONTEXT_SECTION_*).
 * \param GuidToFind A pointer to the GUID to find.
 * \param ReturnedData A pointer to a structure that receives the located section data.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFindActivationContextSectionGuid(
    _In_ ULONG Flags,
    _In_opt_ PCGUID ExtensionGuid,
    _In_ ULONG SectionId, // ACTIVATION_CONTEXT_SECTION_*
    _In_ PCGUID GuidToFind,
    _Inout_ PACTCTX_SECTION_KEYED_DATA ReturnedData
    );

// rev
/**
 * The RtlQueryActivationContextApplicationSettings routine queries an application setting from the specified activation
 * context.
 *
 * \param Flags Reserved. Must be zero.
 * \param ActivationContext A pointer to the activation context to query.
 * \param SettingsNameSpace An optional pointer to the settings namespace URI. If NULL,
 * http://schemas.microsoft.com/SMI/2005/WindowsSettings is used.
 * \param SettingName A pointer to the name of the setting to query.
 * \param Buffer A buffer that receives the setting value.
 * \param BufferLength The size, in bytes, of the buffer.
 * \param RequiredLength An optional pointer to a variable that receives the required buffer size.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryActivationContextApplicationSettings(
    _Reserved_ ULONG Flags,
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _In_opt_ PCWSTR SettingsNameSpace,
    _In_ PCWSTR SettingName,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _In_ SIZE_T BufferLength,
    _Out_opt_ PSIZE_T RequiredLength
    );

// ACTIVATION_CONTEXT_INFO_CLASS
//   ActivationContextBasicInformation                      // q: ACTIVATION_CONTEXT_BASIC_INFORMATION
//   ActivationContextDetailedInformation                   // q: ACTIVATION_CONTEXT_DETAILED_INFORMATION
//   AssemblyDetailedInformationInActivationContext         // q: ACTIVATION_CONTEXT_ASSEMBLY_DETAILED_INFORMATION
//   FileInformationInAssemblyOfAssemblyInActivationContext // q: ASSEMBLY_FILE_DETAILED_INFORMATION
//   RunlevelInformationInActivationContext                 // q: ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION
//   CompatibilityInformationInActivationContext            // q: ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION[_LEGACY]
//   ActivationContextManifestResourceName                  // q: ULONG

/**
 * Flags for RtlQueryInformationActivationContext.
 */
#define RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_USE_ACTIVE_ACTIVATION_CONTEXT 0x00000001
#define RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_ACTIVATION_CONTEXT_IS_MODULE 0x00000002
#define RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_ACTIVATION_CONTEXT_IS_ADDRESS 0x00000004
#define RTL_QUERY_INFORMATION_ACTIVATION_CONTEXT_FLAG_NO_ADDREF 0x80000000

// private
/**
 * The RtlQueryInformationActivationContext routine retrieves information about an activation context.
 *
 * \param Flags Flags controlling the query (for example, whether ActivationContext is a handle).
 * \param ActivationContext An optional activation context to query; NULL queries the active context.
 * \param SubInstanceIndex An optional index selecting a sub-instance within the context.
 * \param ActivationContextInformationClass The class of information to retrieve.
 * \param ActivationContextInformation A buffer that receives the requested information.
 * \param ActivationContextInformationLength The size, in bytes, of the buffer.
 * \param ReturnLength An optional pointer that receives the number of bytes returned.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryInformationActivationContext(
    _In_ ULONG Flags,
    _In_opt_ PACTIVATION_CONTEXT ActivationContext,
    _In_opt_ PACTIVATION_CONTEXT_QUERY_INDEX SubInstanceIndex,
    _In_ ACTIVATION_CONTEXT_INFO_CLASS ActivationContextInformationClass,
    _Out_writes_bytes_(ActivationContextInformationLength) PVOID ActivationContextInformation,
    _In_ SIZE_T ActivationContextInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

/**
 * The RtlQueryInformationActiveActivationContext routine retrieves information about the currently active activation
 * context.
 *
 * \param ActivationContextInformationClass The class of information to retrieve.
 * \param ActivationContextInformation A buffer that receives the requested information.
 * \param ActivationContextInformationLength The size, in bytes, of the buffer.
 * \param ReturnLength An optional pointer that receives the number of bytes returned.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryInformationActiveActivationContext(
    _In_ ACTIVATION_CONTEXT_INFO_CLASS ActivationContextInformationClass,
    _Out_writes_bytes_(ActivationContextInformationLength) PVOID ActivationContextInformation,
    _In_ SIZE_T ActivationContextInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

// RtlActivateActivationContextUnsafeFast
/**
 * The RtlActivateActivationContextUnsafeFast routine activates an activation context on the current thread using the
 * fast, lock-free path.
 *
 * \param CallerFrame A 0x48-byte caller-allocated RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED that
 * receives the frame state.
 * \param ActivationContext An optional activation context to activate.
 */
NTSYSAPI
VOID
FASTCALL
RtlActivateActivationContextUnsafeFast(
    _Out_writes_bytes_(0x48) PVOID CallerFrame,
    _In_opt_ PVOID ActivationContext
    );

// RtlAllocateActivationContextStack
/**
 * The RtlAllocateActivationContextStack routine allocates an activation context stack for a thread.
 *
 * \param ActivationContextStack A pointer to a variable that receives the allocated activation context stack.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateActivationContextStack(
    _Inout_ PACTIVATION_CONTEXT_STACK* ActivationContextStack
    );

// RtlDeactivateActivationContextUnsafeFast
//NTSYSAPI
//ULONG
//NTAPI
//RtlConvertDeviceFamilyInfoToString(
//    _Inout_ PULONG DeviceFamilyBufferSize,
//    _Inout_ PULONG DeviceFormBufferSize,
//    _Out_writes_bytes_opt_(*DeviceFamilyBufferSize) PWSTR DeviceFamily,
//    _Out_writes_bytes_opt_(*DeviceFormBufferSize) PWSTR DeviceForm
//    );
//
//NTSYSAPI
//VOID
//NTAPI
//RtlGetDeviceFamilyInfoEnum(
//    _Out_opt_ PULONGLONG UapInfo,
//    _Out_opt_ PULONG DeviceFamily,
//    _Out_opt_ PULONG DeviceForm
//    );

// rev
/**
 * The RtlDeactivateActivationContextUnsafeFast routine deactivates the activation context previously activated on the
 * current thread using the fast path.
 *
 * \param CallerFrame The 0x48-byte caller frame previously initialized by RtlActivateActivationContextUnsafeFast.
 */
NTSYSAPI
VOID
FASTCALL
RtlDeactivateActivationContextUnsafeFast(
    _Inout_updates_bytes_(0x48) PVOID CallerFrame
    );

// RtlFreeActivationContextStack
//NTSYSAPI
//ULONG
//NTAPI
//RtlFillNonVolatileMemory(
//    _In_ PVOID NvToken,
//    _Out_writes_bytes_(Size) PVOID NvDestination,
//    _In_ SIZE_T Size,
//    _In_ BYTE Value,
//    _In_ ULONG Flags
//    );

// rev
/**
 * The RtlFreeActivationContextStack routine frees an activation context stack.
 *
 * \param ActivationContextStack An optional pointer to the activation context stack to free.
 */
NTSYSAPI
VOID
NTAPI
RtlFreeActivationContextStack(
    _Inout_opt_ PACTIVATION_CONTEXT_STACK ActivationContextStack
    );

// RtlFreeThreadActivationContextStack
//NTSYSAPI
//NTSTATUS
//NTAPI
//RtlFlushNonVolatileMemory(
//    _In_ UCHAR NvToken,
//    _In_ PVOID BaseAddress,
//    _In_ SIZE_T Length,
//    _In_ UCHAR Flags
//    );
//
//NTSYSAPI
//NTSTATUS
//NTAPI
//RtlFlushNonVolatileMemoryRanges(
//    _In_ UCHAR NvToken,
//    _In_reads_(PairCount) const ULONGLONG *AddressLengthPairs,
//    _In_ SIZE_T PairCount,
//    _In_ UCHAR Flags
//    );

// NTSYSAPI
// NTSTATUS
// NTAPI
// RtlFreeNonVolatileToken(
//     _In_ PVOID NvToken
//     );

// rev
/**
 * The RtlFreeThreadActivationContextStack routine frees the activation context stack associated with the current
 * thread.
 */
NTSYSAPI
VOID
NTAPI
RtlFreeThreadActivationContextStack(
    VOID
    );


EXTERN_C_END
