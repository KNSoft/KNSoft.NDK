#pragma once

#include "../MinDef.h"
#include "../Sxs.h"
#include "Path.h"
#include "Debug.h"
#include "Feature.h"
#include "ActCtx.h"
#include "BootStatus.h"
#include "Mui.h"
#include "Reg.h"
#include "Sync.h"
#include "Time.h"
#include "Wow.h"
#include "DataStructures/RBTree.h"
#include "Security/Misc.h"
#include "../Ldr.h"
#include "../Ex/Wnf.h"

EXTERN_C_START

/* phnt private additions synced from 2cc1b9d44 */

typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR CM_PARTIAL_RESOURCE_DESCRIPTOR,
    *PCM_PARTIAL_RESOURCE_DESCRIPTOR;
typedef struct _IO_RESOURCE_DESCRIPTOR IO_RESOURCE_DESCRIPTOR, *PIO_RESOURCE_DESCRIPTOR;

// RtlpApplyLengthFunction
/**
 * The RtlpApplyLengthFunction routine invokes a length function to populate a UNICODE_STRING, then applies
 * the resulting character count as the string's byte Length.
 *
 * \details Calls \p LengthFunction to fill \p Destination and report a character
 * count, converts that count to a byte Length (count * sizeof(WCHAR)), and
 * stores it in \p Destination->Length. If \p Type is 56 the buffer is
 * additionally NUL-terminated at Buffer[count]. A count exceeding 0x7FFF
 * characters (0xFFFE bytes) overflows the UNICODE_STRING length field and is
 * rejected.
 * \param[in] Reserved Reserved; must be 0.
 * \param[in] Type Mode selector. Must be 16 (no termination) or 56
 * (NUL-terminate \p Destination->Buffer).
 * \param[in,out] Destination The target UNICODE_STRING; its Buffer is filled by
 * \p LengthFunction and its Length is set on success.
 * \param[in] LengthFunction Callback that fills \p Destination and returns the
 * character count.
 * \return
 * - STATUS_SUCCESS on success.
 * - STATUS_INVALID_PARAMETER (0xC000000D) if \p Reserved != 0,
 *   \p Destination or \p LengthFunction is NULL, or \p Type is not 16 or 56.
 * - STATUS_NAME_TOO_LONG (0xC0000106) if the character count exceeds 0x7FFF.
 * - Any negative NTSTATUS propagated from \p LengthFunction.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpApplyLengthFunction(
    _In_ ULONG_PTR Reserved,
    _In_ ULONG Type,
    _Inout_ PUNICODE_STRING Destination,
    _In_ NTSTATUS (NTAPI *LengthFunction)(
        _In_ ULONG Flags,
        _In_ PVOID StringStruct,
        _Out_ PULONG LengthChars)
    );

// RtlpEnsureBufferSize
/**
 * The RtlpEnsureBufferSize routine ensures an RTL_BUFFER can hold at least RequiredSize bytes, growing it via the
 * atom-table allocator if necessary.
 *
 * \details No-op if the buffer is already large enough. If the request still
 * fits the embedded static buffer, only the size field is updated.
 * Otherwise a new block is allocated with \c RtlpAllocateAtom, the
 * existing contents are copied unless \p Flags requests otherwise, any
 * prior dynamic allocation is released with \c RtlpSysVolFree, and the
 * buffer is repointed. The buffer is never shrunk.
 * \param[in] Flags Bit 0 skips copying the existing contents on reallocation (RTL_SKIP_BUFFER_COPY); all other bits
 * must be zero.
 * \param[in,out] BufferState The RTL_BUFFER to enlarge.
 * \param[in] RequiredSize The minimum required capacity, in bytes.
 * \return STATUS_SUCCESS on success.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpEnsureBufferSize(
    _In_ ULONG Flags,
    _Inout_ PRTL_BUFFER BufferState,
    _In_ SIZE_T RequiredSize
    );

// RtlpGetDeviceFamilyInfoEnum
/**
 * The RtlpGetDeviceFamilyInfoEnum routine retrieves device family and form factor information for the current system.
 *
 * \param UapInfo An optional pointer that receives the Universal Action Platform (UAP) version information.
 * \param DeviceFamily An optional pointer that receives the device family enumeration value (DEVICEFAMILYINFOENUM).
 * \param DeviceForm An optional pointer that receives the device form factor enumeration value
 * (DEVICEFAMILYDEVICEFORM).
 */
NTSYSAPI
VOID
NTAPI
RtlpGetDeviceFamilyInfoEnum(
    _Out_opt_ PULONGLONG UapInfo,
    _Out_opt_ PULONG DeviceFamily,
    _Out_opt_ PULONG DeviceForm
    );

// RtlpGetNameFromLangInfoNode
/**
 * The RtlpGetNameFromLangInfoNode routine retrieves the language name associated with a language-info node from the MUI
 * registry information string pool.
 *
 * \param RegistryInfo The MUI registry information block that owns the string pool referenced by the node.
 * \param LangInfoNode A pointer to the language-info node to resolve.
 * \param Name Receives the resolved language name.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpGetNameFromLangInfoNode(
    _In_ PRTL_MUI_REGISTRY_INFO RegistryInfo,
    _In_ PVOID LangInfoNode,
    _Inout_ PUNICODE_STRING Name
    );

// RtlpInitializeLangRegistryInfo
/**
 * The RtlpInitializeLangRegistryInfo routine ensures the process MUI registry information cache is created and loaded,
 * initializing it on first use.
 *
 * \param RegistryInfo On input points to the cache pointer; when the pointed-to value is NULL the cache is created and
 * loaded.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpInitializeLangRegistryInfo(
    _Inout_ PRTL_MUI_REGISTRY_INFO *RegistryInfo
    );

// RtlpLoadMachineUIByPolicy
/**
 * The RtlpLoadMachineUIByPolicy routine loads the machine UI language list dictated by the MUI Group Policy settings.
 *
 * \param PolicyRootKey An optional handle to the policy root key; when NULL the default MUI policy key is opened.
 * \param RegistryInfo The MUI registry information block used to build the language list.
 * \param LanguageList On input points to an existing language list (or NULL); receives the populated language list.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpLoadMachineUIByPolicy(
    _In_opt_ HANDLE PolicyRootKey,
    _In_ PRTL_MUI_REGISTRY_INFO RegistryInfo,
    _Inout_ PVOID *LanguageList
    );

// RtlpLoadUserUIByPolicy
/**
 * The RtlpLoadUserUIByPolicy routine loads the per-user UI language list dictated by the MUI Group Policy settings.
 *
 * \param UserRootKey An optional handle to the user policy root key; when NULL the default MUI policy key is opened.
 * \param RegistryInfo The MUI registry information block used to build the language list.
 * \param LanguageList On input points to an existing language list (or NULL); receives the populated language list.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpLoadUserUIByPolicy(
    _In_opt_ HANDLE UserRootKey,
    _In_ PRTL_MUI_REGISTRY_INFO RegistryInfo,
    _Inout_ PVOID *LanguageList
    );

// RtlpNotOwnerCriticalSection
/**
 * The RtlpNotOwnerCriticalSection routine handles the case in which a thread that does not own a critical section
 * attempts to release it.
 *
 * \param CriticalSection A pointer to the critical section involved.
 */
NTSYSAPI
VOID
NTAPI
RtlpNotOwnerCriticalSection(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
    );

// RtlpQueryProcessDebugInformationRemote
/**
 * The RtlpQueryProcessDebugInformationRemote routine is the internal worker thread that collects debug information from
 * a target process.
 *
 * \param DebugInfo A pointer to the RTL_DEBUG_INFORMATION buffer that receives the collected information.
 */
NTSYSAPI
VOID
NTAPI
RtlpQueryProcessDebugInformationRemote(
    _Inout_ PRTL_DEBUG_INFORMATION DebugInfo
    );

// RtlpUnWaitCriticalSection
/**
 * The RtlpUnWaitCriticalSection routine is an internal helper that wakes a thread waiting on a critical section.
 *
 * \param CriticalSection A pointer to the critical section whose waiter is released.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlpUnWaitCriticalSection(
    _Inout_ PRTL_CRITICAL_SECTION CriticalSection
    );

// RtlCmDecodeMemIoResource
#if (NTDDI_VERSION >= NTDDI_VISTA)
/**
 * The RtlCmDecodeMemIoResource routine decodes a memory or I/O resource descriptor.
 *
 * \param Descriptor The partial resource descriptor to decode.
 * \param Start An optional pointer that receives the resource start address.
 * \return The decoded resource length.
 */
NTSYSAPI
ULONGLONG
NTAPI
RtlCmDecodeMemIoResource (
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
    _Out_opt_ PULONGLONG Start
    );
#endif

// RtlCmEncodeMemIoResource
#if (NTDDI_VERSION >= NTDDI_VISTA)
/**
 * The RtlCmEncodeMemIoResource routine encodes a memory or I/O resource descriptor.
 *
 * \param Descriptor The partial resource descriptor to encode.
 * \param Type The resource type.
 * \param Length The length of the resource.
 * \param Start The start address of the resource.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCmEncodeMemIoResource (
    _In_ PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor,
    _In_ UCHAR Type,
    _In_ ULONGLONG Length,
    _In_ ULONGLONG Start
    );
#endif

// RtlInitializeNtUserPfn
/**
 * The RtlInitializeNtUserPfn routine registers the win32u/NtUser private function (PFN) dispatch tables with ntdll.
 *
 * \param NtUserPfnTable The primary NtUser PFN dispatch table.
 * \param NtUserPfnTableSize The size, in bytes, of the primary table.
 * \param NtUserPfnTable2 An optional secondary NtUser PFN dispatch table.
 * \param NtUserPfnTable2Size The size, in bytes, of the secondary table.
 * \param NtUserPfnTable3 An optional tertiary NtUser PFN dispatch table.
 * \param NtUserPfnTable3Size The size, in bytes, of the tertiary table.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeNtUserPfn(
    _In_ PVOID NtUserPfnTable,
    _In_ SIZE_T NtUserPfnTableSize,
    _In_opt_ PVOID NtUserPfnTable2,
    _In_ SIZE_T NtUserPfnTable2Size,
    _In_opt_ PVOID NtUserPfnTable3,
    _In_ SIZE_T NtUserPfnTable3Size
    );

// RtlIoDecodeMemIoResource
#if (NTDDI_VERSION >= NTDDI_VISTA)
/**
 * The RtlIoDecodeMemIoResource routine decodes a memory or I/O resource descriptor.
 *
 * \param Descriptor The I/O resource descriptor to decode.
 * \param Alignment An optional pointer that receives the resource alignment.
 * \param MinimumAddress An optional pointer that receives the minimum resource address.
 * \param MaximumAddress An optional pointer that receives the maximum resource address.
 * \return The decoded resource length.
 */
NTSYSAPI
ULONGLONG
NTAPI
RtlIoDecodeMemIoResource (
    _In_ PIO_RESOURCE_DESCRIPTOR Descriptor,
    _Out_opt_ PULONGLONG Alignment,
    _Out_opt_ PULONGLONG MinimumAddress,
    _Out_opt_ PULONGLONG MaximumAddress
    );
#endif

// RtlIoEncodeMemIoResource
#if (NTDDI_VERSION >= NTDDI_VISTA)
/**
 * The RtlIoEncodeMemIoResource routine encodes a memory or I/O resource descriptor.
 *
 * \param Descriptor The I/O resource descriptor to encode.
 * \param Type The resource type.
 * \param Length The resource length.
 * \param Alignment The alignment requirement.
 * \param MinimumAddress The minimum acceptable address.
 * \param MaximumAddress The maximum acceptable address.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlIoEncodeMemIoResource (
    _In_ PIO_RESOURCE_DESCRIPTOR Descriptor,
    _In_ UCHAR Type,
    _In_ ULONGLONG Length,
    _In_ ULONGLONG Alignment,
    _In_ ULONGLONG MinimumAddress,
    _In_ ULONGLONG MaximumAddress
    );
#endif

// RtlResetNtUserPfn
/**
 * The RtlResetNtUserPfn routine resets (unregisters) the win32u/NtUser private function (PFN) dispatch tables.
 *
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlResetNtUserPfn(
    VOID
    );

// RtlRetrieveNtUserPfn
/**
 * The RtlRetrieveNtUserPfn routine retrieves the win32k user-mode callback function-pointer tables.
 *
 * \param NtUserPfnTable A pointer to a variable that receives the address of the first user PFN table.
 * \param NtUserPfnTable2 A pointer to a variable that receives the address of the second user PFN table.
 * \param NtUserPfnTable3 A pointer to a variable that receives the address of the third user PFN table.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRetrieveNtUserPfn(
    _Out_ PULONGLONG NtUserPfnTable,
    _Out_ PULONGLONG NtUserPfnTable2,
    _Out_ PULONGLONG NtUserPfnTable3
    );

EXTERN_C_END
