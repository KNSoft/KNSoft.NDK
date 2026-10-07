#pragma once

#include "../../MinDef.h"

EXTERN_C_START

#pragma region FLS

/**
 * The RtlFlsAlloc routine allocates a fiber local storage (FLS) index, optionally associating a cleanup callback.
 *
 * \param Callback An optional pointer to a callback invoked when an FLS slot is freed or a fiber is deleted.
 * \param FlsIndex A pointer to a variable that receives the allocated FLS index.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFlsAlloc(
    _In_opt_ PFLS_CALLBACK_FUNCTION Callback,
    _Out_ PULONG FlsIndex);

// rev
/**
 * The RtlFlsAllocEx routine allocates a fiber local storage (FLS) index with extended output, optionally associating a
 * cleanup callback.
 *
 * An additional output parameter receives an allocation output value.
 *
 * \param Callback An optional pointer to a callback invoked when an FLS slot is freed or a fiber is deleted.
 * \param FlsIndex A pointer to a variable that receives the allocated FLS index.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFlsAllocEx(
    _In_opt_ PFLS_CALLBACK_FUNCTION Callback,
    _Out_ PULONG,
    _Out_ PULONG FlsIndex);

/**
 * The RtlFlsFree routine frees a fiber local storage (FLS) index previously allocated by RtlFlsAlloc.
 *
 * \param FlsIndex The FLS index to free.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFlsFree(
    _In_ ULONG FlsIndex);

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)

/**
 * The RtlFlsGetValue routine retrieves the value stored in a fiber local storage (FLS) slot of the current fiber.
 *
 * \param FlsIndex The FLS slot index.
 * \param FlsData Receives the value stored in the slot.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFlsGetValue(
    _In_ ULONG FlsIndex,
    _Out_ PVOID* FlsData);

/**
 * The RtlFlsGetValue2 routine retrieves the value stored in a fiber local storage (FLS) slot of the current fiber.
 *
 * \param FlsIndex The FLS slot index.
 * \return The value stored in the slot.
 */
NTSYSAPI
PVOID
WINAPI
RtlFlsGetValue2(
    _In_ ULONG FlsIndex);

/**
 * The RtlFlsSetValue routine stores a value in a fiber local storage (FLS) slot of the current fiber.
 *
 * \param FlsIndex The FLS slot index.
 * \param FlsData An optional value to store in the slot.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFlsSetValue(
    _In_ ULONG FlsIndex,
    _In_opt_ PVOID FlsData);

/**
 * Flags for fiber-local storage (FLS) data cleanup.
 */
#define RTL_FLS_DATA_CLEANUP_PER_SLOT 1
#define RTL_FLS_DATA_CLEANUP_DEALLOCATE 2

/**
 * The RtlProcessFlsData routine processes the fiber local storage (FLS) data of a fiber, invoking FLS callbacks.
 *
 * \param FlsData The FLS data block to process.
 * \param Flags Flags controlling how the FLS data is processed.
 */
NTSYSAPI
VOID
NTAPI
RtlProcessFlsData(
    _In_ PVOID FlsData,
    _In_ ULONG Flags);

#endif

#pragma endregion

#pragma region TLS

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)

// rev
/**
 * The RtlTlsAlloc routine allocates a thread local storage (TLS) index.
 *
 * \param TlsIndexx A pointer to a variable that receives the allocated TLS index.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlTlsAlloc(
    _Out_ PULONG TlsIndexx);

// rev
/**
 * The RtlTlsFree routine frees a thread local storage (TLS) index previously allocated by RtlTlsAlloc.
 *
 * \param TlsIndex The TLS index to free.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlTlsFree(
    _In_ ULONG TlsIndex);

// rev
/**
 * The RtlTlsSetValue routine stores a value in the specified thread local storage (TLS) slot of the current thread.
 *
 * \param TlsIndex The TLS slot index.
 * \param TlsData An optional value to store in the slot.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlTlsSetValue(
    _In_ ULONG TlsIndex,
    _In_opt_ PVOID TlsData);

#endif

#pragma endregion

#pragma region Protected Policies

#if (NTDDI_VERSION >= NTDDI_WINBLUE)

/**
 * The RtlQueryProtectedPolicy routine retrieves the value of a protected policy identified by a GUID.
 *
 * \param PolicyGuid A pointer to the GUID that identifies the protected policy.
 * \param PolicyValue A pointer to a variable that receives the policy value.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryProtectedPolicy(
    _In_ PCGUID PolicyGuid,
    _Out_ PULONG_PTR PolicyValue);

/**
 * The RtlSetProtectedPolicy routine sets the value of a protected policy identified by a GUID.
 *
 * \param PolicyGuid A pointer to the GUID that identifies the protected policy.
 * \param PolicyValue The new value to assign to the protected policy.
 * \param OldPolicyValue A pointer to a variable that receives the previous policy value.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetProtectedPolicy(
    _In_ PCGUID PolicyGuid,
    _In_ ULONG_PTR PolicyValue,
    _Out_ PULONG_PTR OldPolicyValue);

#endif

#pragma endregion


// RtlCreateUserFiberShadowStack
/**
 * The RtlCreateUserFiberShadowStack routine creates a shadow stack for a user-mode fiber (CET shadow-stack support).
 *
 * \param ShadowStackInfo Describes the shadow stack to create.
 * \param ReserveSize The number of bytes to reserve for the shadow stack.
 * \param ShadowStackOut Receives the base of the newly created shadow stack.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserFiberShadowStack(
    _In_ PVOID ShadowStackInfo,
    _In_ ULONGLONG ReserveSize,
    _Out_ PVOID *ShadowStackOut
    );

// RtlFreeUserFiberShadowStack
/**
 * The RtlFreeUserFiberShadowStack routine frees a user-mode fiber shadow stack allocation.
 *
 * \param AllocationBase The base address of the fiber shadow stack allocation to free.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlFreeUserFiberShadowStack( // NtSetInformationProcess(ProcessFreeFiberShadowStackAllocation)
    _In_ PVOID AllocationBase
    );

// RtlUmsThreadYield
/**
 * The RtlUmsThreadYield routine yields execution of the current user-mode scheduling (UMS) thread back to the UMS
 * scheduler.
 *
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUmsThreadYield(
    _In_ PVOID SchedulerParam
    );

EXTERN_C_END
