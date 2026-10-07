#pragma once

#include "../../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Describes the location and size of a single chunk within an extended CONTEXT structure.
 */
typedef struct _CONTEXT_CHUNK
{
    LONG Offset; // Offset may be negative.
    ULONG Length;
} CONTEXT_CHUNK, *PCONTEXT_CHUNK;

/**
 * Extends the CONTEXT structure with optional, variable-length processor-state chunks.
 */
typedef struct _CONTEXT_EX
{
    CONTEXT_CHUNK All;
    CONTEXT_CHUNK Legacy;
    CONTEXT_CHUNK XState;
    CONTEXT_CHUNK KernelCet;
} CONTEXT_EX, *PCONTEXT_EX;

#if defined(_AMD64_) || defined(_ARM64_) || defined(_ARM64EC_)
#define CONTEXT_ALIGN 0x10
#else
#define CONTEXT_ALIGN 0x8
#endif

#if defined(_AMD64_)
#define CONTEXT_FRAME_LENGTH 0x4D0
#define CONTEXT_EX_PADDING   0x10
#elif defined(_ARM64_) || defined(_ARM64EC_)
#define CONTEXT_FRAME_LENGTH 0x390
#define CONTEXT_EX_PADDING   0x10
#elif defined(_M_ARM)
#define CONTEXT_FRAME_LENGTH 0x1a0
#define CONTEXT_EX_PADDING   0x8
#else
#define CONTEXT_FRAME_LENGTH 0x2CC
#define CONTEXT_EX_PADDING   0x4
#endif

/**
 * Alignment, in bytes, of a CONTEXT structure.
 */
#define CONTEXT_ALIGNMENT(Size, Align) \
    (((ULONG_PTR)(Size) + (Align) - 1) & ~((Align) - 1))

#define CONTEXT_EX_LENGTH \
    CONTEXT_ALIGNMENT(sizeof(CONTEXT_EX), CONTEXT_ALIGN)

_STATIC_ASSERT(CONTEXT_FRAME_LENGTH == sizeof(CONTEXT));
_STATIC_ASSERT(CONTEXT_EX_LENGTH == 0x20);

/**
 * Accessor macros for locating chunks within a CONTEXT_EX structure.
 */
#define RTL_CONTEXT_EX_OFFSET(ContextEx, Chunk) ((ContextEx)->Chunk.Offset)
#define RTL_CONTEXT_EX_LENGTH(ContextEx, Chunk) ((ContextEx)->Chunk.Length)
#define RTL_CONTEXT_EX_CHUNK(Base, Layout, Chunk) ((PVOID)((PUCHAR)(Base) + RTL_CONTEXT_EX_OFFSET(Layout, Chunk)))
#define RTL_CONTEXT_OFFSET(Context, Chunk) RTL_CONTEXT_EX_OFFSET((PCONTEXT_EX)((Context) + 1), Chunk)
#define RTL_CONTEXT_LENGTH(Context, Chunk) RTL_CONTEXT_EX_LENGTH((PCONTEXT_EX)((Context) + 1), Chunk)
#define RTL_CONTEXT_CHUNK(Context, Chunk) RTL_CONTEXT_EX_CHUNK((PCONTEXT_EX)((Context) + 1), (PCONTEXT_EX)((Context) + 1), Chunk)

// returns status of NtWriteVirtualMemory (dmex)
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeContext(
    _In_ HANDLE ProcessHandle,
    _Out_ PCONTEXT Context,
    _In_opt_ PVOID Parameter,
    _In_opt_ PVOID InitialPc,
    _In_opt_ PVOID InitialSp
);

/**
 * The RtlInitializeExtendedContext routine initializes an extended context structure within a caller-supplied buffer.
 *
 * \param Context A pointer to the buffer that receives the initialized context.
 * \param ContextFlags Flags that specify which portions of the context are initialized.
 * \param ContextEx A pointer to a variable that receives a pointer to the extended context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeExtendedContext(
    _Out_ PCONTEXT Context,
    _In_ ULONG ContextFlags,
    _Out_ PCONTEXT_EX* ContextEx);

/**
 * The RtlInitializeExtendedContext2 routine initializes an extended context structure within a caller-supplied buffer,
 * using the specified set of enabled extended features.
 *
 * \param Context A pointer to the buffer that receives the initialized context.
 * \param ContextFlags Flags that specify which portions of the context are initialized.
 * \param ContextEx A pointer to a variable that receives a pointer to the extended context.
 * \param EnabledExtendedFeatures A mask of the enabled extended processor features.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeExtendedContext2(
    _Out_ PCONTEXT Context,
    _In_ ULONG ContextFlags,
    _Out_ PCONTEXT_EX* ContextEx,
    _In_ ULONG64 EnabledExtendedFeatures // RtlGetEnabledExtendedFeatures(-1)
);

/**
 * The RtlCopyContext routine copies the specified portions of a context structure.
 *
 * \param Context A pointer to the destination context.
 * \param ContextFlags Flags that specify which portions of the context are copied.
 * \param Source A pointer to the source context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCopyContext(
    _Inout_ PCONTEXT Context,
    _In_ ULONG ContextFlags,
    _Out_ PCONTEXT Source);

/**
 * The RtlCopyExtendedContext routine copies the specified portions of an extended context structure.
 *
 * \param Destination A pointer to the destination extended context.
 * \param ContextFlags Flags that specify which portions of the context are copied.
 * \param Source A pointer to the source extended context.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCopyExtendedContext(
    _Out_ PCONTEXT_EX Destination,
    _In_ ULONG ContextFlags,
    _In_ PCONTEXT_EX Source);

/**
 * The RtlGetExtendedContextLength routine computes the length required for an extended context structure.
 *
 * \param ContextFlags Flags that specify which portions of the context are included.
 * \param ContextLength A pointer to a variable that receives the required length, in bytes.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetExtendedContextLength(
    _In_ ULONG ContextFlags,
    _Out_ PULONG ContextLength);

/**
 * The RtlGetExtendedContextLength2 routine computes the length required for an extended context structure, using the
 * specified set of enabled extended features.
 *
 * \param ContextFlags Flags that specify which portions of the context are included.
 * \param ContextLength A pointer to a variable that receives the required length, in bytes.
 * \param EnabledExtendedFeatures A mask of the enabled extended processor features.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetExtendedContextLength2(
    _In_ ULONG ContextFlags,
    _Out_ PULONG ContextLength,
    _In_ ULONG64 EnabledExtendedFeatures // RtlGetEnabledExtendedFeatures(-1)
);

/**
 * The RtlGetExtendedFeaturesMask routine returns the mask of extended processor features present in an extended
 * context.
 *
 * \param ContextEx A pointer to the extended context.
 * \return The mask of extended processor features.
 */
NTSYSAPI
ULONG64
NTAPI
RtlGetExtendedFeaturesMask(
    _In_ PCONTEXT_EX ContextEx);

/**
 * The RtlLocateExtendedFeature routine locates the save area of an extended processor feature within an extended
 * context.
 *
 * \param ContextEx The extended context to search.
 * \param FeatureId The XSTATE feature identifier to locate.
 * \param Length An optional pointer that receives the length, in bytes, of the feature save area.
 * \return A pointer to the feature save area, or NULL if the feature is not present.
 */
NTSYSAPI
PVOID
NTAPI
RtlLocateExtendedFeature(
    _In_ PCONTEXT_EX ContextEx,
    _In_ ULONG FeatureId,
    _Out_opt_ PULONG Length);

/**
 * The RtlLocateExtendedFeature2 routine locates the save area of an extended processor feature within an extended
 * context, using an explicit XSTATE configuration.
 *
 * \param ContextEx The extended context to search.
 * \param FeatureId The XSTATE feature identifier to locate.
 * \param XState The XSTATE configuration describing feature layout.
 * \param Length An optional pointer that receives the length, in bytes, of the feature save area.
 * \return A pointer to the feature save area, or NULL if the feature is not present.
 */
NTSYSAPI
PVOID
NTAPI
RtlLocateExtendedFeature2(
    _In_ PCONTEXT_EX ContextEx,
    _In_ ULONG FeatureId,
    _In_ XSTATE_CONFIGURATION XState,
    _Out_opt_ PULONG Length);

/**
 * The RtlLocateLegacyContext routine locates the legacy CONTEXT structure within an extended context.
 *
 * \param ContextEx A pointer to the extended context.
 * \param Length An optional pointer to a variable that receives the length of the legacy context.
 * \return A pointer to the legacy CONTEXT structure.
 */
NTSYSAPI
PCONTEXT
NTAPI
RtlLocateLegacyContext(
    _In_ PCONTEXT_EX ContextEx,
    _Out_opt_ PULONG Length);

/**
 * The RtlSetExtendedFeaturesMask routine sets the mask of extended processor features in an extended context.
 *
 * \param ContextEx A pointer to the extended context.
 * \param FeatureMask The mask of extended processor features to set.
 */
NTSYSAPI
VOID
NTAPI
RtlSetExtendedFeaturesMask(
    _In_ PCONTEXT_EX ContextEx,
    _In_ ULONG64 FeatureMask);

EXTERN_C_END
