#pragma once

#include "../MinDef.h"

EXTERN_C_START

#pragma region Exception

/**
 * Continues execution from a supplied processor context.
 *
 * \param ContextRecord A pointer to the processor context from which execution is to continue.
 * \param TestAlert TRUE to test the current thread for pending alerts before continuing; otherwise, FALSE.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtContinue(
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN TestAlert);

#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)

/**
 * Identifies the continuation operation requested from NtContinueEx.
 */
typedef enum _KCONTINUE_TYPE
{
    KCONTINUE_UNWIND,   // Continue an unwind operation.
    KCONTINUE_RESUME,   // Resume execution from the supplied context.
    KCONTINUE_LONGJUMP, // Perform a long-jump continuation.
    KCONTINUE_SET,      // Set the supplied continuation context.
    KCONTINUE_LAST,     // Maximum continuation type value.
} KCONTINUE_TYPE;

/** Requests alert testing while continuing execution. */
#define KCONTINUE_FLAG_TEST_ALERT 0x00000001
/** Requests delivery of a pending user-mode APC while continuing execution. */
#define KCONTINUE_FLAG_DELIVER_APC 0x00000002

/**
 * Describes an extended continuation operation for NtContinueEx.
 */
typedef struct _KCONTINUE_ARGUMENT
{
    KCONTINUE_TYPE ContinueType; // The requested continuation operation.
    ULONG ContinueFlags;         // A combination of KCONTINUE_FLAG_* values.
    ULONGLONG Reserved[2];        // Reserved; initialize to zero.
} KCONTINUE_ARGUMENT, *PKCONTINUE_ARGUMENT;

/**
 * Continues execution from a supplied processor context using extended continuation arguments.
 *
 * \param ContextRecord A pointer to the processor context from which execution is to continue.
 * \param ContinueArgument Either a pointer to a KCONTINUE_ARGUMENT structure or a BOOLEAN value encoded as a pointer
 * for the legacy TestAlert form.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtContinueEx(
    _In_ PCONTEXT ContextRecord,
    _In_ PVOID ContinueArgument // "PKCONTINUE_ARGUMENT ContinueArgument" and "BOOLEAN TestAlert" are valid
);


#endif

/**
 * Raises an exception using the supplied exception and processor context records.
 *
 * \param ExceptionRecord A pointer to the exception record that describes the exception.
 * \param ContextRecord A pointer to the processor context at which the exception occurred.
 * \param FirstChance TRUE to process the exception as a first-chance exception; FALSE to process it as a second-chance
 * exception.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtRaiseException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN FirstChance);

#pragma endregion phnt

EXTERN_C_END
