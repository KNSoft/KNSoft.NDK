#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * The RtlCreateEnvironment routine creates a new environment block, optionally cloning the current process environment.
 *
 * \param CloneCurrentEnvironment TRUE to clone the current environment; FALSE to create an empty one.
 * \param Environment Receives the newly created environment block.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateEnvironment(
    _In_ BOOLEAN CloneCurrentEnvironment,
    _Out_ PVOID *Environment
    );

// begin_rev
/**
 * Flags for RtlCreateEnvironmentEx.
 */
#define RTL_CREATE_ENVIRONMENT_TRANSLATE 0x1 // translate from multi-byte to Unicode
#define RTL_CREATE_ENVIRONMENT_TRANSLATE_FROM_OEM 0x2 // translate from OEM to Unicode (Translate flag must also be set)
#define RTL_CREATE_ENVIRONMENT_EMPTY 0x4 // create empty environment block
// end_rev

/**
 * The RtlCreateEnvironmentEx routine creates a new environment block from an optional source environment.
 *
 * \param SourceEnvironment An optional source environment block to copy from.
 * \param Environment Receives the newly created environment block.
 * \param Flags Flags controlling creation.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateEnvironmentEx(
    _In_opt_ PVOID SourceEnvironment,
    _Out_ PVOID *Environment,
    _In_ ULONG Flags
    );

/**
 * The RtlDestroyEnvironment routine destroys an environment block created by RtlCreateEnvironment or
 * RtlCreateEnvironmentEx.
 *
 * \param Environment The environment block to destroy.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyEnvironment(
    _In_ _Post_invalid_ PVOID Environment
    );

/**
 * The RtlSetCurrentEnvironment routine sets the environment block for the current process.
 *
 * \param Environment The environment block to make current.
 * \param PreviousEnvironment An optional pointer that receives the previous environment block.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetCurrentEnvironment(
    _In_ PVOID Environment,
    _Out_opt_ PVOID *PreviousEnvironment
    );

/**
 * The RtlSetEnvironmentVar routine sets or removes an environment variable within an environment block, using counted
 * strings.
 *
 * \param Environment An optional pointer to the environment block to modify; NULL uses the current environment.
 * \param Name The name of the environment variable.
 * \param NameLength The length, in characters, of Name.
 * \param Value The value to set, or NULL to remove the variable.
 * \param ValueLength The length, in characters, of Value.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentVar(
    _Inout_opt_ PVOID *Environment,
    _In_reads_(NameLength) PCWSTR Name,
    _In_ SIZE_T NameLength,
    _In_reads_(ValueLength) PCWSTR Value,
    _In_opt_ SIZE_T ValueLength
    );

/**
 * The RtlSetEnvironmentVariable routine sets or removes an environment variable within an environment block.
 *
 * \param Environment An optional pointer to the environment block to modify; NULL uses the current environment.
 * \param Name The name of the environment variable.
 * \param Value The value to set, or NULL to remove the variable.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentVariable(
    _Inout_opt_ PVOID *Environment,
    _In_ PUNICODE_STRING Name,
    _In_opt_ PUNICODE_STRING Value
    );

// private
/**
 * The RtlQueryEnvironmentVariable routine retrieves the value of an environment variable, using counted strings.
 *
 * \param Environment An optional environment block to query; NULL uses the current environment.
 * \param Name The name of the environment variable.
 * \param NameLength The length, in characters, of Name.
 * \param Value An optional buffer that receives the value.
 * \param ValueLength The length, in characters, of the Value buffer.
 * \param ReturnLength Receives the length, in characters, of the value.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryEnvironmentVariable(
    _In_opt_ PVOID Environment,
    _In_reads_(NameLength) PCWSTR Name,
    _In_ SIZE_T NameLength,
    _Out_writes_opt_(ValueLength) PWSTR Value,
    _In_opt_ SIZE_T ValueLength,
    _Out_ PSIZE_T ReturnLength
    );

/**
 * The RtlQueryEnvironmentVariable_U routine retrieves the value of an environment variable.
 *
 * \param Environment An optional environment block to query; NULL uses the current environment.
 * \param Name The name of the environment variable.
 * \param Value Receives the value of the environment variable.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryEnvironmentVariable_U(
    _In_opt_ PVOID Environment,
    _In_ PUNICODE_STRING Name,
    _Inout_ PUNICODE_STRING Value
    );

/**
 * The RtlExpandEnvironmentStrings routine expands environment-variable references within a string, using counted
 * strings.
 *
 * \param Environment An optional environment block used for expansion; NULL uses the current environment.
 * \param Source The source string containing references to expand.
 * \param SourceLength The length, in characters, of Source.
 * \param Destination A buffer that receives the expanded string.
 * \param DestinationLength The length, in characters, of the Destination buffer.
 * \param ReturnLength An optional pointer that receives the length, in characters, of the expanded string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlExpandEnvironmentStrings(
    _In_opt_ PVOID Environment,
    _In_reads_(SourceLength) PCWSTR Source,
    _In_ SIZE_T SourceLength,
    _Out_writes_(DestinationLength) PWSTR Destination,
    _In_ SIZE_T DestinationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

/**
 * The RtlExpandEnvironmentStrings_U routine expands environment-variable references within a string.
 *
 * \param Environment An optional environment block used for expansion; NULL uses the current environment.
 * \param Source The source string containing references to expand.
 * \param Destination Receives the expanded string.
 * \param ReturnedLength An optional pointer that receives the length, in bytes, of the expanded string.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlExpandEnvironmentStrings_U(
    _In_opt_ PVOID Environment,
    _In_ PUNICODE_STRING Source,
    _Inout_ PUNICODE_STRING Destination,
    _Out_opt_ PULONG ReturnedLength
    );

/**
 * The RtlSetEnvironmentStrings routine replaces the environment block of the current process with the specified
 * environment strings.
 *
 * \param NewEnvironment A pointer to the new environment block, consisting of null-terminated name=value strings
 * terminated by an additional null character.
 * \param NewEnvironmentSize The size, in bytes, of the new environment block.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentStrings(
    _In_ PCWSTR NewEnvironment,
    _In_ SIZE_T NewEnvironmentSize
    );

EXTERN_C_END
