#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemTime(
    _Out_ PLARGE_INTEGER SystemTime);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetSystemTime(
    _In_opt_ PLARGE_INTEGER SystemTime,
    _Out_opt_ PLARGE_INTEGER PreviousTime);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryTimerResolution(
    _Out_ PULONG MaximumTime,
    _Out_ PULONG MinimumTime,
    _Out_ PULONG CurrentTime);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetTimerResolution(
    _In_ ULONG DesiredTime,
    _In_ BOOLEAN SetResolution,
    _Out_ PULONG ActualTime);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryPerformanceCounter(
    _Out_ PLARGE_INTEGER PerformanceCounter,
    _Out_opt_ PLARGE_INTEGER PerformanceFrequency);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryAuxiliaryCounterFrequency(
    _Out_ PLARGE_INTEGER AuxiliaryCounterFrequency);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
    _In_ BOOLEAN ConvertAuxiliaryToPerformanceCounter,
    _In_ PLARGE_INTEGER PerformanceOrAuxiliaryCounterValue,
    _Out_ PLARGE_INTEGER ConvertedValue,
    _Out_opt_ PLARGE_INTEGER ConversionError);

#endif

NTSYSCALLAPI
ULONGLONG
NtGetTickCount64(VOID);

NTSYSCALLAPI
ULONG
NtGetTickCount(VOID);

EXTERN_C_END
