#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

typedef struct _TIME_FIELDS
{
    CSHORT Year; // 1601...
    CSHORT Month; // 1..12
    CSHORT Day; // 1..31
    CSHORT Hour; // 0..23
    CSHORT Minute; // 0..59
    CSHORT Second; // 0..59
    CSHORT Milliseconds; // 0..999
    CSHORT Weekday; // 0..6 = Sunday..Saturday
} TIME_FIELDS, *PTIME_FIELDS;

NTSYSAPI
BOOLEAN
NTAPI
RtlCutoverTimeToSystemTime(
    _In_ PTIME_FIELDS CutoverTime,
    _Out_ PLARGE_INTEGER SystemTime,
    _In_ PLARGE_INTEGER CurrentSystemTime,
    _In_ BOOLEAN ThisYear
);

NTSYSAPI
NTSTATUS
NTAPI
RtlSystemTimeToLocalTime(
    _In_ PLARGE_INTEGER SystemTime,
    _Out_ PLARGE_INTEGER LocalTime
);

NTSYSAPI
NTSTATUS
NTAPI
RtlLocalTimeToSystemTime(
    _In_ PLARGE_INTEGER LocalTime,
    _Out_ PLARGE_INTEGER SystemTime
);

NTSYSAPI
VOID
NTAPI
RtlTimeToElapsedTimeFields(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields
);

NTSYSAPI
VOID
NTAPI
RtlTimeToTimeFields(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields
);

NTSYSAPI
BOOLEAN
NTAPI
RtlTimeFieldsToTime(
    _In_ PTIME_FIELDS TimeFields, // Weekday is ignored
    _Out_ PLARGE_INTEGER Time
);

#define SecondsToStartOf1980 LONGLONG_C(11960006400)
#define SecondsToStartOf1970 LONGLONG_C(11644473600)

NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1980(
    _In_ PLARGE_INTEGER Time,
    _Out_ PULONG ElapsedSeconds
);

NTSYSAPI
VOID
NTAPI
RtlSecondsSince1980ToTime(
    _In_ ULONG ElapsedSeconds,
    _Out_ PLARGE_INTEGER Time
);

NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1970(
    _In_ PLARGE_INTEGER Time,
    _Out_ PULONG ElapsedSeconds
);

NTSYSAPI
VOID
NTAPI
RtlSecondsSince1970ToTime(
    _In_ ULONG ElapsedSeconds,
    _Out_ PLARGE_INTEGER Time
);

#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSYSAPI
LARGE_INTEGER
NTAPI
RtlGetSystemTimePrecise(
    VOID
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_NI)
NTSYSAPI
ULONGLONG
NTAPI
RtlGetSystemTimeAndBias(
    _Out_ PLARGE_INTEGER TimeZoneBias,
    _Out_opt_ PLARGE_INTEGER TimeZoneBiasEffectiveStart,
    _Out_opt_ PLARGE_INTEGER TimeZoneBiasEffectiveEnd
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10)
NTSYSAPI
LARGE_INTEGER
NTAPI
RtlGetInterruptTimePrecise(
    _Out_ PLARGE_INTEGER PerformanceCounter
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
NTSYSAPI
BOOLEAN
NTAPI
RtlQueryUnbiasedInterruptTime(
    _Out_ PLARGE_INTEGER InterruptTime
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN11_GE)
// RtlGetMultiTimePrecise RequestedMask/ProvidedMask bits
#define RTL_GET_MULTI_TIME_PRECISE_PERF_COUNTER        0x00000001UL
#define RTL_GET_MULTI_TIME_PRECISE_HV_CORRELATED_TIME  0x00000002UL
#define RTL_GET_MULTI_TIME_PRECISE_SHAREDUSER_TIME     0x00000004UL
#define RTL_GET_MULTI_TIME_PRECISE_SUPPORTED_MASK      0x00000007UL

typedef struct _RTL_MULTI_TIME_PRECISE
{
    ULONGLONG PerformanceCounter;
    ULONGLONG HypervisorCorrelatedTime;
    ULONGLONG SharedUserTime;
} RTL_MULTI_TIME_PRECISE, *PRTL_MULTI_TIME_PRECISE;

NTSYSAPI
NTSTATUS
NTAPI
RtlGetMultiTimePrecise(
    _Out_ PRTL_MULTI_TIME_PRECISE TimesOut,
    _In_ ULONG RequestedMask,
    _Out_ PULONG ProvidedMask
);
#endif

// Time zones

typedef struct _RTL_TIME_ZONE_INFORMATION
{
    LONG Bias;
    WCHAR StandardName[32];
    TIME_FIELDS StandardStart;
    LONG StandardBias;
    WCHAR DaylightName[32];
    TIME_FIELDS DaylightStart;
    LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryTimeZoneInformation(
    _Out_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetTimeZoneInformation(
    _In_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
);

EXTERN_C_END
