#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Represents a time value broken into its individual calendar fields.
 */
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

/**
 * The RtlCutoverTimeToSystemTime routine converts a daylight-saving cutover time to an absolute system time.
 *
 * \param CutoverTime A pointer to the TIME_FIELDS structure describing the cutover time.
 * \param SystemTime A pointer to a variable that receives the resulting absolute system time.
 * \param CurrentSystemTime A pointer to the current system time used to resolve the cutover.
 * \param ThisYear A boolean that specifies whether the cutover is resolved for the current year.
 * \return `TRUE` if the conversion succeeded, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcutovertimetosystemtime
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlCutoverTimeToSystemTime(
    _In_ PTIME_FIELDS CutoverTime,
    _Out_ PLARGE_INTEGER SystemTime,
    _In_ PLARGE_INTEGER CurrentSystemTime,
    _In_ BOOLEAN ThisYear
);

/**
 * The RtlSystemTimeToLocalTime routine converts a system (UTC) time to local time.
 *
 * \param SystemTime A pointer to the system time to convert.
 * \param LocalTime A pointer to a variable that receives the resulting local time.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsystemtimetolocaltime
 */
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

/**
 * The RtlTimeToElapsedTimeFields routine converts an elapsed-time interval to a TIME_FIELDS structure.
 *
 * \param Time A pointer to the elapsed-time interval, in 100-nanosecond units.
 * \param TimeFields A pointer to a TIME_FIELDS structure that receives the converted elapsed time.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetoelapsedtimefields
 */
NTSYSAPI
VOID
NTAPI
RtlTimeToElapsedTimeFields(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields
);

/**
 * The RtlTimeToTimeFields routine converts a system time to a TIME_FIELDS structure.
 *
 * \param Time A pointer to the system time, in 100-nanosecond units, to convert.
 * \param TimeFields A pointer to a TIME_FIELDS structure that receives the converted time.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimetotimefields
 */
NTSYSAPI
VOID
NTAPI
RtlTimeToTimeFields(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields
);

/**
 * The RtlTimeFieldsToTime routine converts a TIME_FIELDS structure into a 64-bit system time value.
 *
 * \param TimeFields A pointer to the TIME_FIELDS structure to convert. The Weekday member is ignored.
 * \param Time A pointer to a variable that receives the converted system time.
 * \return Returns `TRUE` if the time fields are valid and the conversion succeeds, otherwise `FALSE`.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimefieldstotime
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlTimeFieldsToTime(
    _In_ PTIME_FIELDS TimeFields, // Weekday is ignored
    _Out_ PLARGE_INTEGER Time
);

/**
 * Constants giving the number of seconds from 1970 to the start of 1980.
 */
#define SecondsToStartOf1980 LONGLONG_C(11960006400)
#define SecondsToStartOf1970 LONGLONG_C(11644473600)

/**
 * The RtlTimeToSecondsSince1980 routine converts a 64-bit system time value into the number of seconds elapsed since
 * January 1, 1980.
 *
 * \param Time A pointer to the system time value to convert.
 * \param ElapsedSeconds A pointer to a variable that receives the number of elapsed seconds since 1980.
 * \return Returns `TRUE` if the conversion succeeds, otherwise `FALSE` if the time is out of range.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtltimetosecondssince1980
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlTimeToSecondsSince1980(
    _In_ PLARGE_INTEGER Time,
    _Out_ PULONG ElapsedSeconds
);

/**
 * The RtlSecondsSince1980ToTime routine converts a number of seconds elapsed since January 1, 1980 into a 64-bit system
 * time value.
 *
 * \param ElapsedSeconds The number of elapsed seconds since 1980 to convert.
 * \param Time A pointer to a variable that receives the converted system time.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlsecondssince1980totime
 */
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

/**
 * The RtlSecondsSince1970ToTime routine converts a number of seconds elapsed since January 1, 1970 into a 64-bit system
 * time value.
 *
 * \param ElapsedSeconds The number of elapsed seconds since 1970 to convert.
 * \param Time A pointer to a variable that receives the converted system time.
 */
NTSYSAPI
VOID
NTAPI
RtlSecondsSince1970ToTime(
    _In_ ULONG ElapsedSeconds,
    _Out_ PLARGE_INTEGER Time
);

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlGetSystemTimePrecise routine returns the current system time with the highest available precision.
 *
 * \return ULONGLONG The current system time, in 100-nanosecond intervals since January 1, 1601 (UTC).
 */
NTSYSAPI
LARGE_INTEGER
NTAPI
RtlGetSystemTimePrecise(
    VOID
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_NI)
/**
 * The RtlGetSystemTimeAndBias routine returns the current system time together with the current time zone bias and the
 * effective range of that bias.
 *
 * \param TimeZoneBias A pointer to a variable that receives the current time zone bias, in 100-nanosecond intervals.
 * \param TimeZoneBiasEffectiveStart An optional pointer to a variable that receives the time at which the current bias
 * became effective.
 * \param TimeZoneBiasEffectiveEnd An optional pointer to a variable that receives the time at which the current bias
 * ceases to be effective.
 * \return ULONGLONG The current system time, in 100-nanosecond intervals since January 1, 1601 (UTC).
 */
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
/**
 * The RtlGetInterruptTimePrecise routine returns the current interrupt time with the highest available precision,
 * together with the correlated performance counter.
 *
 * \param PerformanceCounter A pointer to a variable that receives the performance counter value correlated with the
 * returned interrupt time.
 * \return ULONGLONG The current interrupt time, in 100-nanosecond intervals.
 */
NTSYSAPI
LARGE_INTEGER
NTAPI
RtlGetInterruptTimePrecise(
    _Out_ PLARGE_INTEGER PerformanceCounter
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN8)
/**
 * The RtlQueryUnbiasedInterruptTime routine returns the current unbiased interrupt time, which excludes time spent in
 * suspend or connected-standby states.
 *
 * \param InterruptTime A pointer to a variable that receives the current unbiased interrupt time, in 100-nanosecond
 * intervals.
 * \return Returns `TRUE` if the unbiased interrupt time was retrieved successfully, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlQueryUnbiasedInterruptTime(
    _Out_ PLARGE_INTEGER InterruptTime
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN11_GE)
// RtlGetMultiTimePrecise RequestedMask/ProvidedMask bits
/**
 * Request flags for RtlGetMultiTimePrecise.
 */
#define RTL_GET_MULTI_TIME_PRECISE_PERF_COUNTER        0x00000001UL
#define RTL_GET_MULTI_TIME_PRECISE_HV_CORRELATED_TIME  0x00000002UL
#define RTL_GET_MULTI_TIME_PRECISE_SHAREDUSER_TIME     0x00000004UL
#define RTL_GET_MULTI_TIME_PRECISE_SUPPORTED_MASK      0x00000007UL

/**
 * Contains multiple precise system time values captured together.
 */
typedef struct _RTL_MULTI_TIME_PRECISE
{
    ULONGLONG PerformanceCounter;
    ULONGLONG HypervisorCorrelatedTime;
    ULONGLONG SharedUserTime;
} RTL_MULTI_TIME_PRECISE, *PRTL_MULTI_TIME_PRECISE;

/**
 * The RtlGetMultiTimePrecise routine retrieves several correlated high-precision time values in a single call,
 * according to a caller-supplied request mask.
 *
 * \param TimesOut A pointer to a RTL_MULTI_TIME_PRECISE structure that receives the requested time values.
 * \param RequestedMask A bit mask selecting which time values to retrieve (for example, performance counter,
 * hypervisor-correlated time, and shared user time).
 * \param ProvidedMask A pointer to a variable that receives the mask of time values that were actually provided.
 * \return NTSTATUS Successful or errant status.
 */
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

/**
 * The RtlQueryTimeZoneInformation routine retrieves the current time zone information for the system.
 *
 * \param TimeZoneInformation A pointer to a RTL_TIME_ZONE_INFORMATION structure that receives the current time zone
 * settings.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryTimeZoneInformation(
    _Out_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
);

/**
 * The RtlSetTimeZoneInformation routine sets the current time zone information for the system.
 *
 * \param TimeZoneInformation A pointer to a RTL_TIME_ZONE_INFORMATION structure that specifies the time zone settings
 * to apply.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetTimeZoneInformation(
    _In_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
);

// RtlQueryUnbiasedInterruptTimePrecise
/**
 * The RtlQueryUnbiasedInterruptTimePrecise routine returns the current unbiased interrupt time with the highest
 * available precision.
 *
 * \param InterruptTime A pointer to a variable that receives the current unbiased interrupt time, in 100-nanosecond
 * intervals.
 * \return ULONGLONG The current biased interrupt time, in 100-nanosecond intervals, used to correlate the unbiased
 * value.
 */
NTSYSAPI
ULONGLONG
NTAPI
RtlQueryUnbiasedInterruptTimePrecise(
    _Out_ PLARGE_INTEGER InterruptTime
    );

// RtlpCheckDynamicTimeZoneInformation
/**
 * The RtlpCheckDynamicTimeZoneInformation routine re-evaluates dynamic time-zone data for a given year and updates the
 * caller's structure in place if the transition rules have changed.
 *
 * \details Opens the registry handle for the zone named in
 * \p TimeZoneInformation->TimeZoneKeyName (via RtlpGetDynamicTimeZoneInfoHandle),
 * loads the REG_TZI record applicable to \p Year (RtlpFindRegTziForCurrentYear),
 * converts it to TIME_ZONE_INFORMATION form (RtlpRegTziFormatToTzi), and
 * memcmp's the first 0xAC bytes against \p TimeZoneInformation. If they differ,
 * the bias/date fields are overwritten while the descriptive name strings are preserved.
 * \param[in,out] TimeZoneInformation The dynamic time-zone info to validate and,
 * if stale, refresh in place.
 * \param[in] Year The (dynamic) year whose transition rules should be applied.
 * \return TRUE if \p TimeZoneInformation was updated; FALSE if it was already
 * current or the registry lookup failed.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlpCheckDynamicTimeZoneInformation(
    _Inout_ PDYNAMIC_TIME_ZONE_INFORMATION TimeZoneInformation,
    _In_ USHORT Year
    );

// RtlpFreezeTimeBias
/**
 * Accumulated system freeze/suspend bias, in 100-nanosecond units.
 *
 * \details Total time the system has spent in a frozen/suspended
 * (connected-standby) state. Subtracted from the raw interrupt time to yield
 * *unbiased* interrupt time:
 * \code
 * UnbiasedInterruptTime = SharedUserData->InterruptTime      // KUSER_SHARED_DATA+0x08
 *                       - RtlpFreezeTimeBias                 // this value
 *                       - SharedUserData->QpcBias;           // KUSER_SHARED_DATA+0x3B0
 * \endcode
 * Consumed by RtlQueryUnbiasedInterruptTime and the threadpool/WNF timer paths,
 * which read it in a torn-read guard loop since it is a 64-bit value updated by
 * the kernel.
 */
NTSYSAPI LONGLONG RtlpFreezeTimeBias;

// RtlpTimeFieldsToTime
/**
 * The RtlpTimeFieldsToTime routine converts a TIME_FIELDS structure into a system time value, accounting for an
 * optional leap-second context.
 *
 * \param TimeFields A pointer to the TIME_FIELDS structure to convert.
 * \param Time A pointer to a variable that receives the converted system time.
 * \param LeapSecondContext An optional pointer to the leap-second context used during conversion.
 * \return Returns `TRUE` if the conversion succeeds, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlpTimeFieldsToTime(
    _In_ PTIME_FIELDS TimeFields,
    _Out_ PLARGE_INTEGER Time,
    _In_opt_ PLARGE_INTEGER LeapSecondContext
    );

// RtlpTimeToTimeFields
/**
 * The RtlpTimeToTimeFields routine converts a system time value into a TIME_FIELDS structure, accounting for an
 * optional leap-second context.
 *
 * \param Time A pointer to the system time value to convert.
 * \param TimeFields A pointer to the TIME_FIELDS structure that receives the converted time.
 * \param LeapSecondContext An optional pointer to the leap-second context used during conversion.
 * \return SHORT The number of leap seconds applied during the conversion.
 */
NTSYSAPI
SHORT
NTAPI
RtlpTimeToTimeFields(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields,
    _In_opt_ PLARGE_INTEGER LeapSecondContext
    );

// RtlQueryDynamicTimeZoneInformation
// NTSYSAPI
// ULONG
// NTAPI
// RtlOsDeploymentState(
//     _In_ ULONG Flags
//     );

// rev
/**
 * The RtlQueryDynamicTimeZoneInformation routine retrieves the current dynamic time zone information for the system.
 *
 * \param DynamicTimeZoneInformation Receives the dynamic time zone information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryDynamicTimeZoneInformation(
    _Out_ PDYNAMIC_TIME_ZONE_INFORMATION DynamicTimeZoneInformation
    );

// RtlSetDynamicTimeZoneInformation
/**
 * The RtlSetDynamicTimeZoneInformation routine sets the system dynamic time zone information.
 *
 * \param DynamicTimeZoneInformation A pointer to the DYNAMIC_TIME_ZONE_INFORMATION to apply.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetDynamicTimeZoneInformation(
    _In_ PDYNAMIC_TIME_ZONE_INFORMATION DynamicTimeZoneInformation
    );

// RtlConvertHostPerfCounterToPerfCounter
/**
 * The RtlConvertHostPerfCounterToPerfCounter routine converts a host performance counter value into the guest
 * performance counter timebase.
 *
 * \param HostCounter The host performance counter value to convert.
 * \param MaxDelta The maximum allowed delta used to bound the conversion.
 * \param PerfCounterOut A pointer to a variable that receives the converted performance counter value.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlConvertHostPerfCounterToPerfCounter(
    _In_ ULONGLONG HostCounter,
    _In_ ULONGLONG MaxDelta,
    _Out_ ULONGLONG *PerfCounterOut
    );

EXTERN_C_END
