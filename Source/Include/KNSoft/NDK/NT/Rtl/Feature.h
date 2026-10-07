#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

// private
/**
 * Identifies a feature in the feature configuration store.
 */
typedef ULONG RTL_FEATURE_ID;
/**
 * Represents a stamp that changes whenever the feature configuration is modified.
 */
typedef ULONGLONG RTL_FEATURE_CHANGE_STAMP, *PRTL_FEATURE_CHANGE_STAMP;
/**
 * Represents the variant selected for a feature.
 */
typedef UCHAR RTL_FEATURE_VARIANT;
/**
 * Represents the payload value associated with a feature variant.
 */
typedef ULONG RTL_FEATURE_VARIANT_PAYLOAD;
/**
 * Represents a registration for feature configuration change notifications.
 */
typedef PVOID RTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION, *PRTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION;

// private
/**
 * Describes a feature usage report submitted to the feature configuration store.
 */
typedef struct _RTL_FEATURE_USAGE_REPORT
{
    ULONG FeatureId;
    USHORT ReportingKind;
    USHORT ReportingOptions;
} RTL_FEATURE_USAGE_REPORT, *PRTL_FEATURE_USAGE_REPORT;

// private
/**
 * Identifies the type of a feature configuration.
 */
typedef enum _RTL_FEATURE_CONFIGURATION_TYPE
{
    RtlFeatureConfigurationBoot,
    RtlFeatureConfigurationRuntime,
    RtlFeatureConfigurationCount
} RTL_FEATURE_CONFIGURATION_TYPE;

// private
/**
 * Describes the configuration of a single feature.
 */
typedef struct _RTL_FEATURE_CONFIGURATION
{
    ULONG FeatureId;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG Priority : 4;
            ULONG EnabledState : 2;
            ULONG IsWexpConfiguration : 1;
            ULONG HasSubscriptions : 1;
            ULONG Variant : 6;
            ULONG VariantPayloadKind : 2;
            ULONG Reserved : 16;
        };
    };
    ULONG VariantPayload;
} RTL_FEATURE_CONFIGURATION, *PRTL_FEATURE_CONFIGURATION;

// private
/**
 * Internal representation of a feature configuration entry.
 */
typedef struct _RTL_FEATURE_CONFIGURATION_INTERNAL
{
    ULONG FeatureId;
    union
    {
        struct
        {
            ULONG Priority : 4;
            ULONG EnabledState : 2;
            ULONG IsWexpConfiguration : 1;
            ULONG HasSubscriptions : 1;
            ULONG Variant : 6;
            ULONG VariantPayloadKind : 2;
            ULONG Reserved : 16;
        };
        ULONG Flags;
    };
    ULONG VariantPayload;
    union
    {
        struct
        {
            ULONG ChangeTimeUpgrade : 1;
            ULONG HasGroupBypass : 1;
            ULONG Reserved2 : 30;
        };
        ULONG Flags2;
    };
} RTL_FEATURE_CONFIGURATION_INTERNAL, *PRTL_FEATURE_CONFIGURATION_INTERNAL;

// private
/**
 * Describes a single feature configuration section entry.
 */
typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY
{
    RTL_FEATURE_CHANGE_STAMP ChangeStamp;
    HANDLE SectionHandle;
    SIZE_T Size;
} SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY, *PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY;

// private
/**
 * Identifies the type of a feature configuration section.
 */
typedef enum _SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE
{
    SystemFeatureConfigurationSectionTypeBoot = 0,
    SystemFeatureConfigurationSectionTypeRuntime = 1,
    SystemFeatureConfigurationSectionTypeUsageTriggers = 2,
    SystemFeatureConfigurationSectionTypeGoverned = 3,
    SystemFeatureConfigurationSectionTypeCount
} SYSTEM_FEATURE_CONFIGURATION_SECTION_TYPE;

// private
/**
 * Specifies a request for feature configuration section information.
 */
typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST
{
    RTL_FEATURE_CHANGE_STAMP PreviousChangeStamps[SystemFeatureConfigurationSectionTypeCount];
} SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, *PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST;

// private
/**
 * Contains information about feature configuration sections.
 */
typedef struct _SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
{
    RTL_FEATURE_CHANGE_STAMP OverallChangeStamp;
    SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION_ENTRY Descriptors[SystemFeatureConfigurationSectionTypeCount];
} SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION, *PSYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION;

//typedef struct _SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
//{
//    ULONG UpdateCount;
//    _Field_size_(UpdateCount) SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE_ENTRY Updates[ANYSIZE_ARRAY];
//} SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE, *PSYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE;

// private
/**
 * Represents a table of feature configuration entries.
 */
typedef struct _RTL_FEATURE_CONFIGURATION_TABLE
{
    ULONG FeatureCount;
    _Field_size_(FeatureCount) RTL_FEATURE_CONFIGURATION_INTERNAL Features[ANYSIZE_ARRAY];
} RTL_FEATURE_CONFIGURATION_TABLE, *PRTL_FEATURE_CONFIGURATION_TABLE;

// private
/**
 * Identifies the priority level of a feature configuration.
 */
typedef enum _RTL_FEATURE_CONFIGURATION_PRIORITY
{
    FeatureConfigurationPriorityImageDefault   = 0,
    FeatureConfigurationPriorityEKB            = 1,
    FeatureConfigurationPrioritySafeguard      = 2,
    FeatureConfigurationPriorityPersistent     = FeatureConfigurationPrioritySafeguard,
    FeatureConfigurationPriorityReserved3      = 3,
    FeatureConfigurationPriorityService        = 4,
    FeatureConfigurationPriorityReserved5      = 5,
    FeatureConfigurationPriorityDynamic        = 6,
    FeatureConfigurationPriorityReserved7      = 7,
    FeatureConfigurationPriorityUser           = 8,
    FeatureConfigurationPrioritySecurity       = 9,
    FeatureConfigurationPriorityUserPolicy     = 10,
    FeatureConfigurationPriorityReserved11     = 11,
    FeatureConfigurationPriorityTest           = 12,
    FeatureConfigurationPriorityReserved13     = 13,
    FeatureConfigurationPriorityReserved14     = 14,
    FeatureConfigurationPriorityImageOverride  = 15,
    FeatureConfigurationPriorityMax            = FeatureConfigurationPriorityImageOverride
} RTL_FEATURE_CONFIGURATION_PRIORITY, *PRTL_FEATURE_CONFIGURATION_PRIORITY;

// private
/**
 * Identifies whether a feature is enabled, disabled, or set to its default state.
 */
typedef enum _RTL_FEATURE_ENABLED_STATE
{
    FeatureEnabledStateDefault,
    FeatureEnabledStateDisabled,
    FeatureEnabledStateEnabled
} RTL_FEATURE_ENABLED_STATE;

// private
/**
 * Specifies options controlling how a feature enabled state is evaluated.
 */
typedef enum _RTL_FEATURE_ENABLED_STATE_OPTIONS
{
    FeatureEnabledStateOptionsNone,
    FeatureEnabledStateOptionsWexpConfig
} RTL_FEATURE_ENABLED_STATE_OPTIONS, *PRTL_FEATURE_ENABLED_STATE_OPTIONS;

// private
/**
 * Identifies the kind of payload carried by a feature variant.
 */
typedef enum _RTL_FEATURE_VARIANT_PAYLOAD_KIND
{
    FeatureVariantPayloadKindNone,
    FeatureVariantPayloadKindResident,
    FeatureVariantPayloadKindExternal
} RTL_FEATURE_VARIANT_PAYLOAD_KIND, *PRTL_FEATURE_VARIANT_PAYLOAD_KIND;

// private
/**
 * Identifies an operation performed on a feature configuration.
 */
typedef enum _RTL_FEATURE_CONFIGURATION_OPERATION
{
    FeatureConfigurationOperationNone         = 0,
    FeatureConfigurationOperationFeatureState = 1,
    FeatureConfigurationOperationVariantState = 2,
    FeatureConfigurationOperationResetState   = 4
} RTL_FEATURE_CONFIGURATION_OPERATION, *PRTL_FEATURE_CONFIGURATION_OPERATION;

/**
 * Masks and shifts for encoding a feature variant and its payload.
 */
#define RTL_FEATURE_VARIANT_MASK              0x000000FF
#define RTL_FEATURE_CHANGE_TIME_UPGRADE       0x00000100
#define RTL_FEATURE_HAS_GROUP_BYPASS          0x00000200

// private
/**
 * Describes an update to be applied to a feature configuration.
 */
typedef struct _RTL_FEATURE_CONFIGURATION_UPDATE
{
    RTL_FEATURE_ID FeatureId;
    RTL_FEATURE_CONFIGURATION_PRIORITY Priority;
    RTL_FEATURE_ENABLED_STATE EnabledState;
    RTL_FEATURE_ENABLED_STATE_OPTIONS EnabledStateOptions;

    union
    {
        ULONG VariantFlags;
        struct
        {
            UCHAR Variant;
            UCHAR Flags;
            USHORT ReservedFlags;
        } DUMMYSTRUCTNAME;
        struct
        {
            ULONG Variant_ : 8;
            ULONG ChangeTimeUpgrade : 1;
            ULONG HasGroupBypass : 1;
            ULONG Reserved_ : 22;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME;

    RTL_FEATURE_VARIANT_PAYLOAD_KIND VariantPayloadKind;
    UCHAR Reserved[3];
    RTL_FEATURE_VARIANT_PAYLOAD VariantPayload;
    RTL_FEATURE_CONFIGURATION_OPERATION Operation;
} RTL_FEATURE_CONFIGURATION_UPDATE, *PRTL_FEATURE_CONFIGURATION_UPDATE;

// private
/**
 * Describes the target of a feature usage subscription.
 */
typedef struct _RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET
{
    ULONG Data[2];
} RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET, *PRTL_FEATURE_USAGE_SUBSCRIPTION_TARGET;

// private
/**
 * Describes the details of a feature usage subscription.
 */
typedef struct _SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
{
    RTL_FEATURE_ID FeatureId;
    USHORT ReportingKind;
    USHORT ReportingOptions;
    RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET ReportingTarget;
} SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS, *PSYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS;

// private
/**
 * Contains usage data collected for a feature.
 */
typedef struct _RTL_FEATURE_USAGE_DATA
{
    RTL_FEATURE_ID FeatureId;
    USHORT ReportingKind;
    USHORT UsageCount;
} RTL_FEATURE_USAGE_DATA, *PRTL_FEATURE_USAGE_DATA;

// private
/**
 * Describes a feature usage subscription.
 */
typedef struct _RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS
{
    RTL_FEATURE_ID FeatureId;
    USHORT ReportingKind;
    USHORT ReportingOptions;
    RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET ReportingTarget;
} RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS, *PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS;

// private
/**
 * Represents a table of feature usage subscriptions.
 */
typedef struct _RTL_FEATURE_USAGE_SUBSCRIPTION_TABLE
{
    ULONG SubscriptionCount;
    _Field_size_(SubscriptionCount) RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS Subscriptions[ANYSIZE_ARRAY];
} RTL_FEATURE_USAGE_SUBSCRIPTION_TABLE, *PRTL_FEATURE_USAGE_SUBSCRIPTION_TABLE;

// private
/**
 * Describes a single feature usage subscription update entry.
 */
typedef struct _SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE_ENTRY
{
    ULONG Remove;
    RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS Details;
} SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE_ENTRY, *PSYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE_ENTRY;

// private
_Function_class_(RTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK)
typedef VOID (NTAPI RTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK)(
    _In_opt_ PVOID Context
    );
/**
 * Pointer to an RTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK callback.
 */
typedef RTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK *PRTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK;

// private
/**
 * Specifies a query for feature configuration information.
 */
typedef struct _SYSTEM_FEATURE_CONFIGURATION_QUERY
{
    RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType;
    RTL_FEATURE_ID FeatureId;
} SYSTEM_FEATURE_CONFIGURATION_QUERY, *PSYSTEM_FEATURE_CONFIGURATION_QUERY;

// private
/**
 * Contains feature configuration information returned by a query.
 */
typedef struct _SYSTEM_FEATURE_CONFIGURATION_INFORMATION
{
    RTL_FEATURE_CHANGE_STAMP ChangeStamp;
    RTL_FEATURE_CONFIGURATION Configuration;
} SYSTEM_FEATURE_CONFIGURATION_INFORMATION, *PSYSTEM_FEATURE_CONFIGURATION_INFORMATION;

// private
/**
 * Identifies the type of a feature configuration update.
 */
typedef enum _SYSTEM_FEATURE_CONFIGURATION_UPDATE_TYPE
{
    SystemFeatureConfigurationUpdateTypeUpdate = 0,
    SystemFeatureConfigurationUpdateTypeOverwrite = 1,
    SystemFeatureConfigurationUpdateTypeCount = 2,
} SYSTEM_FEATURE_CONFIGURATION_UPDATE_TYPE, *PSYSTEM_FEATURE_CONFIGURATION_UPDATE_TYPE;

// private
/**
 * Describes a feature configuration update request.
 */
typedef struct _SYSTEM_FEATURE_CONFIGURATION_UPDATE
{
    SYSTEM_FEATURE_CONFIGURATION_UPDATE_TYPE UpdateType;
    union
    {
        struct
        {
            RTL_FEATURE_CHANGE_STAMP PreviousChangeStamp;
            RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType;
            ULONG UpdateCount;
            _Field_size_(UpdateCount) RTL_FEATURE_CONFIGURATION_UPDATE Updates[ANYSIZE_ARRAY];
        } Update;

        struct
        {
            RTL_FEATURE_CHANGE_STAMP PreviousChangeStamp;
            RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType;
            SIZE_T BufferSize;
            PVOID Buffer;
        } Overwrite;
    };
} SYSTEM_FEATURE_CONFIGURATION_UPDATE, *PSYSTEM_FEATURE_CONFIGURATION_UPDATE;

// private
//typedef struct _SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
//{
//    RTL_FEATURE_ID FeatureId;
//    USHORT ReportingKind;
//    USHORT ReportingOptions;
//    RTL_FEATURE_USAGE_SUBSCRIPTION_TARGET ReportingTarget;
//} SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS, *PSYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS;

//typedef struct _SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE_ENTRY
//{
//    ULONG Remove;
//    RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS Details;
//} SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE_ENTRY, *PSYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE_ENTRY;
//
//typedef struct _SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
//{
//    ULONG UpdateCount;
//    _Field_size_(UpdateCount) SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE_ENTRY Updates[ANYSIZE_ARRAY];
//} SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE, *PSYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE;

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)

// private
/**
 * The RtlNotifyFeatureUsage routine reports usage of a staged feature to the feature configuration subsystem.
 *
 * \param FeatureUsageReport A pointer to an RTL_FEATURE_USAGE_REPORT structure that describes the feature usage.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlNotifyFeatureUsage(
    _In_ PRTL_FEATURE_USAGE_REPORT FeatureUsageReport
    );

// private
/**
 * The RtlQueryFeatureConfiguration routine retrieves the configuration of a staged feature.
 *
 * \param FeatureId The identifier of the feature to query.
 * \param ConfigurationType The RTL_FEATURE_CONFIGURATION_TYPE that selects the configuration store to query.
 * \param ChangeStamp A pointer to a variable that receives the change stamp of the returned configuration.
 * \param FeatureConfiguration A pointer to an RTL_FEATURE_CONFIGURATION structure that receives the feature
 * configuration.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryFeatureConfiguration(
    _In_ RTL_FEATURE_ID FeatureId,
    _In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
    _Out_ PRTL_FEATURE_CHANGE_STAMP ChangeStamp,
    _Out_ PRTL_FEATURE_CONFIGURATION FeatureConfiguration
    );

// private
/**
 * The RtlSetFeatureConfigurations routine applies a set of feature configuration updates.
 *
 * \param PreviousChangeStamp An optional pointer to the expected previous change stamp; the update is applied only if
 * it matches.
 * \param ConfigurationType The RTL_FEATURE_CONFIGURATION_TYPE that selects the configuration store to update.
 * \param ConfigurationUpdates A pointer to an array of RTL_FEATURE_CONFIGURATION_UPDATE entries to apply.
 * \param ConfigurationUpdateCount The number of entries in the ConfigurationUpdates array.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetFeatureConfigurations(
    _In_opt_ PRTL_FEATURE_CHANGE_STAMP PreviousChangeStamp,
    _In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
    _In_reads_(ConfigurationUpdateCount) PRTL_FEATURE_CONFIGURATION_UPDATE ConfigurationUpdates,
    _In_ SIZE_T ConfigurationUpdateCount
    );

// private
/**
 * The RtlQueryAllFeatureConfigurations routine retrieves all feature configurations from the specified configuration
 * store.
 *
 * \param ConfigurationType The RTL_FEATURE_CONFIGURATION_TYPE that selects the configuration store to query.
 * \param ChangeStamp An optional pointer to a variable that receives the change stamp of the returned configurations.
 * \param Configurations A buffer that receives the array of RTL_FEATURE_CONFIGURATION entries.
 * \param ConfigurationCount A pointer to the number of entries the buffer can hold; updated with the number of entries
 * available or written.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryAllFeatureConfigurations(
    _In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
    _Out_opt_ PRTL_FEATURE_CHANGE_STAMP ChangeStamp,
    _Out_writes_(*ConfigurationCount) PRTL_FEATURE_CONFIGURATION Configurations,
    _Inout_ PSIZE_T ConfigurationCount
    );

// private
/**
 * The RtlQueryAllInternalFeatureConfigurations routine retrieves all internal feature configurations from the specified
 * configuration store.
 *
 * \param ConfigurationType The RTL_FEATURE_CONFIGURATION_TYPE that selects the configuration store to query.
 * \param ChangeStamp An optional pointer to a variable that receives the change stamp of the returned configurations.
 * \param Configurations A buffer that receives the array of RTL_FEATURE_CONFIGURATION entries.
 * \param ConfigurationCount A pointer to the number of entries the buffer can hold; updated with the number of entries
 * available or written.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryAllInternalFeatureConfigurations(
    _In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
    _Out_opt_ PRTL_FEATURE_CHANGE_STAMP ChangeStamp,
    _Out_writes_(*ConfigurationCount) PRTL_FEATURE_CONFIGURATION Configurations,
    _Inout_ PSIZE_T ConfigurationCount
    );

// private
/**
 * The RtlQueryAllInternalRuntimeFeatureConfigurations routine retrieves all internal runtime feature configurations
 * related to the specified feature.
 *
 * \param FeatureId The identifier of the feature whose runtime configurations are queried.
 * \param ConfigurationType The RTL_FEATURE_CONFIGURATION_TYPE that selects the configuration store to query.
 * \param ChangeStamp An optional pointer to a variable that receives the change stamp of the returned configurations.
 * \param Configurations A buffer that receives the array of RTL_FEATURE_CONFIGURATION entries.
 * \param ConfigurationCount A pointer to the number of entries the buffer can hold; updated with the number of entries
 * available or written.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryAllInternalRuntimeFeatureConfigurations(
    _In_ RTL_FEATURE_ID FeatureId,
    _In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
    _Out_opt_ PRTL_FEATURE_CHANGE_STAMP ChangeStamp,
    _Out_writes_(*ConfigurationCount) PRTL_FEATURE_CONFIGURATION Configurations,
    _Inout_ PSIZE_T ConfigurationCount
    );

// private
/**
 * The RtlQueryFeatureConfigurationChangeStamp routine returns the current global feature configuration change stamp.
 *
 * \return RTL_FEATURE_CHANGE_STAMP The current feature configuration change stamp.
 */
NTSYSAPI
RTL_FEATURE_CHANGE_STAMP
NTAPI
RtlQueryFeatureConfigurationChangeStamp(
    VOID
    );

// private
/**
 * The RtlQueryFeatureUsageNotificationSubscriptions routine retrieves the current feature usage notification
 * subscriptions.
 *
 * \param Subscriptions A buffer that receives the array of RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS entries.
 * \param SubscriptionCount A pointer to the number of entries the buffer can hold; updated with the number of entries
 * available or written.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryFeatureUsageNotificationSubscriptions(
    _Out_writes_(*SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS Subscriptions,
    _Inout_ PSIZE_T SubscriptionCount
    );

// private
/**
 * The RtlRegisterFeatureConfigurationChangeNotification routine registers a callback invoked when the feature
 * configuration state changes.
 *
 * \param Callback The callback invoked on feature configuration changes.
 * \param Context An optional context value passed to the callback.
 * \param ObservedChangeStamp An optional change stamp last observed by the caller.
 * \param RegistrationHandle Receives the registration handle.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlRegisterFeatureConfigurationChangeNotification(
    _In_ PRTL_FEATURE_CONFIGURATION_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PRTL_FEATURE_CHANGE_STAMP ObservedChangeStamp,
    _Out_ PRTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION RegistrationHandle
    );

// private
/**
 * The RtlUnregisterFeatureConfigurationChangeNotification routine removes a feature configuration change notification
 * registration.
 *
 * \param RegistrationHandle The registration handle returned when the change notification was registered.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnregisterFeatureConfigurationChangeNotification(
    _In_ RTL_FEATURE_CONFIGURATION_CHANGE_REGISTRATION RegistrationHandle
    );

// private
/**
 * The RtlSubscribeForFeatureUsageNotification routine subscribes for notifications about usage of the specified
 * features.
 *
 * \param SubscriptionDetails A pointer to an array of RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS entries describing the
 * subscriptions.
 * \param SubscriptionCount The number of entries in the SubscriptionDetails array.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSubscribeForFeatureUsageNotification(
    _In_reads_(SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS SubscriptionDetails,
    _In_ SIZE_T SubscriptionCount
    );

// private
/**
 * The RtlUnsubscribeFromFeatureUsageNotifications routine removes feature usage notification subscriptions previously
 * created by RtlSubscribeForFeatureUsageNotification.
 *
 * \param SubscriptionDetails A pointer to an array of RTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS entries describing the
 * subscriptions to remove.
 * \param SubscriptionCount The number of entries in the SubscriptionDetails array.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlUnsubscribeFromFeatureUsageNotifications(
    _In_reads_(SubscriptionCount) PRTL_FEATURE_USAGE_SUBSCRIPTION_DETAILS SubscriptionDetails,
    _In_ SIZE_T SubscriptionCount
    );
#endif

// private
#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
/**
 * The RtlOverwriteFeatureConfigurationBuffer routine replaces the current feature configuration buffer.
 *
 * \param PreviousChangeStamp An optional change stamp that must match the current one for the update to occur.
 * \param ConfigurationType The type of feature configuration to overwrite.
 * \param ConfigurationBuffer An optional buffer containing the new feature configuration.
 * \param ConfigurationBufferSize The size, in bytes, of ConfigurationBuffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlOverwriteFeatureConfigurationBuffer(
    _In_opt_ PRTL_FEATURE_CHANGE_STAMP PreviousChangeStamp,
    _In_ RTL_FEATURE_CONFIGURATION_TYPE ConfigurationType,
    _In_reads_bytes_opt_(ConfigurationBufferSize) PVOID ConfigurationBuffer,
    _In_ ULONG ConfigurationBufferSize
    );
#endif

// rev
/**
 * The RtlNotifyFeatureToggleUsage routine reports usage of a feature toggle to the feature configuration subsystem.
 *
 * \param FeatureId The identifier of the feature toggle.
 * \param Configuration The feature configuration.
 * \param UsageKind The kind of feature usage being reported.
 * \return ULONG Status or result code.
 */
NTSYSAPI
ULONG
NTAPI
RtlNotifyFeatureToggleUsage(
    _In_ ULONG FeatureId,
    _In_ ULONGLONG Configuration,
    _In_ ULONG UsageKind
    );

// rev
/**
 * The RtlGetFeatureTogglesChangeToken routine returns a token that changes whenever the feature toggle state changes.
 *
 * \return ULONG The current feature toggles change token.
 */
NTSYSAPI
ULONG
NTAPI
RtlGetFeatureTogglesChangeToken(
    VOID
    );

// RtlGetFeatureToggleConfiguration
/**
 * The RtlGetFeatureToggleConfiguration routine returns the configuration value for a feature toggle.
 *
 * \param FeatureId The identifier of the feature toggle to query.
 * \param ConfigurationType The type of configuration value to retrieve.
 * \return ULONGLONG The configuration value for the feature toggle.
 */
NTSYSAPI
ULONGLONG
NTAPI
RtlGetFeatureToggleConfiguration(
    _In_ ULONG FeatureId,
    _In_ ULONGLONG ConfigurationType
    );

// RtlIsFeatureEnabledForEnterprise
/**
 * The RtlIsFeatureEnabledForEnterprise routine determines whether a feature is enabled for the enterprise
 * configuration.
 *
 * \param FeatureId The identifier of the feature to test.
 * \return Returns `TRUE` if the feature is enabled for the enterprise, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlIsFeatureEnabledForEnterprise(
    _In_ ULONG FeatureId
    );

// RtlQueryInternalFeatureConfiguration
/**
 * The RtlQueryInternalFeatureConfiguration routine queries the configuration of an internal (velocity/feature-staging)
 * feature.
 *
 * \param FeatureId The identifier of the feature to query.
 * \param QueryFlags Flags controlling the query.
 * \param ChangeStamp An optional pointer that receives the configuration change stamp.
 * \param FeatureConfiguration Receives the feature configuration.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryInternalFeatureConfiguration(
    _In_ ULONG FeatureId,
    _In_ ULONG QueryFlags,
    _Out_opt_ PULONGLONG ChangeStamp,
    _Out_ PVOID FeatureConfiguration
    );


EXTERN_C_END
