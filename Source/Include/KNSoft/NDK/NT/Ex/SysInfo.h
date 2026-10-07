#pragma once

#include "../MinDef.h"
#include "../Ke/Ke.h"
#include "../Mm/Misc.h"
#include "../Ldr.h"

EXTERN_C_START

/* phnt */

typedef struct _TEB *PTEB;

// rev
// private
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                                 // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation,                             // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation,                           // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation,                             // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation,                                  // q: not implemented
    SystemProcessInformation,                               // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation,                             // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation,                                // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation,                  // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation,                                 // qs: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation,                              // q: SYSTEM_CALL_TIME_INFORMATION // not implemented // 10
    SystemModuleInformation,                                // q: RTL_PROCESS_MODULES
    SystemLocksInformation,                                 // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation,                            // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation,                             // q: not implemented
    SystemNonPagedPoolInformation,                          // q: not implemented
    SystemHandleInformation,                                // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation,                                // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation,                              // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation,                           // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation,                                // q: not implemented // 20
    SystemFileCacheInformation,                             // qs: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation,                               // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation,                             // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation,                           // qs: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation,                            // q: SYSTEM_MEMORY_USAGE_INFORMATION // not implemented
    SystemLoadGdiDriverInformation,                         // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only)
    SystemUnloadGdiDriverInformation,                       // s: SYSTEM_GDI_DRIVER_UNLOAD_INFORMATION (kernel-mode only)
    SystemTimeAdjustmentInformation,                        // qs: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation,                         // q: SYSTEM_MEMORY_USAGE_INFORMATION // not implemented
    SystemMirrorMemoryInformation,                          // qs: (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation,                      // qs: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0,                                        // q: not implemented
    SystemExceptionInformation,                             // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation,                        // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation,                        // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation,                         // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation,                         // qs: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation,                    // s: SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeparation,                               // s: SYSTEM_PRIORITY_SEPARATION_INFORMATION (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation,                     // s: UNICODE_STRING (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation,                  // s: UNICODE_STRING (requires SeDebugPrivilege)
    SystemProcessorIdleInformation,                         // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation,                          // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation,                       // qs: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation,                             // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification,                             // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate,                                    // q: not implemented
    SystemSessionDetach,                                    // q: not implemented
    SystemSessionInformation,                               // q: not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation,                            // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation,                              // qs: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend,                              // qs: (kernel-mode only)
    SystemSessionProcessInformation,                        // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace,                       // qs: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same handler as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap,                                 // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation,                            // qs: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation,                       // q: SYSTEM_EXTENDED_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment,                   // q: SYSTEM_RECOMMENDED_SHARED_DATA_ALIGNMENT_INFORMATION // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage,                                   // qs: SYSTEM_COMPLUS_PACKAGE_INFORMATION
    SystemNumaAvailableMemory,                              // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation,                        // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation,                        // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation,                    // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation,                        // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation,                      // q: SYSTEM_LOST_DELAYED_WRITE_INFORMATION
    SystemBigPoolInformation,                               // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation,                        // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation,                     // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation,                              // qs: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode,                               // q: SYSTEM_OBJECT_SECURITY_MODE_INFORMATION // 70
    SystemWatchdogTimerHandler,                             // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation,                         // qs: out: SYSTEM_WATCHDOG_TIMER_INFORMATION (EX in: ULONG WATCHDOG_INFORMATION_CLASS) // NtQuerySystemInformationEx
    SystemLogicalProcessorInformation,                      // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemWow64SharedInformationObsolete,                   // q: not implemented
    SystemRegisterFirmwareTableInformationHandler,          // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation,                         // q: SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx,                              // q: RTL_PROCESS_MODULE_INFORMATION_EX // since VISTA
    SystemVerifierTriageInformation,                        // q: not implemented
    SystemSuperfetchInformation,                            // qs: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation,                            // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx,                           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation,                // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege) // NtQuerySystemInformationEx
    SystemProcessorIdleCycleTimeInformation,                // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemVerifierCancellationInformation,                  // q: SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx,                      // q: not implemented
    SystemRefTraceInformation,                              // qs: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation,                           // qs: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation,                             // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation,                             // s: HANDLE (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation,                       // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation,                            // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx,                            // qs: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation,                              // qs: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation,             // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation,                              // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation,                         // q: SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation,                        // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation,                       // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation,                            // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution,                 // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 100
    SystemNumaProximityNodeInformation,                     // qs: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation,                       // qs: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation,                         // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation,              // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION (requires SeLoadDriverPrivilege)
    SystemProcessorBrandString,                             // q: SYSTEM_PROCESSOR_BRAND_STRING // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation,                        // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation,              // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // NtQuerySystemInformationEx // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation,                    // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemStoreInformation,                                 // qs: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString,                             // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue,                                 // s: SYSTEM_AIT_SAMPLING_VALUE_INFORMATION (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation,                               // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation,                              // qs: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation,                           // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts,                                // q: SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation,                         // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation,                        // q: BOOT_ENTROPY_NT_RESULT // ExQueryBootEntropyInformation
    SystemVerifierCountersInformation,                      // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx,                           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx,                          // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation,                          // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber) // NtQuerySystemInformationEx
    SystemAcpiAuditInformation,                             // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation,                      // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation,               // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation,                        // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation,                          // qs: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation,                   // qs: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,                               // q: SYSTEM_BAD_PAGE_INFORMATION
    SystemProcessorProfileControlArea,                      // qs: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation,                 // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation,                // qs: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation,                               // qs: SYSTEM_CONSOLE_INFORMATION // (requires SeLoadDriverPrivilege)
    SystemPlatformBinaryInformation,                        // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation,                                // q: SYSTEM_POLICY_INFORMATION
    SystemHypervisorProcessorCountInformation,              // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation,                            // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation,                 // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation,                        // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation,                         // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation,                              // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx,                // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // since WINBLUE
    SystemCriticalProcessErrorLogInformation,               // q: SYSTEM_CRITICAL_PROCESS_EXCEPTION_INFORMATION
    SystemSecureBootPolicyInformation,                      // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx,                            // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation,                            // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,             // qs: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemPortableWorkspaceEfiLauncherInformation,          // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation,                           // q: SYSTEM_EXTENDED_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx,                      // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation,                          // q: SYSTEM_BOOT_METADATA_INFORMATION // (requires SeTcbPrivilege) // 150
    SystemSoftRebootInformation,                            // qs: SYSTEM_SOFT_REBOOT_INFORMATION (s requires SeTcbPrivilege) // query returns ExSoftRebootFlags; set calls ExpSetSoftRebootFlags
    SystemElamCertificateInformation,                       // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation,                     // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation,                     // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation,                // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation,                                  // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation,                         // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation,                // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation,                      // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation,                   // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 160
    SystemVmGenerationCountInformation,                     // s: PHYSICAL_ADDRESS (kernel-mode only) (vmgencounter.sys)
    SystemTrustedPlatformModuleInformation,                 // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags,                              // q: SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation,                   // qs: SYSTEM_CODEINTEGRITY_POLICY_INFORMATION
    SystemIsolatedUserModeInformation,                      // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,  // q: SYSTEM_HARDWARE_SECURITY_TEST_INTERFACE_RESULTS_INFORMATION
    SystemSingleModuleInformation,                          // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,                        // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
    SystemVsmProtectionInformation,                         // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation,                      // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation,                  // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,               // q: SYSTEM_CODE_INTEGRITY_POLICY_FULL_INFORMATION
    SystemAffinitizedInterruptProcessorInformation,         // q: KAFFINITY_EX // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation,                              // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation,                                // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation,                             // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,                             // s: SYSTEM_WIN32_WER_START_CALLOUT (optional; 0-length uses current process)
    SystemSecureKernelProfileInformation,                   // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation,         // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // NtQuerySystemInformationEx // since REDSTONE
    SystemInterruptSteeringInformation,                     // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
    SystemSupportedProcessorArchitectures,                  // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation,                           // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation,              // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation,                        // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition,                            // qs: SYSTEM_CONTROL_FLOW_TRANSITION // operation-tagged Warbird control-flow transition request
    SystemKernelDebuggingAllowed,                           // s: ULONG
    SystemActivityModerationExeState,                       // s: SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings,                   // q: SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,             // qs: SYSTEM_CODE_INTEGRITY_POLICIES_FULL_INFORMATION // NtQuerySystemInformationEx
    SystemCodeIntegrityUnlockInformation,                   // q: SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,                        // s: SYSTEM_INTEGRITY_QUOTA_INFORMATION (requires SeDebugPrivilege)
    SystemFlushInformation,                                 // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation,                     // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation,                  // qs: SYSTEM_SECURE_DUMP_ENCRYPTION_INFORMATION // NtQuerySystemInformationEx // opaque dump-key transform buffer (q: requires SeDebugPrivilege) (s: 0-length only, requires SeTcbPrivilege)
    SystemWriteConstraintInformation,                       // q: SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation,                        // q: SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation,                  // q: SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,               // q: SYSTEM_FIRMWARE_BOOT_PERFORMANCE_INFORMATION // HaliQuerySystemInformation -> HalpFwBootPerformanceTable, info class 34
    SystemCodeIntegrityVerificationInformation,             // q: SYSTEM_CODEINTEGRITY_VERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation,                     // q: SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation,                    // q: SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation,                        // q: SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation,                  // q: SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation,                // q: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation,               // q: SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
    SystemLeapSecondInformation,                            // qs: SYSTEM_LEAP_SECOND_INFORMATION // (s: requires SeSystemtimePrivilege)
    SystemFlags2Information,                                // q: SYSTEM_FLAGS_INFORMATION // (s: requires SeDebugPrivilege)
    SystemSecurityModelInformation,                         // q: SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,           // qs: NtQuerySystemInformationEx
    SystemFeatureConfigurationInformation,                  // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation,           // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
    SystemFeatureUsageSubscriptionInformation,              // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
    SystemSecureSpeculationControlInformation,              // q: SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation,                            // q: SYSTEM_SPACES_BOOT_INFORMATION // variable-length opaque blob copied from ExpSpacesBootInformation (kernel mode only) // since 20H2
    SystemFwRamdiskInformation,                             // q: SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,                      // q: SYSTEM_WHEA_IPMI_HARDWARE_INFORMATION
    SystemDifSetRuleClassInformation,                       // s: SYSTEM_DIF_VOLATILE_INFORMATION (requires SeDebugPrivilege)
    SystemDifClearRuleClassInformation,                     // s: NULL (requires SeDebugPrivilege)
    SystemDifApplyPluginVerificationOnDriver,               // q: SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege)
    SystemDifRemovePluginVerificationOnDriver,              // q: SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege) // 220
    SystemShadowStackInformation,                           // q: SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation,                          // q: in: SYSTEM_BUILD_VERSION_INFORMATION_INPUT, out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // CmQueryBuildVersionInformation
    SystemPoolLimitInformation,                             // q: SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege) // NtQuerySystemInformationEx
    SystemCodeIntegrityAddDynamicStore,                     // q: SYSTEM_CODE_INTEGRITY_DYNAMIC_STORE // CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
    SystemCodeIntegrityClearDynamicStores,                  // q: SYSTEM_CODE_INTEGRITY_DYNAMIC_STORE // CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
    SystemDifPoolTrackingInformation,                       // s: SYSTEM_DIF_POOL_TRACKING_INFORMATION (requires SeDebugPrivilege)
    SystemPoolZeroingInformation,                           // q: SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation,                           // qs: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
    SystemDpcWatchdogInformation2,                          // qs: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
    SystemSupportedProcessorArchitectures2,                 // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
    SystemSingleProcessorRelationshipInformation,           // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor) // NtQuerySystemInformationEx
    SystemXfgCheckFailureInformation,                       // q: SYSTEM_XFG_FAILURE_INFORMATION
    SystemIommuStateInformation,                            // q: SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation,                     // q: SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation,                   // q: SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation,                           // q: SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,                  // q: in: SYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION_INPUT, out: SYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION // NtQuerySystemInformationEx // kernel mode only on this build
    SystemOriginalImageFeatureInformation,                  // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaInformation,                            // q: SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaPerformanceInformation,                 // q: SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
    SystemCodeIntegritySignedPoliciesFullInformation,       // qs: SYSTEM_CODE_INTEGRITY_SIGNED_POLICIES // NtQuerySystemInformationEx
    SystemSecureCoreInformation,                            // qs: SYSTEM_SECURE_CORE_INFORMATION // SystemSecureSecretsInformation
    SystemTrustedAppsRuntimeInformation,                    // q: SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
    SystemBadPageInformationEx,                             // q: SYSTEM_BAD_PAGE_INFORMATION
    SystemResourceDeadlockTimeout,                          // q: ULONG
    SystemBreakOnContextUnwindFailureInformation,           // q: ULONG (requires SeDebugPrivilege)
    SystemOslRamdiskInformation,                            // q: SYSTEM_OSL_RAMDISK_INFORMATION
    SystemCodeIntegrityPolicyManagementInformation,         // q: SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT // since 25H2
    SystemMemoryNumaCacheInformation,                       // q: SYSTEM_MEMORY_NUMA_CACHE_INFORMATION
    SystemProcessorFeaturesBitMapInformation,               // q: ULONG64[2] // RTL_BITMAP_EX // RtlInitializeBitMapEx // 250
    SystemRefTraceInformationEx,                            // q: SYSTEM_REF_TRACE_INFORMATION_EX
    SystemBasicProcessInformation,                          // q: SYSTEM_BASICPROCESS_INFORMATION
    SystemHandleCountInformation,                           // q: SYSTEM_HANDLECOUNT_INFORMATION
    SystemRuntimeAttestationReport,                         // q: SYSTEM_RUNTIME_REPORT_INPUT
    SystemPoolTagInformation2,                              // q: SYSTEM_POOLTAG_INFORMATION2 // since 26H1
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

/**
 * The SYSTEM_BASIC_INFORMATION structure contains basic information about the current system.
 */
typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;                         // Reserved
    ULONG TimerResolution;                  // The resolution of the system clock, in 100-nanosecond units. // NtQueryTimerResolution
    ULONG PageSize;                         // The page size and the granularity of page protection and commitment.
    ULONG NumberOfPhysicalPages;            // The number of physical pages in the system. // KUSER_SHARED_DATA->NumberOfPhysicalPages
    ULONG LowestPhysicalPageNumber;         // The lowest memory page accessible to applications and dynamic-link libraries (DLLs).
    ULONG HighestPhysicalPageNumber;        // The highest memory page accessible to applications and dynamic-link libraries (DLLs).
    ULONG AllocationGranularity;            // The granularity for the starting address at which virtual memory can be allocated.
    ULONG_PTR MinimumUserModeAddress;       // A pointer to the lowest memory address accessible to applications and dynamic-link libraries (DLLs).
    ULONG_PTR MaximumUserModeAddress;       // A pointer to the highest memory address accessible to applications and dynamic-link libraries (DLLs).
    KAFFINITY ActiveProcessorsAffinityMask; // A mask representing the set of processors configured in the current processor group. // deprecated
    UCHAR NumberOfProcessors;               // The number of logical processors in the current processor group. // deprecated
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

// SYSTEM_PROCESSOR_INFORMATION // ProcessorFeatureBits (see also SYSTEM_PROCESSOR_FEATURES_INFORMATION)
#define KF32_V86_VIS      0x00000001 // Virtual 8086 mode.
#define KF32_RDTSC        0x00000002 // RDTSC (Read Time-Stamp Counter) instruction.
#define KF32_CR4          0x00000004 // CR4 (Control Register 4) register.
#define KF32_CMOV         0x00000008 // CMOV (Conditional Move) instruction.
#define KF32_GLOBAL_PAGE  0x00000010 // Global memory pages.
#define KF32_LARGE_PAGE   0x00000020 // Large memory pages.
#define KF32_MTRR         0x00000040 // MTRR (Memory Type Range Registers).
#define KF32_CMPXCHG8B    0x00000080 // CMPXCHG8B (CompareExchange) instruction.
#define KF32_MMX          0x00000100 // MMX (MultiMedia eXtensions).
#define KF32_WORKING_PTE  0x00000200 // PTE (Page Table Entries).
#define KF32_PAT          0x00000400 // PAT (Page Attribute Table).
#define KF32_FXSR         0x00000800 // FXSR (Floating Point Extended Save and Restore).
#define KF32_FAST_SYSCALL 0x00001000 // Fast system calls.
#define KF32_XMMI         0x00002000 // XMMI (Streaming SIMD Extensions - 32-bit).
#define KF32_3DNOW        0x00004000 // AMD 3DNow! technology.
#define KF32_AMDK6MTRR    0x00008000 // AMD K6 MTRR.
#define KF32_XMMI64       0x00010000 // XMMI (Streaming SIMD Extensions - 64-bit).
#define KF32_DTS          0x00020000 // DTS (Digital Thermal Sensor).
#define KF32_TM2          0x00040000 // TM2 (Thermal Monitor 2).
#define KF32_EST          0x00080000 // EST (Enhanced SpeedStep Technology).
#define KF32_IA64         0x00100000 // Intel Itanium architecture.
#define KF32_3DNOW2       0x00200000 // AMD 3DNow! technology, version 2.
#define KF32_VMX          0x00400000 // VMX (Virtual Machine Extensions).
#define KF32_SMX          0x00800000 // SMX (Safer Mode Extensions).
#define KF32_EST2         0x01000000 // EST (Enhanced SpeedStep Technology), version 2.
#define KF32_SSSE3        0x02000000 // SSSE3 (Supplemental Streaming SIMD Extensions 3).
#define KF32_CX16         0x04000000 // CMPXCHG16B instruction.
#define KF32_ETPRD        0x08000000 // ETPRD (Enhanced Time-Stamp Counter Priority Rotation Disable).
#define KF32_PDCM         0x10000000 // PDCM (Performance and Debug Capability MSR).
#define KF32_NOEXECUTE    0x20000000 // No-Execute (NX) bit.
#define KF32_GLOBAL_32BIT_EXECUTE 0x40000000
#define KF32_GLOBAL_32BIT_NOEXECUTE 0x80000000

/**
 * The SYSTEM_PROCESSOR_INFORMATION structure contains information about the current processor.
 *
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
 */
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT MaximumProcessors;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG AvailablePagedPoolPages;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
    ULONGLONG CcTotalDirtyPages; // since THRESHOLD
    ULONGLONG CcDirtyPageThreshold;
    LONGLONG ResidentAvailablePages;
    ULONGLONG SharedCommittedPages;
    ULONGLONG MdlPagesAllocated; // since 24H2
    ULONGLONG PfnDatabaseCommittedPages;
    ULONGLONG SystemPageTableCommittedPages;
    ULONGLONG ContiguousPagesAllocated;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

/**
 * The SYSTEM_TIMEOFDAY_INFORMATION structure contains information about the system uptime.
 */
typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
    LARGE_INTEGER BootTime;         // Number of 100-nanosecond intervals since the system was started.
    LARGE_INTEGER CurrentTime;      // The current system date and time.
    LARGE_INTEGER TimeZoneBias;     // Number of 100-nanosecond intervals between local time and Coordinated Universal Time (UTC).
    ULONG TimeZoneId;               // The current system time zone identifier.
    ULONG Reserved;                 // Reserved
    ULONGLONG BootTimeBias;         // Number of 100-nanosecond intervals between the boot time and Coordinated Universal Time (UTC).
    ULONGLONG SleepTimeBias;        // Number of 100-nanosecond intervals between the sleep time and Coordinated Universal Time (UTC).
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

/**
 * The SYSTEM_THREAD_INFORMATION structure contains information about a thread running on a system.
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/e82d73e4-cedb-4077-9099-d58f3459722f
 */
typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;       // Number of 100-nanosecond intervals spent executing kernel code.
    LARGE_INTEGER UserTime;         // Number of 100-nanosecond intervals spent executing user code.
    LARGE_INTEGER CreateTime;       // The date and time when the thread was created.
    ULONG WaitTime;                 // The current time spent in ready queue or waiting (depending on the thread state).
    PVOID StartAddress;             // The initial start address of the thread.
    CLIENT_ID ClientId;             // The identifier of the thread and the process owning the thread.
    KPRIORITY Priority;             // The dynamic priority of the thread.
    KPRIORITY BasePriority;         // The starting priority of the thread.
    ULONG ContextSwitches;          // The total number of context switches performed.
    KTHREAD_STATE ThreadState;      // The current state of the thread.
    KWAIT_REASON WaitReason;        // The current reason the thread is waiting.
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

/**
 * The SYSTEM_PROCESS_INFORMATION structure contains information about a process running on a system.
 */
_Struct_size_bytes_(NextEntryOffset)
typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;                  // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
    ULONG NumberOfThreads;                  // The NumberOfThreads member contains the number of threads in the process.
    ULONGLONG WorkingSetPrivateSize;        // The total private memory that a process currently has allocated and is physically resident in memory. // since VISTA
    ULONG HardFaultCount;                   // The total number of hard faults for data from disk rather than from in-memory pages. // since WIN7
    ULONG NumberOfThreadsHighWatermark;     // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
    ULONGLONG CycleTime;                    // The sum of the cycle time of all threads in the process.
    LARGE_INTEGER CreateTime;               // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
    LARGE_INTEGER UserTime;                 // Number of 100-nanosecond intervals the process has executed in user mode.
    LARGE_INTEGER KernelTime;               // Number of 100-nanosecond intervals the process has executed in kernel mode.
    UNICODE_STRING ImageName;               // The file name of the executable image.
    KPRIORITY BasePriority;                 // The starting priority of the process.
    HANDLE UniqueProcessId;                 // The identifier of the process.
    HANDLE InheritedFromUniqueProcessId;    // The identifier of the process that created this process. Not updated and incorrectly refers to processes with recycled identifiers.
    ULONG HandleCount;                      // The current number of open handles used by the process.
    ULONG SessionId;                        // The identifier of the Remote Desktop Services session under which the specified process is running.
    ULONG_PTR UniqueProcessKey;             // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                 // The peak size, in bytes, of the virtual memory used by the process.
    SIZE_T VirtualSize;                     // The current size, in bytes, of virtual memory used by the process.
    ULONG PageFaultCount;                   // The total number of page faults for data that is not currently in memory. The value wraps around to zero on average 24 hours.
    SIZE_T PeakWorkingSetSize;              // The peak size, in kilobytes, of the working set of the process.
    SIZE_T WorkingSetSize;                  // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
    SIZE_T QuotaPeakPagedPoolUsage;         // The peak quota charged to the process for pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;             // The quota charged to the process for paged pool usage, in bytes.
    SIZE_T QuotaPeakNonPagedPoolUsage;      // The peak quota charged to the process for nonpaged pool usage, in bytes.
    SIZE_T QuotaNonPagedPoolUsage;          // The current quota charged to the process for nonpaged pool usage.
    SIZE_T PagefileUsage;                   // The total number of bytes of page file storage in use by the process.
    SIZE_T PeakPagefileUsage;               // The maximum number of bytes of page-file storage used by the process.
    SIZE_T PrivatePageCount;                // The number of memory pages allocated for the use by the process.
    LARGE_INTEGER ReadOperationCount;       // The total number of read operations performed.
    LARGE_INTEGER WriteOperationCount;      // The total number of write operations performed.
    LARGE_INTEGER OtherOperationCount;      // The total number of I/O operations performed other than read and write operations.
    LARGE_INTEGER ReadTransferCount;        // The total number of bytes read during a read operation.
    LARGE_INTEGER WriteTransferCount;       // The total number of bytes written during a write operation.
    LARGE_INTEGER OtherTransferCount;       // The total number of bytes transferred during operations other than read and write operations.
    SYSTEM_THREAD_INFORMATION Threads[];    // This type is not defined in the structure but was added for convenience.
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// private
/**
 * The SYSTEM_EXTENDED_THREAD_INFORMATION structure contains extended information about a thread in the system.
 */
typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
    union
    {
        SYSTEM_THREAD_INFORMATION ThreadInfo;
        struct
        {
            ULONGLONG KernelTime;           // Number of 100-nanosecond intervals spent executing kernel code.
            ULONGLONG UserTime;             // Number of 100-nanosecond intervals spent executing user code.
            ULONGLONG CreateTime;           // The date and time when the thread was created.
            ULONG WaitTime;                 // The current time spent in ready queue or waiting (depending on the thread state).
            PVOID StartAddress;             // The initial start address of the thread.
            CLIENT_ID ClientId;             // The identifier of the thread and the process owning the thread.
            KPRIORITY Priority;             // The dynamic priority of the thread.
            KPRIORITY BasePriority;         // The starting priority of the thread.
            ULONG ContextSwitches;          // The total number of context switches performed.
            KTHREAD_STATE ThreadState;      // The current state of the thread.
            KWAIT_REASON WaitReason;        // The current reason the thread is waiting.
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    PVOID StackBase;                        // The lower boundary of the current thread stack.
    PVOID StackLimit;                       // The upper boundary of the current thread stack.
    PVOID Win32StartAddress;                // The thread's Win32 start address.
    PVOID TebBaseAddress;                   // The base address of the memory region containing the TEB structure. // since VISTA
    ULONG_PTR Reserved2;
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

/**
 * The SYSTEM_EXTENDED_PROCESS_INFORMATION structure contains extended information about a process running on a system.
 * https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-system_extended_process_information
 */
_Struct_size_bytes_(NextEntryOffset)
typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;                  // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
    ULONG NumberOfThreads;                  // The NumberOfThreads member contains the number of threads in the process.
    ULONGLONG WorkingSetPrivateSize;        // The total private memory that a process currently has allocated and is physically resident in memory. // since VISTA
    ULONG HardFaultCount;                   // The total number of hard faults for data from disk rather than from in-memory pages. // since WIN7
    ULONG NumberOfThreadsHighWatermark;     // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
    ULONGLONG CycleTime;                    // The sum of the cycle time of all threads in the process.
    ULONGLONG CreateTime;                   // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
    ULONGLONG UserTime;                     // Number of 100-nanosecond intervals the process has executed in user mode.
    ULONGLONG KernelTime;                   // Number of 100-nanosecond intervals the process has executed in kernel mode.
    UNICODE_STRING ImageName;               // The file name of the executable image.
    KPRIORITY BasePriority;                 // The starting priority of the process.
    HANDLE UniqueProcessId;                 // The identifier of the process.
    HANDLE InheritedFromUniqueProcessId;    // The identifier of the process that created this process. Not updated and incorrectly refers to processes with recycled identifiers.
    ULONG HandleCount;                      // The current number of open handles used by the process.
    ULONG SessionId;                        // The identifier of the Remote Desktop Services session under which the specified process is running.
    HANDLE UniqueProcessKey;                // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                 // The peak size, in bytes, of the virtual memory used by the process.
    SIZE_T VirtualSize;                     // The current size, in bytes, of virtual memory used by the process.
    ULONG PageFaultCount;                   // The total number of page faults for data that is not currently in memory. The value wraps around to zero on average 24 hours.
    SIZE_T PeakWorkingSetSize;              // The peak size, in kilobytes, of the working set of the process.
    SIZE_T WorkingSetSize;                  // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
    SIZE_T QuotaPeakPagedPoolUsage;         // The peak quota charged to the process for pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;             // The quota charged to the process for paged pool usage, in bytes.
    SIZE_T QuotaPeakNonPagedPoolUsage;      // The peak quota charged to the process for nonpaged pool usage, in bytes.
    SIZE_T QuotaNonPagedPoolUsage;          // The current quota charged to the process for nonpaged pool usage.
    SIZE_T PagefileUsage;                   // The total number of bytes of page file storage in use by the process.
    SIZE_T PeakPagefileUsage;               // The maximum number of bytes of page-file storage used by the process.
    SIZE_T PrivatePageCount;                // The number of memory pages allocated for the use by the process.
    ULONGLONG ReadOperationCount;           // The total number of read operations performed.
    ULONGLONG WriteOperationCount;          // The total number of write operations performed.
    ULONGLONG OtherOperationCount;          // The total number of I/O operations performed other than read and write operations.
    ULONGLONG ReadTransferCount;            // The total number of bytes read during a read operation.
    ULONGLONG WriteTransferCount;           // The total number of bytes written during a write operation.
    ULONGLONG OtherTransferCount;           // The total number of bytes transferred during operations other than read and write operations.
    SYSTEM_EXTENDED_THREAD_INFORMATION Threads[];
    // SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_EXTENDED_PROCESS_INFORMATION, *PSYSTEM_EXTENDED_PROCESS_INFORMATION;

/**
 * The SYSTEM_CALL_COUNT_INFORMATION structure contains per-processor system service call counts.
 */
typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
    ULONG Length;
    ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

/**
 * The SYSTEM_DEVICE_INFORMATION structure contains information about the devices in the system.
 */
typedef struct _SYSTEM_DEVICE_INFORMATION
{
    ULONG NumberOfDisks;
    ULONG NumberOfFloppies;
    ULONG NumberOfCdRoms;
    ULONG NumberOfTapes;
    ULONG NumberOfSerialPorts;
    ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

/**
 * The SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION structure contains information about the performance of each processor installed in the system.
 * https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_processor_performance_information
 */
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleTime;         // The IdleTime member contains the amount of time that the system has been idle, in 100-nanosecond intervals.
    LARGE_INTEGER KernelTime;       // The KernelTime member contains the amount of time that the system has spent executing in Kernel mode (including all threads in all processes, on all processors), in 100-nanosecond intervals.
    LARGE_INTEGER UserTime;         // The UserTime member contains the amount of time that the system has spent executing in User mode (including all threads in all processes, on all processors), in 100-nanosecond intervals.
    LARGE_INTEGER DpcTime;          // The DpcTime member contains the amount of time that the system has spent processing deferred procedure calls (DPCs), in 100-nanosecond intervals.
    LARGE_INTEGER InterruptTime;    // The InterruptTime member contains the amount of time that the system has spent processing hardware interrupts, in 100-nanosecond intervals.
    ULONG InterruptCount;           // The InterruptCount member contains the number of interrupts that have occurred, as counted by the system.
    ULONG Spare0;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

/**
 * The SYSTEM_FLAGS_INFORMATION structure contains the global NT flags that control kernel debugging and
 * instrumentation.
 */
typedef struct _SYSTEM_FLAGS_INFORMATION
{
    union
    {
        ULONG Flags; // NtGlobalFlag
        struct
        {
            ULONG StopOnException : 1;          // FLG_STOP_ON_EXCEPTION
            ULONG ShowLoaderSnaps : 1;          // FLG_SHOW_LDR_SNAPS
            ULONG DebugInitialCommand : 1;      // FLG_DEBUG_INITIAL_COMMAND
            ULONG StopOnHungGUI : 1;            // FLG_STOP_ON_HUNG_GUI
            ULONG HeapEnableTailCheck : 1;      // FLG_HEAP_ENABLE_TAIL_CHECK
            ULONG HeapEnableFreeCheck : 1;      // FLG_HEAP_ENABLE_FREE_CHECK
            ULONG HeapValidateParameters : 1;   // FLG_HEAP_VALIDATE_PARAMETERS
            ULONG HeapValidateAll : 1;          // FLG_HEAP_VALIDATE_ALL
            ULONG ApplicationVerifier : 1;      // FLG_APPLICATION_VERIFIER
            ULONG MonitorSilentProcessExit : 1; // FLG_MONITOR_SILENT_PROCESS_EXIT
            ULONG PoolEnableTagging : 1;        // FLG_POOL_ENABLE_TAGGING
            ULONG HeapEnableTagging : 1;        // FLG_HEAP_ENABLE_TAGGING
            ULONG UserStackTraceDb : 1;         // FLG_USER_STACK_TRACE_DB
            ULONG KernelStackTraceDb : 1;       // FLG_KERNEL_STACK_TRACE_DB
            ULONG MaintainObjectTypeList : 1;   // FLG_MAINTAIN_OBJECT_TYPELIST
            ULONG HeapEnableTagByDll : 1;       // FLG_HEAP_ENABLE_TAG_BY_DLL
            ULONG DisableStackExtension : 1;    // FLG_DISABLE_STACK_EXTENSION
            ULONG EnableCsrDebug : 1;           // FLG_ENABLE_CSRDEBUG
            ULONG EnableKDebugSymbolLoad : 1;   // FLG_ENABLE_KDEBUG_SYMBOL_LOAD
            ULONG DisablePageKernelStacks : 1;  // FLG_DISABLE_PAGE_KERNEL_STACKS
            ULONG EnableSystemCritBreaks : 1;   // FLG_ENABLE_SYSTEM_CRIT_BREAKS
            ULONG HeapDisableCoalescing : 1;    // FLG_HEAP_DISABLE_COALESCING
            ULONG EnableCloseExceptions : 1;    // FLG_ENABLE_CLOSE_EXCEPTIONS
            ULONG EnableExceptionLogging : 1;   // FLG_ENABLE_EXCEPTION_LOGGING
            ULONG EnableHandleTypeTagging : 1;  // FLG_ENABLE_HANDLE_TYPE_TAGGING
            ULONG HeapPageAllocs : 1;           // FLG_HEAP_PAGE_ALLOCS
            ULONG DebugInitialCommandEx : 1;    // FLG_DEBUG_INITIAL_COMMAND_EX
            ULONG DisableDbgPrint : 1;          // FLG_DISABLE_DBGPRINT
            ULONG CritSecEventCreation : 1;     // FLG_CRITSEC_EVENT_CREATION
            ULONG LdrTopDown : 1;               // FLG_LDR_TOP_DOWN
            ULONG EnableHandleExceptions : 1;   // FLG_ENABLE_HANDLE_EXCEPTIONS
            ULONG DisableProtDlls : 1;          // FLG_DISABLE_PROTDLLS
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

// private
/**
 * The SYSTEM_CALL_TIME_INFORMATION structure contains timing information for system service calls.
 */
typedef struct _SYSTEM_CALL_TIME_INFORMATION
{
    ULONG Length;
    ULONG TotalCalls;
    LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION;

// Note: This information class is deprecated since values are limited to 65535. Use SystemExtendedHandleInformation instead.
/**
 * The SYSTEM_HANDLE_TABLE_ENTRY_INFO structure describes a single open handle in the system-wide handle table.
 */
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

/**
 * The SYSTEM_HANDLE_INFORMATION structure contains information about the open handles in the system.
 */
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    _Field_size_(NumberOfHandles) SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

_Struct_size_bytes_(NextEntryOffset)
/**
 * The SYSTEM_OBJECTTYPE_INFORMATION structure contains information about an object type in the system.
 */
typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfObjects;
    ULONG NumberOfHandles;
    ULONG TypeIndex;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ACCESS_MASK ValidAccessMask;
    ULONG PoolType;
    BOOLEAN SecurityRequired;
    BOOLEAN WaitableObject;
    UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

_Struct_size_bytes_(NextEntryOffset)
/**
 * The SYSTEM_OBJECT_INFORMATION structure contains information about an object in the system.
 */
typedef struct _SYSTEM_OBJECT_INFORMATION
{
    ULONG NextEntryOffset;
    PVOID Object;
    HANDLE CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Flags;
    LONG PointerCount;
    LONG HandleCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    HANDLE ExclusiveProcessId;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    UNICODE_STRING NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

_Struct_size_bytes_(NextEntryOffset)
/**
 * The SYSTEM_PAGEFILE_INFORMATION structure contains information about a paging file in the system.
 */
typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG TotalInUse;
    ULONG PeakUsage;
    UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

/**
 * The SYSTEM_VDM_INSTEMUL_INFO structure contains statistics about VDM instruction emulation.
 */
typedef struct _SYSTEM_VDM_INSTEMUL_INFO
{
    ULONG SegmentNotPresent;
    ULONG VdmOpcode0F;
    ULONG OpcodeESPrefix;
    ULONG OpcodeCSPrefix;
    ULONG OpcodeSSPrefix;
    ULONG OpcodeDSPrefix;
    ULONG OpcodeFSPrefix;
    ULONG OpcodeGSPrefix;
    ULONG OpcodeOPER32Prefix;
    ULONG OpcodeADDR32Prefix;
    ULONG OpcodeINSB;
    ULONG OpcodeINSW;
    ULONG OpcodeOUTSB;
    ULONG OpcodeOUTSW;
    ULONG OpcodePUSHF;
    ULONG OpcodePOPF;
    ULONG OpcodeINTnn;
    ULONG OpcodeINTO;
    ULONG OpcodeIRET;
    ULONG OpcodeINBimm;
    ULONG OpcodeINWimm;
    ULONG OpcodeOUTBimm;
    ULONG OpcodeOUTWimm;
    ULONG OpcodeINB;
    ULONG OpcodeINW;
    ULONG OpcodeOUTB;
    ULONG OpcodeOUTW;
    ULONG OpcodeLOCKPrefix;
    ULONG OpcodeREPNEPrefix;
    ULONG OpcodeREPPrefix;
    ULONG OpcodeHLT;
    ULONG OpcodeCLI;
    ULONG OpcodeSTI;
    ULONG BopCount;
} SYSTEM_VDM_INSTEMUL_INFO, *PSYSTEM_VDM_INSTEMUL_INFO;

#define MM_WORKING_SET_MAX_HARD_ENABLE 0x1
#define MM_WORKING_SET_MAX_HARD_DISABLE 0x2
#define MM_WORKING_SET_MIN_HARD_ENABLE 0x4
#define MM_WORKING_SET_MIN_HARD_DISABLE 0x8

// SYSTEM_FILECACHE_INFORMATION.Flags / SetSystemFileCacheSize flags
// #define FILE_CACHE_MAX_HARD_ENABLE MM_WORKING_SET_MAX_HARD_ENABLE
// #define FILE_CACHE_MAX_HARD_DISABLE MM_WORKING_SET_MAX_HARD_DISABLE
// #define FILE_CACHE_MIN_HARD_ENABLE MM_WORKING_SET_MIN_HARD_ENABLE
// #define FILE_CACHE_MIN_HARD_DISABLE MM_WORKING_SET_MIN_HARD_DISABLE

/**
 * The SYSTEM_FILECACHE_INFORMATION structure contains information about the system file cache.
 */
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags; // FILE_CACHE_* / MM_WORKING_SET_* flags
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

// Can be used instead of SYSTEM_FILECACHE_INFORMATION
/**
 * The SYSTEM_BASIC_WORKING_SET_INFORMATION structure contains basic working set information for the system.
 */
typedef struct _SYSTEM_BASIC_WORKING_SET_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
} SYSTEM_BASIC_WORKING_SET_INFORMATION, *PSYSTEM_BASIC_WORKING_SET_INFORMATION;

/**
 * The SYSTEM_POOLTAG structure describes pool allocation statistics for a single pool tag.
 */
typedef struct _SYSTEM_POOLTAG
{
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    } DUMMYUNIONNAME;
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

/**
 * The SYSTEM_POOLTAG_INFORMATION structure contains pool allocation statistics for all pool tags in the system.
 */
typedef struct _SYSTEM_POOLTAG_INFORMATION
{
    ULONG Count;
    _Field_size_(Count) SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

/**
 * The SYSTEM_DPC_BEHAVIOR_INFORMATION structure contains the deferred procedure call (DPC) timeout and behavior
 * settings.
 */
typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
    ULONG Spare;
    ULONG DpcQueueDepth;
    ULONG MinimumDpcRate;
    ULONG AdjustDpcThreshold;
    ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

/**
 * The SYSTEM_QUERY_TIME_ADJUST_INFORMATION structure contains the current time adjustment settings.
 */
typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    ULONG TimeIncrement;
    BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

/**
 * The SYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE structure contains the current high-precision time adjustment
 * settings.
 */
typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE
{
    ULONGLONG TimeAdjustment;
    ULONGLONG TimeIncrement;
    BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION_PRECISE;

/**
 * The SYSTEM_SET_TIME_ADJUST_INFORMATION structure specifies the time adjustment settings to apply.
 */
typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

/**
 * The SYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE structure specifies the high-precision time adjustment settings to
 * apply.
 */
typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE
{
    ULONGLONG TimeAdjustment;
    BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE, *PSYSTEM_SET_TIME_ADJUST_INFORMATION_PRECISE;

typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
    ULONG AlignmentFixupCount;
    ULONG ExceptionDispatchCount;
    ULONG FloatingEmulationCount;
    ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

/**
 * The SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS enumeration defines the system crash dump configuration classes.
 */
typedef enum _SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS
{
    SystemCrashDumpDisable,
    SystemCrashDumpReconfigure,
    SystemCrashDumpInitializationComplete
} SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS, *PSYSTEM_CRASH_DUMP_CONFIGURATION_CLASS;

/**
 * The SYSTEM_CRASH_DUMP_STATE_INFORMATION structure contains system crash dump state information.
 */
typedef struct _SYSTEM_CRASH_DUMP_STATE_INFORMATION
{
    SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS CrashDumpConfigurationClass;
} SYSTEM_CRASH_DUMP_STATE_INFORMATION, *PSYSTEM_CRASH_DUMP_STATE_INFORMATION;

/**
 * The SYSTEM_KERNEL_DEBUGGER_INFORMATION structure indicates whether a kernel debugger is present and enabled.
 */
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

/**
 * The SYSTEM_CONTEXT_SWITCH_INFORMATION structure contains system-wide context switch statistics.
 */
typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
    ULONG ContextSwitches;
    ULONG FindAny;
    ULONG FindLast;
    ULONG FindIdeal;
    ULONG IdleAny;
    ULONG IdleCurrent;
    ULONG IdleLast;
    ULONG IdleIdeal;
    ULONG PreemptAny;
    ULONG PreemptCurrent;
    ULONG PreemptLast;
    ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
    ULONG RegistryQuotaAllowed;
    ULONG RegistryQuotaUsed;
    SIZE_T PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

/**
 * The SYSTEM_PROCESSOR_IDLE_INFORMATION structure contains per-processor idle time statistics.
 */
typedef struct _SYSTEM_PROCESSOR_IDLE_INFORMATION
{
    ULONGLONG IdleTime;
    ULONGLONG C1Time;
    ULONGLONG C2Time;
    ULONGLONG C3Time;
    ULONG C1Transitions;
    ULONG C2Transitions;
    ULONG C3Transitions;
    ULONG Padding;
} SYSTEM_PROCESSOR_IDLE_INFORMATION, *PSYSTEM_PROCESSOR_IDLE_INFORMATION;

/**
 * The SYSTEM_LEGACY_DRIVER_INFORMATION structure contains information about legacy drivers in the system.
 */
typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
{
    ULONG VetoType;
    UNICODE_STRING VetoList;
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
    USHORT CurrentDepth;
    USHORT MaximumDepth;
    ULONG TotalAllocates;
    ULONG AllocateMisses;
    ULONG TotalFrees;
    ULONG FreeMisses;
    ULONG Type;
    ULONG Tag;
    ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

// private
/**
 * The SYSTEM_RANGE_START_INFORMATION structure contains the start address of the system virtual address range.
 */
typedef struct _SYSTEM_RANGE_START_INFORMATION
{
    ULONG_PTR SystemRangeStart;
} SYSTEM_RANGE_START_INFORMATION, *PSYSTEM_RANGE_START_INFORMATION;

_Struct_size_bytes_(NextEntryOffset)
/**
 * The SYSTEM_VERIFIER_INFORMATION_LEGACY structure describes the system verifier information legacy.
 */
typedef struct _SYSTEM_VERIFIER_INFORMATION_LEGACY // pre-19H1
{
    ULONG NextEntryOffset;
    ULONG Level;
    UNICODE_STRING DriverName;
    ULONG RaiseIrqls;
    ULONG AcquireSpinLocks;
    ULONG SynchronizeExecutions;
    ULONG AllocationsAttempted;
    ULONG AllocationsSucceeded;
    ULONG AllocationsSucceededSpecialPool;
    ULONG AllocationsWithNoTag;
    ULONG TrimRequests;
    ULONG Trims;
    ULONG AllocationsFailed;
    ULONG AllocationsFailedDeliberately;
    ULONG Loads;
    ULONG Unloads;
    ULONG UnTrackedPool;
    ULONG CurrentPagedPoolAllocations;
    ULONG CurrentNonPagedPoolAllocations;
    ULONG PeakPagedPoolAllocations;
    ULONG PeakNonPagedPoolAllocations;
    SIZE_T PagedPoolUsageInBytes;
    SIZE_T NonPagedPoolUsageInBytes;
    SIZE_T PeakPagedPoolUsageInBytes;
    SIZE_T PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION_LEGACY, *PSYSTEM_VERIFIER_INFORMATION_LEGACY;

_Struct_size_bytes_(NextEntryOffset)
/**
 * The SYSTEM_VERIFIER_INFORMATION structure contains system verifier information.
 */
typedef struct _SYSTEM_VERIFIER_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG Level;
    ULONG RuleClasses[2];
    ULONG TriageContext;
    ULONG AreAllDriversBeingVerified;
    UNICODE_STRING DriverName;
    ULONG RaiseIrqls;
    ULONG AcquireSpinLocks;
    ULONG SynchronizeExecutions;
    ULONG AllocationsAttempted;
    ULONG AllocationsSucceeded;
    ULONG AllocationsSucceededSpecialPool;
    ULONG AllocationsWithNoTag;
    ULONG TrimRequests;
    ULONG Trims;
    ULONG AllocationsFailed;
    ULONG AllocationsFailedDeliberately;
    ULONG Loads;
    ULONG Unloads;
    ULONG UnTrackedPool;
    ULONG CurrentPagedPoolAllocations;
    ULONG CurrentNonPagedPoolAllocations;
    ULONG PeakPagedPoolAllocations;
    ULONG PeakNonPagedPoolAllocations;
    SIZE_T PagedPoolUsageInBytes;
    SIZE_T NonPagedPoolUsageInBytes;
    SIZE_T PeakPagedPoolUsageInBytes;
    SIZE_T PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION;

// private
/**
 * The SYSTEM_SESSION_PROCESS_INFORMATION structure contains system session process information.
 */
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    ULONG SessionId;
    ULONG BufferSize;
    PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

#if !defined(_KERNEL_MODE)

// private
// Validates that ServiceTableName is exactly "\\SystemRoot\\System32\\win32k.sys"
// and forwards it to ZwSetSystemInformation(SystemLoadGdiDriverInSystemSpace, ...).
/**
 * The SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION structure contains system extend service table information.
 */
typedef struct _SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION
{
    UNICODE_STRING ServiceTableName;
} SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION, *PSYSTEM_EXTEND_SERVICE_TABLE_INFORMATION;

// private
// Consumed by PsChangeQuantumTable(ApplyToProcesses = TRUE, PrioritySeparation).
#define PSPRIORITYSEPARATION_MASK 0x03
#define PSQUANTUMTYPE_MASK 0x0C
#define PSFOREGROUNDQUANTUM_MASK 0x30

#define PSQUANTUMTYPE_DEFAULT 0x00 // Product-type default: variable on workstation, fixed on server.
#define PSQUANTUMTYPE_VARIABLE 0x04 // Sets KiVariableQuantumEnabled = TRUE and uses PspVariableQuantums or PspVariableQuantums_With_ShortQuantum.
#define PSQUANTUMTYPE_FIXED 0x08 // Sets KiVariableQuantumEnabled = FALSE and uses PspFixedQuantums.

#define PSFOREGROUNDQUANTUM_DEFAULT 0x00
#define PSFOREGROUNDQUANTUM_ALTERNATE 0x10
#define PSFOREGROUNDQUANTUM_BASE 0x20

/**
 * The SYSTEM_PRIORITY_SEPARATION_INFORMATION structure contains system priority separation information.
 */
typedef struct _SYSTEM_PRIORITY_SEPARATION_INFORMATION
{
    union
    {
        ULONG PrioritySeparation;
        struct
        {
            ULONG PrioritySeparationValue : 2;
            ULONG QuantumType : 2;
            ULONG ForegroundQuantum : 2;
            ULONG Reserved : 26;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} SYSTEM_PRIORITY_SEPARATION_INFORMATION, *PSYSTEM_PRIORITY_SEPARATION_INFORMATION;

// private
/**
 * The recommended alignment equals the system's largest cache-line size, in bytes.
 *
 * So the returned value is simply:
 * - KeLargestCacheLine
 */
typedef struct _SYSTEM_RECOMMENDED_SHARED_DATA_ALIGNMENT_INFORMATION
{
    ULONG RecommendedSharedDataAlignment;
} SYSTEM_RECOMMENDED_SHARED_DATA_ALIGNMENT_INFORMATION, *PSYSTEM_RECOMMENDED_SHARED_DATA_ALIGNMENT_INFORMATION;

// private
/**
 * Used by SystemComPlusPackage.
 *
 * NtSetSystemInformation(SystemComPlusPackage, ...) expects a 4-byte value,
 * passes it to ExpUpdateComPlusPackage, and mirrors the result into
 * KUSER_SHARED_DATA.ComPlusPackage.
 */
typedef struct _SYSTEM_COMPLUS_PACKAGE_INFORMATION
{
    ULONG ComPlusPackage;
} SYSTEM_COMPLUS_PACKAGE_INFORMATION, *PSYSTEM_COMPLUS_PACKAGE_INFORMATION;

// private
/**
 * The SYSTEM_LOST_DELAYED_WRITE_INFORMATION structure contains system lost delayed write information.
 */
typedef struct _SYSTEM_LOST_DELAYED_WRITE_INFORMATION
{
    ULONG LostDelayedWrites;
} SYSTEM_LOST_DELAYED_WRITE_INFORMATION, *PSYSTEM_LOST_DELAYED_WRITE_INFORMATION;

// private
/**
 * Used by SystemObjectSecurityMode.
 *
 * SeSecurityModelQueryInformation returns a 4-byte mode value.
 * The value is initialized to 0 and set to 2 when
 * SepIsDeviceOwnerProtectionDowngradeAllowed() returns TRUE.
 */
typedef struct _SYSTEM_OBJECT_SECURITY_MODE_INFORMATION
{
    ULONG ObjectSecurityMode;
} SYSTEM_OBJECT_SECURITY_MODE_INFORMATION, *PSYSTEM_OBJECT_SECURITY_MODE_INFORMATION;

// private
/**
 * Used by SystemAitSamplingValue.
 *
 * AIT refers to Application Impact Telemetry.
 *
 * NtSetSystemInformation(SystemAitSamplingValue, ...) expects a 4-byte value
 * and mirrors it into KUSER_SHARED_DATA.AitSamplingValue.
 */
typedef struct _SYSTEM_AIT_SAMPLING_VALUE_INFORMATION
{
    ULONG AitSamplingValue;
} SYSTEM_AIT_SAMPLING_VALUE_INFORMATION, *PSYSTEM_AIT_SAMPLING_VALUE_INFORMATION;

// private
/**
 * The SYSTEM_GDI_DRIVER_INFORMATION_V0 structure contains system GDI driver information.
 */
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION_V0
{
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION_V0, *PSYSTEM_GDI_DRIVER_INFORMATION_V0;

// private
/**
 * The SYSTEM_GDI_DRIVER_INFORMATION_V1 structure contains system GDI driver information.
 */
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION_V1
{
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
    ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION_V1, *PSYSTEM_GDI_DRIVER_INFORMATION_V1;

#define SYSTEM_GDI_DRIVER_INFORMATION SYSTEM_GDI_DRIVER_INFORMATION_V1
#define PSYSTEM_GDI_DRIVER_INFORMATION PSYSTEM_GDI_DRIVER_INFORMATION_V1

// private
/**
 * The SYSTEM_GDI_DRIVER_UNLOAD_INFORMATION structure contains system GDI driver unload information.
 */
typedef struct _SYSTEM_GDI_DRIVER_UNLOAD_INFORMATION
{
    PVOID SectionPointer;
} SYSTEM_GDI_DRIVER_UNLOAD_INFORMATION, *PSYSTEM_GDI_DRIVER_UNLOAD_INFORMATION;
#endif

// geoffchappell
#ifdef _WIN64
#define MAXIMUM_NODE_COUNT 0x40
#else
#define MAXIMUM_NODE_COUNT 0x10
#endif

// private
/**
 * The SYSTEM_NUMA_INFORMATION structure contains system NUMA information.
 */
typedef struct _SYSTEM_NUMA_INFORMATION
{
    ULONG HighestNodeNumber;
    ULONG Reserved;
    union
    {
        GROUP_AFFINITY ActiveProcessorsGroupAffinity[MAXIMUM_NODE_COUNT];
        ULONGLONG AvailableMemory[MAXIMUM_NODE_COUNT];
        ULONGLONG Pad[MAXIMUM_NODE_COUNT * 2];
    } DUMMYUNIONNAME;
} SYSTEM_NUMA_INFORMATION, *PSYSTEM_NUMA_INFORMATION;

/**
 * The SYSTEM_PROCESSOR_POWER_INFORMATION structure contains system processor power information.
 */
typedef struct _SYSTEM_PROCESSOR_POWER_INFORMATION
{
    UCHAR CurrentFrequency;
    UCHAR ThermalLimitFrequency;
    UCHAR ConstantThrottleFrequency;
    UCHAR DegradedThrottleFrequency;
    UCHAR LastBusyFrequency;
    UCHAR LastC3Frequency;
    UCHAR LastAdjustedBusyFrequency;
    UCHAR ProcessorMinThrottle;
    UCHAR ProcessorMaxThrottle;
    ULONG NumberOfFrequencies;
    ULONG PromotionCount;
    ULONG DemotionCount;
    ULONG ErrorCount;
    ULONG RetryCount;
    ULONGLONG CurrentFrequencyTime;
    ULONGLONG CurrentProcessorTime;
    ULONGLONG CurrentProcessorIdleTime;
    ULONGLONG LastProcessorTime;
    ULONGLONG LastProcessorIdleTime;
    ULONGLONG Energy;
} SYSTEM_PROCESSOR_POWER_INFORMATION, *PSYSTEM_PROCESSOR_POWER_INFORMATION;

/**
 * The SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX structure describes a single open handle in the system, with extended
 * information.
 */
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ACCESS_MASK GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

/**
 * The SYSTEM_HANDLE_INFORMATION_EX structure contains extended information about the open handles in the system.
 */
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    _Field_size_(NumberOfHandles) SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

/**
 * The SYSTEM_BIGPOOL_ENTRY structure describes a single large pool allocation.
 */
typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union
    {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    } DUMMYUNIONNAME;
    SIZE_T SizeInBytes;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    } DUMMYUNIONNAME2;
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

/**
 * The SYSTEM_BIGPOOL_INFORMATION structure contains information about the system's large pool allocations.
 */
typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
    ULONG Count;
    _Field_size_(Count) SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

/**
 * The SYSTEM_POOL_ENTRY structure describes a single pool allocation.
 */
typedef struct _SYSTEM_POOL_ENTRY
{
    BOOLEAN Allocated;
    BOOLEAN Spare0;
    USHORT AllocatorBackTraceIndex;
    ULONG Size;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
        PVOID ProcessChargedQuota;
    } DUMMYUNIONNAME;
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

/**
 * The SYSTEM_POOL_INFORMATION structure contains information about the system pool allocations.
 */
typedef struct _SYSTEM_POOL_INFORMATION
{
    SIZE_T TotalSize;
    PVOID FirstEntry;
    USHORT EntryOverhead;
    BOOLEAN PoolTagPresent;
    BOOLEAN Spare0;
    ULONG NumberOfEntries;
    _Field_size_(NumberOfEntries) SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

_Struct_size_bytes_(NextEntryOffset)
/**
 * The SYSTEM_SESSION_POOLTAG_INFORMATION structure contains system session pooltag information.
 */
typedef struct _SYSTEM_SESSION_POOLTAG_INFORMATION
{
    SIZE_T NextEntryOffset;
    ULONG SessionId;
    ULONG Count;
    _Field_size_(Count) SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_SESSION_POOLTAG_INFORMATION, *PSYSTEM_SESSION_POOLTAG_INFORMATION;

_Struct_size_bytes_(NextEntryOffset)
/**
 * The SYSTEM_SESSION_MAPPED_VIEW_INFORMATION structure contains system session mapped view information.
 */
typedef struct _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
{
    SIZE_T NextEntryOffset;
    ULONG SessionId;
    ULONG ViewFailures;
    SIZE_T NumberOfBytesAvailable;
    SIZE_T NumberOfBytesAvailableContiguous;
} SYSTEM_SESSION_MAPPED_VIEW_INFORMATION, *PSYSTEM_SESSION_MAPPED_VIEW_INFORMATION;

/**
 * The WATCHDOG_HANDLER_ACTION enumeration defines the actions for watchdog handler.
 */
typedef enum _WATCHDOG_HANDLER_ACTION
{
    WdActionSetTimeoutValue,
    WdActionQueryTimeoutValue,
    WdActionResetTimer,
    WdActionStopTimer,
    WdActionStartTimer,
    WdActionSetTriggerAction,
    WdActionQueryTriggerAction,
    WdActionQueryState
} WATCHDOG_HANDLER_ACTION;

typedef
_Function_class_(SYSTEM_WATCHDOG_HANDLER)
NTSTATUS
NTAPI
SYSTEM_WATCHDOG_HANDLER(
    _In_ WATCHDOG_HANDLER_ACTION Action,
    _In_ PVOID Context,
    _Inout_ PULONG DataValue,
    _In_ BOOLEAN NoLocks);
typedef SYSTEM_WATCHDOG_HANDLER* PSYSTEM_WATCHDOG_HANDLER;

// private
/**
 * The SYSTEM_WATCHDOG_HANDLER_INFORMATION structure contains system watchdog handler information.
 */
typedef struct _SYSTEM_WATCHDOG_HANDLER_INFORMATION
{
    PSYSTEM_WATCHDOG_HANDLER WdHandler;
    PVOID Context;
} SYSTEM_WATCHDOG_HANDLER_INFORMATION, *PSYSTEM_WATCHDOG_HANDLER_INFORMATION;

/**
 * The WATCHDOG_INFORMATION_CLASS enumeration defines the information classes for querying and setting watchdog
 * information.
 */
typedef enum _WATCHDOG_INFORMATION_CLASS
{
    WdInfoTimeoutValue = 0,
    WdInfoResetTimer = 1,
    WdInfoStopTimer = 2,
    WdInfoStartTimer = 3,
    WdInfoTriggerAction = 4,
    WdInfoState = 5,
    WdInfoTriggerReset = 6,
    WdInfoNop = 7,
    WdInfoGeneratedLastReset = 8,
    WdInfoInvalid = 9,
} WATCHDOG_INFORMATION_CLASS;

// private
/**
 * The SYSTEM_WATCHDOG_TIMER_INFORMATION structure contains system watchdog timer information.
 */
typedef struct _SYSTEM_WATCHDOG_TIMER_INFORMATION
{
    WATCHDOG_INFORMATION_CLASS WdInfoClass;
    ULONG DataValue;
} SYSTEM_WATCHDOG_TIMER_INFORMATION, *PSYSTEM_WATCHDOG_TIMER_INFORMATION;

#if !defined(_KERNEL_MODE)
// private
/**
 * The SYSTEM_FIRMWARE_TABLE_ACTION enumeration defines the actions for enumerating or retrieving firmware tables.
 */
typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
    SystemFirmwareTable_Enumerate,
    SystemFirmwareTable_Get
} SYSTEM_FIRMWARE_TABLE_ACTION;

// private
/**
 * The SYSTEM_FIRMWARE_TABLE_INFORMATION structure specifies a firmware table request and receives its data.
 */
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    ULONG ProviderSignature; // (same as the GetSystemFirmwareTable function)
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID;
    ULONG TableBufferLength;
    _Field_size_bytes_(TableBufferLength) UCHAR TableBuffer[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;
#endif

#if !defined(_KERNEL_MODE)

// private
typedef _Function_class_(FNFTH)
NTSTATUS STDAPIVCALLTYPE FNFTH(
    _Inout_ PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo
    );
typedef FNFTH* PFNFTH;

// private
/**
 * The SYSTEM_FIRMWARE_TABLE_HANDLER structure describes the system firmware table handler.
 */
typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
{
    ULONG ProviderSignature;
    BOOLEAN Register;
    PFNFTH FirmwareTableHandler;
    PVOID DriverObject;
} SYSTEM_FIRMWARE_TABLE_HANDLER, *PSYSTEM_FIRMWARE_TABLE_HANDLER;

#endif

// private
/**
 * The SYSTEM_MEMORY_LIST_INFORMATION structure contains system memory list information.
 */
typedef struct _SYSTEM_MEMORY_LIST_INFORMATION
{
    SIZE_T ZeroPageCount;
    SIZE_T FreePageCount;
    SIZE_T ModifiedPageCount;
    SIZE_T ModifiedNoWritePageCount;
    SIZE_T BadPageCount;
    SIZE_T PageCountByPriority[8];
    SIZE_T RepurposedPagesByPriority[8];
    SIZE_T ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION, *PSYSTEM_MEMORY_LIST_INFORMATION;

// private
/**
 * The SYSTEM_MEMORY_LIST_COMMAND enumeration defines the commands for manipulating the system memory lists.
 */
typedef enum _SYSTEM_MEMORY_LIST_COMMAND
{
    MemoryCaptureAccessedBits,
    MemoryCaptureAndResetAccessedBits,
    MemoryEmptyWorkingSets,
    MemoryFlushModifiedList,
    MemoryPurgeStandbyList,
    MemoryPurgeLowPriorityStandbyList,
    MemoryCommandMax
} SYSTEM_MEMORY_LIST_COMMAND;

/**
 * The SYSTEM_THREAD_CID_PRIORITY_INFORMATION structure is used with NtSetSystemInformation
 * to set the priority of a thread by its client ID without requiring a thread handle.
 *
 * \remarks This structure is used with the SystemThreadPriorityClientIdInformation
 * information class (0x52). The caller must have SeIncreaseBasePriorityPrivilege
 * to raise a thread's priority above normal.
 */
typedef struct _SYSTEM_THREAD_CID_PRIORITY_INFORMATION
{
    CLIENT_ID ClientId; // The process and thread identifiers of the target thread.
    KPRIORITY Priority; // The new priority value to assign to the thread.
} SYSTEM_THREAD_CID_PRIORITY_INFORMATION, *PSYSTEM_THREAD_CID_PRIORITY_INFORMATION;

/**
 * The SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION structure contains the cumulative number of clock cycles a logical processor
 * has spent running its idle thread, deferred procedure calls (DPCs) and interrupt service routines (ISRs) since it became active.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryidleprocessorcycletimeex
 */
typedef struct _SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION
{
    ULONGLONG CycleTime;
} SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION, *PSYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION;

// private
/**
 * The SYSTEM_VERIFIER_ISSUE structure describes the system verifier issue.
 */
typedef struct _SYSTEM_VERIFIER_ISSUE
{
    ULONGLONG IssueType;
    PVOID Address;
    ULONGLONG Parameters[2];
} SYSTEM_VERIFIER_ISSUE, *PSYSTEM_VERIFIER_ISSUE;

// private
/**
 * The SYSTEM_VERIFIER_CANCELLATION_INFORMATION structure contains system verifier cancellation information.
 */
typedef struct _SYSTEM_VERIFIER_CANCELLATION_INFORMATION
{
    ULONG CancelProbability;
    ULONG CancelThreshold;
    ULONG CompletionThreshold;
    ULONG CancellationVerifierDisabled;
    ULONG AvailableIssues;
    SYSTEM_VERIFIER_ISSUE Issues[128];
} SYSTEM_VERIFIER_CANCELLATION_INFORMATION, *PSYSTEM_VERIFIER_CANCELLATION_INFORMATION;

// private
/**
 * The SYSTEM_REF_TRACE_INFORMATION structure contains system ref trace information.
 */
typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
    BOOLEAN TraceEnable;
    BOOLEAN TracePermanent;
    UNICODE_STRING TraceProcessName;
    UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION;

// private
#define SYSTEM_SPECIAL_POOL_CATCH_OVERRUNS 0x1 // MmSpecialPoolCatchOverruns

// private
/**
 * The SYSTEM_SPECIAL_POOL_INFORMATION structure contains system special pool information.
 */
typedef struct _SYSTEM_SPECIAL_POOL_INFORMATION
{
    ULONG PoolTag;
    ULONG Flags; // SYSTEM_SPECIAL_POOL_* flags
} SYSTEM_SPECIAL_POOL_INFORMATION, *PSYSTEM_SPECIAL_POOL_INFORMATION;

/**
 * The SYSTEM_PROCESS_ID_INFORMATION structure retrieves the executable image
 * name associated with a specific process ID. The caller supplies a process ID,
 * and on return the system fills the UNICODE_STRING with the corresponding image path.
 */
typedef struct _SYSTEM_PROCESS_ID_INFORMATION
{
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
} SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION;

// private
/**
 * The SYSTEM_HYPERVISOR_QUERY_INFORMATION structure contains system hypervisor query information.
 */
typedef struct _SYSTEM_HYPERVISOR_QUERY_INFORMATION
{
    BOOLEAN HypervisorConnected;
    BOOLEAN HypervisorDebuggingEnabled;
    BOOLEAN HypervisorPresent;
    BOOLEAN Spare0[5];
    ULONGLONG EnabledEnlightenments;
} SYSTEM_HYPERVISOR_QUERY_INFORMATION, *PSYSTEM_HYPERVISOR_QUERY_INFORMATION;

// private
/**
 * The SYSTEM_BOOT_ENVIRONMENT_INFORMATION structure contains system boot environment information.
 */
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
{
    GUID BootIdentifier;
    FIRMWARE_TYPE FirmwareType;
    union
    {
        ULONGLONG BootFlags;
        struct
        {
            ULONGLONG DbgMenuOsSelection : 1; // REDSTONE4
            ULONGLONG DbgHiberBoot : 1;
            ULONGLONG DbgSoftBoot : 1;
            ULONGLONG DbgMeasuredLaunch : 1;
            ULONGLONG DbgMeasuredLaunchCapable : 1; // 19H1
            ULONGLONG DbgSystemHiveReplace : 1;
            ULONGLONG DbgMeasuredLaunchSmmProtections : 1;
            ULONGLONG DbgMeasuredLaunchSmmLevel : 7; // 20H1
            ULONGLONG DbgBugCheckRecovery : 1; // 24H2
            ULONGLONG DbgFASR : 1;
            ULONGLONG DbgUseCachedBcd : 1;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

// private
/**
 * The SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION structure contains system image file execution options
 * information.
 */
typedef struct _SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION
{
    ULONG FlagsToEnable; // FLG_* bits to add to the image's execution options.
    ULONG FlagsToDisable; // FLG_* bits to clear from the image's execution options.
} SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION, *PSYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION;

// private
/**
 * The COVERAGE_REQUEST_CODES enumeration defines the request codes for coverage request.
 */
typedef enum _COVERAGE_REQUEST_CODES
{
    CoverageAllModules = 0,
    CoverageSearchByHash = 1,
    CoverageSearchByName = 2
} COVERAGE_REQUEST_CODES;

// private
/**
 * The COVERAGE_MODULE_REQUEST structure describes a coverage module request.
 */
typedef struct _COVERAGE_MODULE_REQUEST
{
    COVERAGE_REQUEST_CODES RequestType;
    union
    {
        UCHAR MD5Hash[16];
        UNICODE_STRING ModuleName;
    } SearchInfo;
} COVERAGE_MODULE_REQUEST, *PCOVERAGE_MODULE_REQUEST;

// private
/**
 * The COVERAGE_MODULE_INFO structure contains coverage module information.
 */
typedef struct _COVERAGE_MODULE_INFO
{
    ULONG ModuleInfoSize;
    ULONG IsBinaryLoaded;
    UNICODE_STRING ModulePathName;
    ULONG CoverageSectionSize;
    _Field_size_bytes_(CoverageSectionSize) UCHAR CoverageSection[1];
} COVERAGE_MODULE_INFO, *PCOVERAGE_MODULE_INFO;

// private
/**
 * The COVERAGE_MODULES structure describes the coverage modules.
 */
typedef struct _COVERAGE_MODULES
{
    ULONG ListAndReset;
    ULONG NumberOfModules;
    COVERAGE_MODULE_REQUEST ModuleRequestInfo;
    COVERAGE_MODULE_INFO Modules[1];
} COVERAGE_MODULES, *PCOVERAGE_MODULES;

// private
/**
 * The SYSTEM_PREFETCH_PATCH_INFORMATION structure contains system prefetch patch information.
 */
typedef struct _SYSTEM_PREFETCH_PATCH_INFORMATION
{
    ULONG PrefetchPatchCount;
} SYSTEM_PREFETCH_PATCH_INFORMATION, *PSYSTEM_PREFETCH_PATCH_INFORMATION;

// private
/**
 * The SYSTEM_VERIFIER_FAULTS_INFORMATION structure contains system verifier faults information.
 */
typedef struct _SYSTEM_VERIFIER_FAULTS_INFORMATION
{
    ULONG Probability;
    ULONG MaxProbability;
    UNICODE_STRING PoolTags;
    UNICODE_STRING Applications;
} SYSTEM_VERIFIER_FAULTS_INFORMATION, *PSYSTEM_VERIFIER_FAULTS_INFORMATION;

// private
/**
 * The SYSTEM_VERIFIER_INFORMATION_EX structure contains system verifier information.
 */
typedef struct _SYSTEM_VERIFIER_INFORMATION_EX
{
    ULONG VerifyMode;
    ULONG OptionChanges;
    UNICODE_STRING PreviousBucketName;
    ULONG IrpCancelTimeoutMsec;
    ULONG VerifierExtensionEnabled;
#ifdef _WIN64
    ULONG Reserved[1];
#else
    ULONG Reserved[3];
#endif
} SYSTEM_VERIFIER_INFORMATION_EX, *PSYSTEM_VERIFIER_INFORMATION_EX;

// private
/**
 * The SYSTEM_SYSTEM_PARTITION_INFORMATION structure contains system system partition information.
 */
typedef struct _SYSTEM_SYSTEM_PARTITION_INFORMATION
{
    UNICODE_STRING SystemPartition;
} SYSTEM_SYSTEM_PARTITION_INFORMATION, *PSYSTEM_SYSTEM_PARTITION_INFORMATION;

// private
/**
 * The SYSTEM_SYSTEM_DISK_INFORMATION structure contains system system disk information.
 */
typedef struct _SYSTEM_SYSTEM_DISK_INFORMATION
{
    UNICODE_STRING SystemDisk;
} SYSTEM_SYSTEM_DISK_INFORMATION, *PSYSTEM_SYSTEM_DISK_INFORMATION;

// private
/**
 * The SYSTEM_NUMA_PROXIMITY_MAP structure describes the system NUMA proximity map.
 */
typedef struct _SYSTEM_NUMA_PROXIMITY_MAP
{
    ULONG NodeProximityId;
    USHORT NodeNumber;
} SYSTEM_NUMA_PROXIMITY_MAP, *PSYSTEM_NUMA_PROXIMITY_MAP;

// private (Windows 8.1 and above)
/**
 * The SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT structure describes the system processor performance hitcount.
 */
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT
{
    ULONGLONG Hits;
    UCHAR PercentFrequency;
} SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT, *PSYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT;

// private (Windows 8.1 and above)
/**
 * The SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION structure describes the system processor performance state
 * distribution.
 */
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION
{
    ULONG ProcessorNumber;
    ULONG StateCount;
    _Field_size_(StateCount) SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT States[1];
} SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION, *PSYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION;

// private (Windows 7 and Windows 8)
/**
 * The SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT_WIN8 structure describes the system processor performance hitcount WIN8.
 */
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT_WIN8
{
    ULONG Hits;
    UCHAR PercentFrequency;
} SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT_WIN8, *PSYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT_WIN8;

// private (Windows 7 and Windows 8)
/**
 * The SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION_WIN8 structure describes the system processor performance
 * state distribution WIN8.
 */
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION_WIN8
{
    ULONG ProcessorNumber;
    ULONG StateCount;
    _Field_size_(StateCount) SYSTEM_PROCESSOR_PERFORMANCE_HITCOUNT_WIN8 States[1];
} SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION_WIN8, *PSYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION_WIN8;

// private
/**
 * The SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION structure describes the system processor performance distribution.
 */
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
{
    ULONG ProcessorCount;
    ULONG Offsets[1];
} SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION, *PSYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION;

//
// The hit counts in SYSTEM_PROCESSOR_PERFORMANCE_STATE_DISTRIBUTION are the raw data behind the
// "Processor Information" counter set (counter set {b4fc721a-0378-476f-89ba-a5a79f810b36}).
//
// The weighted mean of the hit counts is "% Processor Performance" (counter 24), the average
// performance of the processor while it is executing instructions, as a percentage of its nominal
// performance:
//
//     PercentPerformance = SUM(dHits[i] * PercentFrequency[i]) / SUM(dHits[i])
//
// On hardware performance state (HWP/CPPC) systems the table is a two entry pseudo distribution
// with PercentFrequency values of 0 and 255, encoded so the ordinary weighted mean above yields the
// correct answer. The result may exceed 100 percent when the processor is above its nominal
// frequency, and callers must not clamp it. "Actual Frequency" (counter 33) is:
//
//     ActualFrequency = PercentPerformance * NominalFrequency / 100
//
// where NominalFrequency comes from PowerInternalProcessorBrandedFrequency. Note that
// PROCESSOR_POWER_INFORMATION.CurrentMhz is a performance state value and does not track the
// delivered frequency on turbo capable processors.
//
// The hit counts do not count events. They accumulate unhalted reference time, advancing only while
// the processor is executing, which is what makes "% Processor Utility" (counter 26) recoverable.
// Utility and performance share one numerator in the kernel and differ only in their divisor:
// performance divides by unhalted time, utility divides by elapsed time. So:
//
//     UnhaltedTime100ns = SUM(dHits[i]) * HITCOUNT_UNIT_NUMERATOR / HITCOUNT_UNIT_DENOMINATOR
//     PercentUtility    = PercentPerformance * UnhaltedTime100ns / dElapsed100ns
//
// which reduces to SUM(dHits[i] * PercentFrequency[i]) * 512 / (255 * dElapsed100ns).
//
// The unit was measured against the counter set on an x64 HWP system and agreed to within 0.03%
// across idle and saturated processors, and confirmed on AMD (Zen 5, CPPC) where the unit implied by
// the counter set matched 512/255 to within 0.01% and the recovered utility tracked "% Processor
// Utility" to within 0.06 percentage points. Both report the two entry pseudo distribution. It is
// unvalidated on ARM64 and on legacy performance state tables, which report an occurrence count
// rather than these accumulators and have no PercentFrequency == 0 entry; the presence of that entry
// discriminates between the two forms.
//
#define SYSTEM_PROCESSOR_HITCOUNT_UNIT_NUMERATOR   512 // 512/255 of a 100ns interval, ~200.8ns
#define SYSTEM_PROCESSOR_HITCOUNT_UNIT_DENOMINATOR 255

#define CODEINTEGRITY_OPTION_ENABLED 0x01
#define CODEINTEGRITY_OPTION_TESTSIGN 0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED 0x04
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED 0x08
#define CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED 0x10
#define CODEINTEGRITY_OPTION_TEST_BUILD 0x20
#define CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD 0x40
#define CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED 0x80
#define CODEINTEGRITY_OPTION_FLIGHT_BUILD 0x100
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED 0x200
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED 0x800
#define CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED 0x1000
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED 0x2000
#define CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED 0x4000
#define CODEINTEGRITY_OPTION_WHQL_AUDITMODE_ENABLED 0x8000

// private
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    union
    {
        ULONG CodeIntegrityOptions;
        struct
        {
            ULONG Enabled : 1;                          // CODEINTEGRITY_OPTION_ENABLED
            ULONG TestSign : 1;                         // CODEINTEGRITY_OPTION_TESTSIGN
            ULONG UmciEnabled : 1;                      // CODEINTEGRITY_OPTION_UMCI_ENABLED
            ULONG UmciAuditModeEnabled : 1;             // CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED
            ULONG UmciExclusionPathsEnabled : 1;        // CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED
            ULONG TestBuild : 1;                        // CODEINTEGRITY_OPTION_TEST_BUILD
            ULONG PreproductionBuild : 1;               // CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD
            ULONG DebugModeEnabled : 1;                 // CODEINTEGRITY_OPTION_DEBUGMODE_ENABLE
            ULONG FlightBuild : 1;                      // CODEINTEGRITY_OPTION_FLIGHT_BUILD
            ULONG FlightingEnabled : 1;                 // CODEINTEGRITY_OPTION_FLIGHTING_ENABLED
            ULONG HvciKmciEnabled : 1;                  // CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
            ULONG HvciKmciAuditModeEnabled : 1;         // CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED
            ULONG HvciKmciStrictModeEnabled : 1;        // CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED
            ULONG HvciIumEnabled : 1;                   // CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED
            ULONG WhqlEnforcementEnabled : 1;           // CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED
            ULONG WhqlAuditModeEnabled : 1;             // CODEINTEGRITY_OPTION_WHQL_AUDITMODE_ENABLED
            ULONG Spare : 16;
        };
    };
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

// rev
// Loads mcupdate.dll via ntosext.sys to perform microcode updates.
#define PROCESSOR_MICROCODE_OPERATION_LOAD 0x01
// rev
// Unloads mcupdate.dll via ntosext.sys to preform microcode updates.
#define PROCESSOR_MICROCODE_OPERATION_UNLOAD 0x02

// private
/**
 * The SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION structure contains system processor microcode update information.
 */
typedef struct _SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
{
    ULONG Operation;
} SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION, *PSYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION;

// private
/**
 * The SYSTEM_PROCESSOR_BRAND_STRING structure contains the processor brand string.
 */
typedef struct _SYSTEM_PROCESSOR_BRAND_STRING
{
    CHAR BrandString[49];
} SYSTEM_PROCESSOR_BRAND_STRING, *PSYSTEM_PROCESSOR_BRAND_STRING;

// private
typedef HANDLE SYSTEM_WIN32_WER_START_CALLOUT, *PSYSTEM_WIN32_WER_START_CALLOUT;

// private
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_ENCRYPT                 0x01 // SYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V0/V1
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_DECRYPT                 0x02 // SYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V0/V1
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_EXECUTE                 0x03 // variable execute request
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_FLUSH                   0x04 // no payload
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_RESERVED5               0x05 // rejected
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_RESERVED6               0x06 // rejected
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_QUERY                   0x07 // no payload
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_SET_DYNAMIC_ENFORCEMENT 0x08 // sub_140A6375C, SYSTEM_CONTROL_FLOW_TRANSITION_OP8
#define SYSTEM_CONTROL_FLOW_TRANSITION_OPERATION_UNLOAD_MODULE           0x09 // WbHeapExecutionUnloadModule/sub_140A50E08, SYSTEM_CONTROL_FLOW_TRANSITION_OP9

/**
 * \brief Warbird control-flow transition request header.
 *
 * Used with \c SystemControlFlowTransition to dispatch an operation-tagged
 * request into the kernel's Warbird control-flow transition handlers.
 *
 * Warbird is Windows' internal code/data protection and controlled execution
 * mechanism used by protected components to transition memory between encrypted,
 * decrypted, and executable states under policy.
 *
 * \a Parameters points to an operation-specific payload determined by
 * \a Operation.
 */
// private
/**
 * The SYSTEM_CONTROL_FLOW_TRANSITION structure describes the system control flow transition.
 */
typedef struct _SYSTEM_CONTROL_FLOW_TRANSITION
{
    ULONG Operation;
    ULONG Reserved;
    PVOID Parameters; // User pointer to an operation-specific payload.
} SYSTEM_CONTROL_FLOW_TRANSITION, *PSYSTEM_CONTROL_FLOW_TRANSITION;

// private
/**
 * The SYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V0 structure describes the system control flow transition segment V0.
 */
typedef struct _SYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V0
{
    UCHAR Data[0xF4]; // Opaque Warbird segment descriptor for operations 1/2, format selector 0.
} SYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V0, *PSYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V0;

// private
/**
 * The SYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V1 structure describes the system control flow transition segment V1.
 */
typedef struct _SYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V1
{
    UCHAR Data[0xF8]; // Opaque Warbird segment descriptor for operations 1/2, format selector 1.
} SYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V1, *PSYSTEM_CONTROL_FLOW_TRANSITION_SEGMENT_V1;

// private
/**
 * The SYSTEM_CONTROL_FLOW_TRANSITION_OP8 structure describes the system control flow transition OP8.
 */
typedef struct _SYSTEM_CONTROL_FLOW_TRANSITION_OP8
{
    ULONG ReservedMustBeZero;
    ULONG LengthOrFlags;
    ULONGLONG Reserved2;
    PVOID PointerOrHandle;
} SYSTEM_CONTROL_FLOW_TRANSITION_OP8, *PSYSTEM_CONTROL_FLOW_TRANSITION_OP8;

// private
/**
 * The SYSTEM_CONTROL_FLOW_TRANSITION_OP9 structure describes the system control flow transition OP9.
 */
typedef struct _SYSTEM_CONTROL_FLOW_TRANSITION_OP9
{
    ULONG ReservedMustBeZero;
    ULONG Reserved;
    PVOID ModuleBase;
} SYSTEM_CONTROL_FLOW_TRANSITION_OP9, *PSYSTEM_CONTROL_FLOW_TRANSITION_OP9;

// private
/**
 * The SYSTEM_SECURE_DUMP_ENCRYPTION_INFORMATION structure contains system secure dump encryption information.
 */
typedef struct _SYSTEM_SECURE_DUMP_ENCRYPTION_INFORMATION
{
    UCHAR Data[ANYSIZE_ARRAY]; // Opaque input/output buffer used by VslTransformDumpKey via NtQuerySystemInformationEx.
} SYSTEM_SECURE_DUMP_ENCRYPTION_INFORMATION, *PSYSTEM_SECURE_DUMP_ENCRYPTION_INFORMATION;

// private
#define SYSTEM_FIRMWARE_BOOT_PERFORMANCE_SIGNATURE 0x54504246u // "FBPT"

// private
/**
 * The SYSTEM_FIRMWARE_BOOT_PERFORMANCE_INFORMATION structure contains system firmware boot performance information.
 */
typedef struct _SYSTEM_FIRMWARE_BOOT_PERFORMANCE_INFORMATION
{
    ULONG Signature; // SYSTEM_FIRMWARE_BOOT_PERFORMANCE_SIGNATURE
    ULONG Length; // Total size of the copied ACPI FBPT, including trailing records.
    UCHAR Data[ANYSIZE_ARRAY]; // Firmware boot performance records.
} SYSTEM_FIRMWARE_BOOT_PERFORMANCE_INFORMATION, *PSYSTEM_FIRMWARE_BOOT_PERFORMANCE_INFORMATION;

// private
/**
 * The SYSTEM_VA_TYPE enumeration defines the system VA types.
 */
typedef enum _SYSTEM_VA_TYPE
{
    SystemVaTypeAll,
    SystemVaTypeNonPagedPool,
    SystemVaTypePagedPool,
    SystemVaTypeSystemCache,
    SystemVaTypeSystemPtes,
    SystemVaTypeSessionSpace,
    SystemVaTypeMax
} SYSTEM_VA_TYPE, *PSYSTEM_VA_TYPE;

// private
/**
 * The SYSTEM_VA_LIST_INFORMATION structure contains system VA list information.
 */
typedef struct _SYSTEM_VA_LIST_INFORMATION
{
    SIZE_T VirtualSize;
    SIZE_T VirtualPeak;
    SIZE_T VirtualLimit;
    SIZE_T AllocationFailures;
} SYSTEM_VA_LIST_INFORMATION, *PSYSTEM_VA_LIST_INFORMATION;

// private
//typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP
//{
//    RelationProcessorCore,
//    RelationNumaNode,
//    RelationCache,
//    RelationProcessorPackage,
//    RelationGroup,
//    RelationProcessorDie,
//    RelationNumaNodeEx,
//    RelationProcessorModule,
//    RelationAll = 0xffff
//} LOGICAL_PROCESSOR_RELATIONSHIP;
//
// private
//typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION
//{
//    ULONG_PTR ProcessorMask;
//    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
//    union
//    {
//        struct
//        {
//            UCHAR Flags;
//        } ProcessorCore;
//        struct
//        {
//            ULONG NodeNumber;
//        } NumaNode;
//        CACHE_DESCRIPTOR Cache;
//        ULONGLONG Reserved[2];
//    };
//} SYSTEM_LOGICAL_PROCESSOR_INFORMATION, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;
//
// private
//typedef struct _PROCESSOR_RELATIONSHIP
//{
//    UCHAR Flags;
//    UCHAR EfficiencyClass;
//    UCHAR Reserved[20];
//    USHORT GroupCount;
//    _Field_size_(GroupCount) GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
//} PROCESSOR_RELATIONSHIP, *PPROCESSOR_RELATIONSHIP;
//
// private
//typedef struct _NUMA_NODE_RELATIONSHIP
//{
//    ULONG NodeNumber;
//    UCHAR Reserved[18];
//    USHORT GroupCount;
//    union
//    {
//        GROUP_AFFINITY GroupMask;
//        _Field_size_(GroupCount) GROUP_AFFINITY GroupMasks[ANYSIZE_ARRAY];
//    };
//} NUMA_NODE_RELATIONSHIP, *PNUMA_NODE_RELATIONSHIP;
//
// private
//typedef struct _CACHE_RELATIONSHIP
//{
//    UCHAR Level;
//    UCHAR Associativity;
//    USHORT LineSize;
//    ULONG CacheSize;
//    PROCESSOR_CACHE_TYPE Type;
//    UCHAR Reserved[18];
//    USHORT GroupCount;
//    union
//    {
//        GROUP_AFFINITY GroupMask;
//        _Field_size_(GroupCount) GROUP_AFFINITY GroupMasks[ANYSIZE_ARRAY];
//    };
//} CACHE_RELATIONSHIP, *PCACHE_RELATIONSHIP;
//
// private
//typedef struct _PROCESSOR_GROUP_INFO
//{
//    UCHAR MaximumProcessorCount;
//    UCHAR ActiveProcessorCount;
//    UCHAR Reserved[38];
//    KAFFINITY ActiveProcessorMask;
//} PROCESSOR_GROUP_INFO, *PPROCESSOR_GROUP_INFO;
//
// private
//typedef struct _GROUP_RELATIONSHIP
//{
//    USHORT MaximumGroupCount;
//    USHORT ActiveGroupCount;
//    UCHAR Reserved[20];
//    _Field_size_(ActiveGroupCount) PROCESSOR_GROUP_INFO GroupInfo[ANYSIZE_ARRAY];
//} GROUP_RELATIONSHIP, *PGROUP_RELATIONSHIP;
//
// private
//typedef _Struct_size_bytes_(Size) struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
//{
//    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
//    ULONG Size;
//    _Field_size_bytes_(Size - (sizeof(LOGICAL_PROCESSOR_RELATIONSHIP) + sizeof(ULONG))) union
//    {
//        PROCESSOR_RELATIONSHIP Processor;
//        NUMA_NODE_RELATIONSHIP NumaNode;
//        CACHE_RELATIONSHIP Cache;
//        GROUP_RELATIONSHIP Group;
//    };
//} SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;

// rev
/**
 * The STORE_INFORMATION_CLASS enumeration defines the information classes for querying and setting store information.
 */
typedef enum _STORE_INFORMATION_CLASS
{
    StorePageRequest = 1,
    StoreStatsRequest = 2, // q: SM_STATS_REQUEST // SmProcessStatsRequest
    StoreCreateRequest = 3, // s: SM_CREATE_REQUEST (requires SeProfileSingleProcessPrivilege)
    StoreDeleteRequest = 4, // s: SM_DELETE_REQUEST (requires SeProfileSingleProcessPrivilege)
    StoreListRequest = 5, // q: SM_STORE_LIST_REQUEST / SM_STORE_LIST_REQUEST_EX // SmProcessListRequest
    Available1 = 6,
    StoreEmptyRequest = 7,
    CacheListRequest = 8, // q: SMC_CACHE_LIST_REQUEST // SmcProcessListRequest
    CacheCreateRequest = 9, // s: SMC_CACHE_CREATE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheDeleteRequest = 10, // s: SMC_CACHE_DELETE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheStoreCreateRequest = 11, // s: SMC_STORE_CREATE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheStoreDeleteRequest = 12, // s: SMC_STORE_DELETE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheStatsRequest = 13, // q: SMC_CACHE_STATS_REQUEST // SmcProcessStatsRequest
    Available2 = 14,
    RegistrationRequest = 15, // q: SM_REGISTRATION_REQUEST (requires SeProfileSingleProcessPrivilege) // SmProcessRegistrationRequest
    GlobalCacheStatsRequest = 16,
    StoreResizeRequest = 17, // s: SM_STORE_RESIZE_REQUEST (requires SeProfileSingleProcessPrivilege)
    CacheStoreResizeRequest = 18, // s: SM_STORE_CACHE_RESIZE_REQUEST (requires SeProfileSingleProcessPrivilege)
    SmConfigRequest = 19, // s: SM_CONFIG_REQUEST (requires SeProfileSingleProcessPrivilege)
    StoreHighMemoryPriorityRequest = 20, // s: SM_STORE_HIGH_MEMORY_PRIORITY_REQUEST (requires SeProfileSingleProcessPrivilege)
    SystemStoreTrimRequest = 21, // s: SM_SYSTEM_STORE_TRIM_REQUEST (requires SeProfileSingleProcessPrivilege) // SmProcessSystemStoreTrimRequest
    MemCompressionInfoRequest = 22,  // q: SM_STORE_COMPRESSION_INFORMATION_REQUEST // SmProcessCompressionInfoRequest
    ProcessStoreInfoRequest = 23, // SmProcessProcessStoreInfoRequest
    StoreInformationMax
} STORE_INFORMATION_CLASS;

// rev
#define SYSTEM_STORE_INFORMATION_VERSION 1

// rev
/**
 * The SYSTEM_STORE_INFORMATION structure wraps a store manager request issued through NtQuerySystemInformation with
 * SystemStoreInformation.
 */
typedef struct _SYSTEM_STORE_INFORMATION
{
    _In_ ULONG Version;
    _In_ STORE_INFORMATION_CLASS StoreInformationClass;
    _Inout_ PVOID Data;
    _Inout_ ULONG Length;
} SYSTEM_STORE_INFORMATION, *PSYSTEM_STORE_INFORMATION;

#define SYSTEM_STORE_STATS_INFORMATION_VERSION 2

/**
 * The ST_STATS_LEVEL enumeration defines the level of detail requested for store statistics.
 */
typedef enum _ST_STATS_LEVEL
{
    StStatsLevelBasic = 0,
    StStatsLevelIoStats = 1,
    StStatsLevelRegionSpace = 2, // requires SeProfileSingleProcessPrivilege
    StStatsLevelSpaceBitmap = 3, // requires SeProfileSingleProcessPrivilege
    StStatsLevelMax = 4
} ST_STATS_LEVEL;

/**
 * The SM_STATS_REQUEST structure describes a request for store manager statistics.
 */
typedef struct _SM_STATS_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_STATS_INFORMATION_VERSION
    ULONG DetailLevel : 8; // ST_STATS_LEVEL
    ULONG StoreId : 16;
    ULONG BufferSize;
    PVOID Buffer; // PST_STATS
} SM_STATS_REQUEST, *PSM_STATS_REQUEST;

/**
 * The ST_DATA_MGR_STATS structure contains statistics for the store data manager.
 */
typedef struct _ST_DATA_MGR_STATS
{
    ULONG RegionCount;
    ULONG PagesStored;
    ULONG UniquePagesStored;
    ULONG LazyCleanupRegionCount;
    struct
    {
        ULONG RegionsInUse;
        ULONG SpaceUsed;
    } Space[8]; // IDA: SmpProcessQueryStoreStats iterates all 8 buckets and sums RegionSize * RegionsInUse
} ST_DATA_MGR_STATS, *PST_DATA_MGR_STATS;

/**
 * The ST_IO_STATS_PERIOD structure contains store I/O statistics for a single time period.
 */
typedef struct _ST_IO_STATS_PERIOD
{
    ULONG PageCounts[5]; // one 20-byte IO period sample copied from the store's internal ring buffer
} ST_IO_STATS_PERIOD, *PST_IO_STATS_PERIOD;

/**
 * The ST_IO_STATS structure contains store I/O statistics.
 */
typedef struct _ST_IO_STATS
{
    ULONG PeriodCount; // number of valid exported periods, capped at 64
    ST_IO_STATS_PERIOD Periods[64]; // IDA: StCopyIoStats flattens the internal ring buffer into chronological order
} ST_IO_STATS, *PST_IO_STATS;

/**
 * The ST_READ_LATENCY_BUCKET structure describes a single store read-latency histogram bucket.
 */
typedef struct _ST_READ_LATENCY_BUCKET
{
    ULONG LatencyUs;
    ULONG Count;
} ST_READ_LATENCY_BUCKET, *PST_READ_LATENCY_BUCKET;

/**
 * The ST_READ_LATENCY_STATS structure contains store read-latency statistics.
 */
typedef struct _ST_READ_LATENCY_STATS
{
    ST_READ_LATENCY_BUCKET Buckets[8];
} ST_READ_LATENCY_STATS, *PST_READ_LATENCY_STATS;

// rev
/**
 * The ST_STATS_REGION_INFO structure contains statistics about a store region.
 */
typedef struct _ST_STATS_REGION_INFO
{
    USHORT SpaceUsed;
    UCHAR Priority;
    UCHAR Spare;
} ST_STATS_REGION_INFO, *PST_STATS_REGION_INFO;

// rev
/**
 * The ST_STATS_SPACE_BITMAP structure describes the store space-usage bitmap.
 */
typedef struct _ST_STATS_SPACE_BITMAP
{
    SIZE_T CompressedBytes;
    ULONG BytesPerBit;
    UCHAR StoreBitmap[1];
} ST_STATS_SPACE_BITMAP, *PST_STATS_SPACE_BITMAP;

// rev
/**
 * The ST_STATS structure contains store statistics.
 */
typedef struct _ST_STATS
{
    ULONG Version : 8; // SYSTEM_STORE_STATS_INFORMATION_VERSION
    ULONG Level : 4; // ST_STATS_LEVEL
    ULONG StoreType : 4; // SM_STORE_TYPE
    ULONG NoDuplication : 1;
    ULONG NoCompression : 1;
    ULONG EncryptionStrength : 12;
    ULONG VirtualRegions : 1;
    ULONG Spare0 : 1;
    ULONG Size; // total bytes returned in the caller-supplied stats buffer
    USHORT CompressionFormat;
    USHORT Spare;

    struct
    {
        ULONG RegionSize;
        ULONG RegionCount;
        ULONG RegionCountMax;
        ULONG Granularity;
        ST_DATA_MGR_STATS UserData;
        ST_DATA_MGR_STATS Metadata;
    } Basic; // present for StStatsLevelBasic and higher

    struct
    {
        ST_IO_STATS IoStats;
        ST_READ_LATENCY_STATS ReadLatencyStats;
    } Io; // present for StStatsLevelIoStats and higher

    // For StStatsLevelRegionSpace, variable-length ST_STATS_REGION_INFO[Basic.RegionCountMax] follows.
    // For StStatsLevelSpaceBitmap, ST_STATS_SPACE_BITMAP follows after the fixed header.
} ST_STATS, *PST_STATS;

// rev
/**
 * The ST_STATS_REGION_SPACE structure describes the space usage of a store region.
 */
typedef struct _ST_STATS_REGION_SPACE
{
    ST_STATS Stats;
    ST_STATS_REGION_INFO Regions[1]; // variable-length ST_STATS_REGION_INFO[Stats.Basic.RegionCountMax]
} ST_STATS_REGION_SPACE, *PST_STATS_REGION_SPACE;

// rev
/**
 * The ST_STATS_SPACE_BITMAP_EX structure describes the extended store space-usage bitmap.
 */
typedef struct _ST_STATS_SPACE_BITMAP_EX
{
    ST_STATS Stats;
    ST_STATS_SPACE_BITMAP SpaceBitmap; // variable-length bitmap payload follows in SpaceBitmap.StoreBitmap
} ST_STATS_SPACE_BITMAP_EX, *PST_STATS_SPACE_BITMAP_EX;

#define SYSTEM_STORE_CREATE_INFORMATION_VERSION 6

/**
 * The SM_STORE_TYPE enumeration defines the store manager store types.
 */
typedef enum _SM_STORE_TYPE
{
    StoreTypeInMemory = 0,
    StoreTypeFile = 1,
    StoreTypeMax = 2
} SM_STORE_TYPE;

// rev
#define SM_STORE_FLAG_NO_DUPLICATION 0x00000100u
#define SM_STORE_FLAG_FAIL_NO_COMPRESSION 0x00000200u
#define SM_STORE_FLAG_NO_COMPRESSION 0x00000400u
#define SM_STORE_FLAG_NO_ENCRYPTION 0x00000800u
#define SM_STORE_FLAG_NO_EVICT_ON_ADD 0x00001000u
#define SM_STORE_FLAG_PERFORMS_FILE_IO 0x00002000u
#define SM_STORE_FLAG_VDL_NOT_SET 0x00004000u
#define SM_STORE_FLAG_USE_INTERMEDIATE_ADD_BUFFER 0x00008000u
#define SM_STORE_FLAG_COMPRESS_NO_HUFF 0x00010000u
#define SM_STORE_FLAG_LOCK_ACTIVE_REGIONS 0x00020000u
#define SM_STORE_FLAG_VIRTUAL_REGIONS 0x00040000u

// rev
/**
 * The SM_STORE_BASIC_PARAMS structure specifies the basic parameters of a store manager store.
 */
typedef struct _SM_STORE_BASIC_PARAMS
{
    union
    {
        struct
        {
            ULONG StoreType : 8; // SM_STORE_TYPE
            ULONG NoDuplication : 1; // SM_STORE_FLAG_NO_DUPLICATION // rejected by SmProcessCreateRequest
            ULONG FailNoCompression : 1; // SM_STORE_FLAG_FAIL_NO_COMPRESSION // rejected by SmProcessCreateRequest
            ULONG NoCompression : 1; // SM_STORE_FLAG_NO_COMPRESSION
            ULONG NoEncryption : 1; // SM_STORE_FLAG_NO_ENCRYPTION
            ULONG NoEvictOnAdd : 1; // SM_STORE_FLAG_NO_EVICT_ON_ADD
            ULONG PerformsFileIo : 1; // SM_STORE_FLAG_PERFORMS_FILE_IO
            ULONG VdlNotSet : 1; // SM_STORE_FLAG_VDL_NOT_SET
            ULONG UseIntermediateAddBuffer : 1; // SM_STORE_FLAG_USE_INTERMEDIATE_ADD_BUFFER
            ULONG CompressNoHuff : 1; // SM_STORE_FLAG_COMPRESS_NO_HUFF
            ULONG LockActiveRegions : 1; // SM_STORE_FLAG_LOCK_ACTIVE_REGIONS // required for the in-memory create path observed in SmProcessCreateRequest
            ULONG VirtualRegions : 1; // SM_STORE_FLAG_VIRTUAL_REGIONS
            ULONG Spare : 13;
        } DUMMYSTRUCTNAME;
        ULONG StoreFlags; // low 8 bits: SM_STORE_TYPE, high bits: SM_STORE_FLAG_*
    } DUMMYUNIONNAME;
    ULONG Granularity; // store granularity; SmpDirtyStoreCreate uses 0x80 for dirty-store creation
    ULONG RegionSize; // region size; SmProcessCreateRequest rejects some in-memory create requests above 0x20000
    ULONG RegionCountMax; // maximum region count for the store
} SM_STORE_BASIC_PARAMS, *PSM_STORE_BASIC_PARAMS;

/**
 * The SMKM_REGION_EXTENT structure describes a region extent within the kernel-mode store manager.
 */
typedef struct _SMKM_REGION_EXTENT
{
    ULONG RegionCount;
    SIZE_T ByteOffset;
} SMKM_REGION_EXTENT, *PSMKM_REGION_EXTENT;

typedef struct _RTL_BITMAP *PRTL_BITMAP;

/**
 * The SMKM_FILE_INFO structure contains information about a store manager backing file.
 */
typedef struct _SMKM_FILE_INFO
{
    HANDLE FileHandle;
    PFILE_OBJECT FileObject;
    PFILE_OBJECT VolumeFileObject;
    PDEVICE_OBJECT VolumeDeviceObject;
    HANDLE VolumePnpHandle;
    PIRP UsageNotificationIrp;
    PSMKM_REGION_EXTENT Extents;
    ULONG ExtentCount;
} SMKM_FILE_INFO, *PSMKM_FILE_INFO;

/**
 * The SM_STORE_CACHE_BACKED_PARAMS structure specifies the parameters for a cache-backed store manager store.
 */
typedef struct _SM_STORE_CACHE_BACKED_PARAMS
{
    ULONG SectorSize;
    PCHAR EncryptionKey;
    ULONG EncryptionKeySize;
    PSMKM_FILE_INFO FileInfo;
    PVOID EtaContext;
    PRTL_BITMAP StoreRegionBitmap;
} SM_STORE_CACHE_BACKED_PARAMS, *PSM_STORE_CACHE_BACKED_PARAMS;

/**
 * The SM_STORE_PARAMETERS structure specifies the parameters of a store manager store.
 */
typedef struct _SM_STORE_PARAMETERS
{
    SM_STORE_BASIC_PARAMS Store;
    ULONG Priority;
    ULONG Flags;
    SM_STORE_CACHE_BACKED_PARAMS CacheBacked;
} SM_STORE_PARAMETERS, *PSM_STORE_PARAMETERS;

/**
 * The SM_CREATE_REQUEST structure describes a request to create a store manager store.
 */
typedef struct _SM_CREATE_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_CREATE_INFORMATION_VERSION
    ULONG AcquireReference : 1;
    ULONG KeyedStore : 1;
    ULONG Spare : 22;
    SM_STORE_PARAMETERS Params;
    ULONG StoreId;
} SM_CREATE_REQUEST, *PSM_CREATE_REQUEST;

#define SYSTEM_STORE_DELETE_INFORMATION_VERSION 1

/**
 * The SM_DELETE_REQUEST structure describes a request to delete a store manager store.
 */
typedef struct _SM_DELETE_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_DELETE_INFORMATION_VERSION
    ULONG Spare : 24;
    ULONG StoreId;
} SM_DELETE_REQUEST, *PSM_DELETE_REQUEST;

#define SYSTEM_STORE_LIST_INFORMATION_VERSION 2

/**
 * The SM_STORE_LIST_REQUEST structure describes a request to enumerate store manager stores.
 */
typedef struct _SM_STORE_LIST_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_LIST_INFORMATION_VERSION
    ULONG StoreCount : 8; // = 0
    ULONG ExtendedRequest : 1; // SM_STORE_LIST_REQUEST_EX if set
    ULONG Spare : 15;
    ULONG StoreId[32];
} SM_STORE_LIST_REQUEST, *PSM_STORE_LIST_REQUEST;

/**
 * The SM_STORE_LIST_REQUEST_EX structure describes an extended request to enumerate store manager stores.
 */
typedef struct _SM_STORE_LIST_REQUEST_EX
{
    SM_STORE_LIST_REQUEST Request;
    WCHAR NameBuffer[32][64];
} SM_STORE_LIST_REQUEST_EX, *PSM_STORE_LIST_REQUEST_EX;

#define SYSTEM_CACHE_LIST_INFORMATION_VERSION 2

/**
 * The SMC_CACHE_LIST_REQUEST structure describes a request to enumerate store manager caches.
 */
typedef struct _SMC_CACHE_LIST_REQUEST
{
    ULONG Version : 8; // SYSTEM_CACHE_LIST_INFORMATION_VERSION
    ULONG CacheCount : 8; // = 0
    ULONG Spare : 16;
    ULONG CacheId[16];
} SMC_CACHE_LIST_REQUEST, *PSMC_CACHE_LIST_REQUEST;

#define SYSTEM_CACHE_CREATE_INFORMATION_VERSION 3

/**
 * The SMC_CACHE_PARAMETERS structure specifies the parameters of a store manager cache.
 */
typedef struct _SMC_CACHE_PARAMETERS
{
    SIZE_T CacheFileSize;
    ULONG StoreAlignment;
    ULONG PerformsFileIo : 1; // SM_STORE_FLAG_PERFORMS_FILE_IO
    ULONG VdlNotSet : 1; // SM_STORE_FLAG_VDL_NOT_SET
    ULONG Spare : 30;
    ULONG CacheFlags;
    ULONG Priority;
} SMC_CACHE_PARAMETERS, *PSMC_CACHE_PARAMETERS;

/**
 * The SMC_CACHE_CREATE_PARAMETERS structure specifies the parameters used to create a store manager cache.
 */
typedef struct _SMC_CACHE_CREATE_PARAMETERS
{
    SMC_CACHE_PARAMETERS CacheParameters;
    WCHAR TemplateFilePath[512];
} SMC_CACHE_CREATE_PARAMETERS, *PSMC_CACHE_CREATE_PARAMETERS;

/**
 * The SMC_CACHE_CREATE_REQUEST structure describes a request to create a store manager cache.
 */
typedef struct _SMC_CACHE_CREATE_REQUEST
{
    ULONG Version : 8; // SYSTEM_CACHE_CREATE_INFORMATION_VERSION
    ULONG Spare : 24;
    ULONG CacheId;
    SMC_CACHE_CREATE_PARAMETERS CacheCreateParams;
} SMC_CACHE_CREATE_REQUEST, *PSMC_CACHE_CREATE_REQUEST;

#define SYSTEM_CACHE_DELETE_INFORMATION_VERSION 1

/**
 * The SMC_CACHE_DELETE_REQUEST structure describes a request to delete a store manager cache.
 */
typedef struct _SMC_CACHE_DELETE_REQUEST
{
    ULONG Version : 8; // SYSTEM_CACHE_DELETE_INFORMATION_VERSION
    ULONG Spare : 24;
    ULONG CacheId;
} SMC_CACHE_DELETE_REQUEST, *PSMC_CACHE_DELETE_REQUEST;

#define SYSTEM_CACHE_STORE_CREATE_INFORMATION_VERSION 2

/**
 * The SM_STORE_MANAGER_TYPE enumeration defines the store manager types.
 */
typedef enum _SM_STORE_MANAGER_TYPE
{
    SmStoreManagerTypePhysical = 0,
    SmStoreManagerTypeVirtual = 1,
    SmStoreManagerTypeMax = 2
} SM_STORE_MANAGER_TYPE;

/**
 * The SMC_STORE_CREATE_REQUEST structure describes a request to create a store within a store manager cache.
 */
typedef struct _SMC_STORE_CREATE_REQUEST
{
    ULONG Version : 8; // SYSTEM_CACHE_STORE_CREATE_INFORMATION_VERSION
    ULONG Spare : 24;
    SM_STORE_BASIC_PARAMS StoreParams;
    ULONG CacheId;
    SM_STORE_MANAGER_TYPE StoreManagerType;
    ULONG StoreId;
} SMC_STORE_CREATE_REQUEST, *PSMC_STORE_CREATE_REQUEST;

#define SYSTEM_CACHE_STORE_DELETE_INFORMATION_VERSION 1

/**
 * The SMC_STORE_DELETE_REQUEST structure describes a request to delete a store within a store manager cache.
 */
typedef struct _SMC_STORE_DELETE_REQUEST
{
    ULONG Version : 8; // SYSTEM_CACHE_STORE_DELETE_INFORMATION_VERSION
    ULONG Spare : 24;
    ULONG CacheId;
    SM_STORE_MANAGER_TYPE StoreManagerType;
    ULONG StoreId;
} SMC_STORE_DELETE_REQUEST, *PSMC_STORE_DELETE_REQUEST;

#define SYSTEM_CACHE_STATS_INFORMATION_VERSION 3

/**
 * The SMC_CACHE_STATS structure contains statistics for a store manager cache.
 */
typedef struct _SMC_CACHE_STATS
{
    SIZE_T TotalFileSize;
    ULONG StoreCount;
    ULONG RegionCount;
    ULONG RegionSizeBytes;
    ULONG FileCount : 6;
    ULONG PerformsFileIo : 1; // SM_STORE_FLAG_PERFORMS_FILE_IO
    ULONG Spare : 25;
    ULONG StoreIds[16];
    ULONG PhysicalStoreBitmap;
    ULONG Priority;
    WCHAR TemplateFilePath[512];
} SMC_CACHE_STATS, *PSMC_CACHE_STATS;

/**
 * The SMC_CACHE_STATS_REQUEST structure describes a request for store manager cache statistics.
 */
typedef struct _SMC_CACHE_STATS_REQUEST
{
    ULONG Version : 8; // SYSTEM_CACHE_STATS_INFORMATION_VERSION
    ULONG NoFilePath : 1;
    ULONG Spare : 23;
    ULONG CacheId;
    SMC_CACHE_STATS CacheStats;
} SMC_CACHE_STATS_REQUEST, *PSMC_CACHE_STATS_REQUEST;

#define SYSTEM_STORE_REGISTRATION_INFORMATION_VERSION 2

/**
 * The SM_REGISTRATION_INFO structure contains store manager registration information.
 */
typedef struct _SM_REGISTRATION_INFO
{
    HANDLE CachesUpdatedEvent;
} SM_REGISTRATION_INFO, *PSM_REGISTRATION_INFO;

/**
 * The SM_REGISTRATION_REQUEST structure describes a store manager registration request.
 */
typedef struct _SM_REGISTRATION_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_REGISTRATION_INFORMATION_VERSION
    ULONG Spare : 24;
    SM_REGISTRATION_INFO RegInfo;
} SM_REGISTRATION_REQUEST, *PSM_REGISTRATION_REQUEST;

#define SYSTEM_STORE_RESIZE_INFORMATION_VERSION 6

/**
 * The SM_STORE_RESIZE_REQUEST structure describes a request to resize a store manager store.
 */
typedef struct _SM_STORE_RESIZE_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_RESIZE_INFORMATION_VERSION
    ULONG AddRegions : 1; // Clear to remove regions, set to add regions. Current handler rejects user-mode callers.
    ULONG Spare : 23;
    ULONG StoreId;
    ULONG NumberOfRegions;
    PRTL_BITMAP RegionBitmap; // Kernel-mode only bitmap pointer consumed by SmProcessResizeRequest.
} SM_STORE_RESIZE_REQUEST, *PSM_STORE_RESIZE_REQUEST;

#define SYSTEM_CACHE_STORE_RESIZE_INFORMATION_VERSION 1

/**
 * The SM_STORE_CACHE_RESIZE_REQUEST structure describes a request to resize a store manager cache.
 */
typedef struct _SM_STORE_CACHE_RESIZE_REQUEST
{
    ULONG Version : 8; // SYSTEM_CACHE_STORE_RESIZE_INFORMATION_VERSION
    ULONG AddRegions : 1;
    ULONG Spare : 23;
    ULONG CacheId;
    ULONG StoreId;
    SM_STORE_MANAGER_TYPE StoreManagerType;
    ULONG RegionCount;
} SM_STORE_CACHE_RESIZE_REQUEST, *PSM_STORE_CACHE_RESIZE_REQUEST;

#define SYSTEM_STORE_CONFIG_INFORMATION_VERSION 4

/**
 * The SM_CONFIG_TYPE enumeration defines the store manager configuration types.
 */
typedef enum _SM_CONFIG_TYPE
{
    SmConfigDirtyPageCompression = 0,
    SmConfigAsyncInswap = 1,
    SmConfigPrefetchSeekThreshold = 2,
    SmConfigTypeMax = 3
} SM_CONFIG_TYPE;

/**
 * The SM_CONFIG_REQUEST structure describes a store manager configuration request.
 */
typedef struct _SM_CONFIG_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_CONFIG_INFORMATION_VERSION
    ULONG Spare : 16;
    ULONG ConfigType : 8; // SM_CONFIG_TYPE
    ULONG ConfigValue;
} SM_CONFIG_REQUEST, *PSM_CONFIG_REQUEST;

#define SYSTEM_STORE_HIGH_MEM_PRIORITY_INFORMATION_VERSION 1

// rev
typedef struct _SM_STORE_HIGH_MEMORY_PRIORITY_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_HIGH_MEMORY_PRIORITY_INFORMATION_VERSION
    ULONG SetHighMemoryPriority : 1;
    ULONG Spare : 23;
    HANDLE ProcessHandle;
} SM_STORE_HIGH_MEMORY_PRIORITY_REQUEST, *PSM_STORE_HIGH_MEMORY_PRIORITY_REQUEST;

// rev
/**
 * The SM_SYSTEM_STORE_TRIM_REQUEST structure describes a request to trim the system store.
 */
typedef struct _SM_SYSTEM_STORE_TRIM_REQUEST
{
    ULONG Version : 8;  // SYSTEM_STORE_TRIM_INFORMATION_VERSION_V1 or _V2
    ULONG Spare : 24;
    SIZE_T PagesToTrim; // Must be non-zero.
    HANDLE PartitionHandle; // Optional in V2 (24H2+); absent in V1.
} SM_SYSTEM_STORE_TRIM_REQUEST, *PSM_SYSTEM_STORE_TRIM_REQUEST;

// rev
#define SYSTEM_STORE_TRIM_INFORMATION_VERSION_V1 1 // WIN10
#define SYSTEM_STORE_TRIM_INFORMATION_VERSION_V2 2 // 24H2
#define SYSTEM_STORE_TRIM_INFORMATION_VERSION SYSTEM_STORE_TRIM_INFORMATION_VERSION_V2

// rev
#define SYSTEM_STORE_TRIM_INFORMATION_SIZE_V1 RTL_SIZEOF_THROUGH_FIELD(SM_SYSTEM_STORE_TRIM_REQUEST, PagesToTrim) // Version 1 input size
#define SYSTEM_STORE_TRIM_INFORMATION_SIZE_V2 RTL_SIZEOF_THROUGH_FIELD(SM_SYSTEM_STORE_TRIM_REQUEST, PartitionHandle) // Version 2 input size (24H2+)
#define SYSTEM_STORE_TRIM_INFORMATION_SIZE SYSTEM_STORE_TRIM_INFORMATION_SIZE_V2

#ifdef _WIN64
_STATIC_ASSERT(SYSTEM_STORE_TRIM_INFORMATION_SIZE_V1 == 16);
_STATIC_ASSERT(SYSTEM_STORE_TRIM_INFORMATION_SIZE_V2 == 24);
#else
_STATIC_ASSERT(SYSTEM_STORE_TRIM_INFORMATION_SIZE_V1 == 8);
_STATIC_ASSERT(SYSTEM_STORE_TRIM_INFORMATION_SIZE_V2 == 12);
#endif

// rev
/**
 * The SM_STORE_COMPRESSION_INFORMATION_REQUEST structure describes a request for store compression information.
 */
typedef struct _SM_STORE_COMPRESSION_INFORMATION_REQUEST
{
    ULONG Version : 8; // SYSTEM_STORE_COMPRESSION_INFORMATION_VERSION_V1 or _V2
    ULONG Spare : 24;
    ULONG CompressionPid;
    ULONG WorkingSetSize;
    SIZE_T TotalDataCompressed;
    SIZE_T TotalCompressedSize;
    SIZE_T TotalUniqueDataCompressed;
    HANDLE PartitionHandle; // Optional in V2 (24H2+); absent in V1.
} SM_STORE_COMPRESSION_INFORMATION_REQUEST, *PSM_STORE_COMPRESSION_INFORMATION_REQUEST;

// rev
#define SYSTEM_STORE_COMPRESSION_INFORMATION_VERSION_V1 3 // WIN10
#define SYSTEM_STORE_COMPRESSION_INFORMATION_VERSION_V2 4 // 24H2
#define SYSTEM_STORE_COMPRESSION_INFORMATION_VERSION SYSTEM_STORE_COMPRESSION_INFORMATION_VERSION_V2

// rev
#define SYSTEM_STORE_COMPRESSION_INFORMATION_SIZE_V1 RTL_SIZEOF_THROUGH_FIELD(SM_STORE_COMPRESSION_INFORMATION_REQUEST, TotalUniqueDataCompressed) // Version 3 input/output size
#define SYSTEM_STORE_COMPRESSION_INFORMATION_SIZE_V2 RTL_SIZEOF_THROUGH_FIELD(SM_STORE_COMPRESSION_INFORMATION_REQUEST, PartitionHandle) // Version 4 input/output size (24H2+)
#define SYSTEM_STORE_COMPRESSION_INFORMATION_SIZE SYSTEM_STORE_COMPRESSION_INFORMATION_SIZE_V2

#ifdef _WIN64
_STATIC_ASSERT(SYSTEM_STORE_COMPRESSION_INFORMATION_SIZE_V1 == 40);
_STATIC_ASSERT(SYSTEM_STORE_COMPRESSION_INFORMATION_SIZE_V2 == 48);
#else
_STATIC_ASSERT(SYSTEM_STORE_COMPRESSION_INFORMATION_SIZE_V1 == 24);
_STATIC_ASSERT(SYSTEM_STORE_COMPRESSION_INFORMATION_SIZE_V2 == 28);
#endif

// private
/**
 * The SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS structure specifies the parameters for system registry append string.
 */
typedef struct _SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS
{
    HANDLE KeyHandle;
    PUNICODE_STRING ValueNamePointer;
    PULONG RequiredLengthPointer;
    PUCHAR Buffer;
    ULONG BufferLength;
    ULONG Type;
    PUCHAR AppendBuffer;
    ULONG AppendBufferLength;
    BOOLEAN CreateIfDoesntExist;
    BOOLEAN TruncateExistingValue;
} SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS, *PSYSTEM_REGISTRY_APPEND_STRING_PARAMETERS;

// msdn
/**
 * The SYSTEM_VHD_BOOT_INFORMATION structure contains system VHD boot information.
 */
typedef struct _SYSTEM_VHD_BOOT_INFORMATION
{
    BOOLEAN OsDiskIsVhd;
    ULONG OsVhdFilePathOffset;
    WCHAR OsVhdParentVolume[1];
} SYSTEM_VHD_BOOT_INFORMATION, *PSYSTEM_VHD_BOOT_INFORMATION;

// private
/**
 * The PS_CPU_QUOTA_QUERY_ENTRY structure describes a single PS CPU quota query entry.
 */
typedef struct _PS_CPU_QUOTA_QUERY_ENTRY
{
    ULONG SessionId;
    ULONG Weight;
} PS_CPU_QUOTA_QUERY_ENTRY, *PPS_CPU_QUOTA_QUERY_ENTRY;

// private
/**
 * The PS_CPU_QUOTA_QUERY_INFORMATION structure contains PS CPU quota query information.
 */
typedef struct _PS_CPU_QUOTA_QUERY_INFORMATION
{
    ULONG SessionCount;
    PS_CPU_QUOTA_QUERY_ENTRY SessionInformation[1];
} PS_CPU_QUOTA_QUERY_INFORMATION, *PPS_CPU_QUOTA_QUERY_INFORMATION;

// private
/**
 * The SYSTEM_ERROR_PORT_TIMEOUTS structure contains the system error port timeout values.
 */
typedef struct _SYSTEM_ERROR_PORT_TIMEOUTS
{
    ULONG StartTimeout;
    ULONG CommTimeout;
} SYSTEM_ERROR_PORT_TIMEOUTS, *PSYSTEM_ERROR_PORT_TIMEOUTS;

// private
/**
 * The SYSTEM_LOW_PRIORITY_IO_INFORMATION structure contains system low priority IO information.
 */
typedef struct _SYSTEM_LOW_PRIORITY_IO_INFORMATION
{
    ULONG LowPriReadOperations;
    ULONG LowPriWriteOperations;
    ULONG KernelBumpedToNormalOperations;
    ULONG LowPriPagingReadOperations;
    ULONG KernelPagingReadsBumpedToNormal;
    ULONG LowPriPagingWriteOperations;
    ULONG KernelPagingWritesBumpedToNormal;
    ULONG BoostedIrpCount;
    ULONG BoostedPagingIrpCount;
    ULONG BlanketBoostCount;
} SYSTEM_LOW_PRIORITY_IO_INFORMATION, *PSYSTEM_LOW_PRIORITY_IO_INFORMATION;

// symbols
/**
 * The BOOT_ENTROPY_SOURCE_RESULT_CODE enumeration defines the boot entropy source result code values.
 */
typedef enum _BOOT_ENTROPY_SOURCE_RESULT_CODE
{
    BootEntropySourceStructureUninitialized,
    BootEntropySourceDisabledByPolicy,
    BootEntropySourceNotPresent,
    BootEntropySourceError,
    BootEntropySourceSuccess
} BOOT_ENTROPY_SOURCE_RESULT_CODE;

/**
 * The BOOT_ENTROPY_SOURCE_ID enumeration identifies a boot entropy source.
 */
typedef enum _BOOT_ENTROPY_SOURCE_ID
{
    BootEntropySourceNone = 0,
    BootEntropySourceSeedfile = 1,
    BootEntropySourceExternal = 2,
    BootEntropySourceTpm = 3,
    BootEntropySourceRdrand = 4,
    BootEntropySourceTime = 5,
    BootEntropySourceAcpiOem0 = 6,
    BootEntropySourceUefi = 7,
    BootEntropySourceCng = 8,
    BootEntropySourceTcbTpm = 9,
    BootEntropySourceTcbRdrand = 10,
    BootMaxEntropySources = 10
} BOOT_ENTROPY_SOURCE_ID, *PBOOT_ENTROPY_SOURCE_ID;

// Contents of KeLoaderBlock->Extension->TpmBootEntropyResult (TPM_BOOT_ENTROPY_LDR_RESULT).
// EntropyData is truncated to 40 bytes.

// private
/**
 * The TPM_BOOT_ENTROPY_NT_RESULT structure contains the TPM boot entropy nt result.
 */
typedef struct _TPM_BOOT_ENTROPY_NT_RESULT
{
    ULONGLONG Policy;
    BOOT_ENTROPY_SOURCE_RESULT_CODE ResultCode;
    NTSTATUS ResultStatus;
    ULONGLONG Time;
    ULONG EntropyLength;
    UCHAR EntropyData[40];
} TPM_BOOT_ENTROPY_NT_RESULT, *PTPM_BOOT_ENTROPY_NT_RESULT;

// private
/**
 * The BOOT_ENTROPY_SOURCE_NT_RESULT structure contains the boot entropy source nt result.
 */
typedef struct _BOOT_ENTROPY_SOURCE_NT_RESULT
{
    BOOT_ENTROPY_SOURCE_ID SourceId;
    ULONG64 Policy;
    BOOT_ENTROPY_SOURCE_RESULT_CODE ResultCode;
    NTSTATUS ResultStatus;
    ULONGLONG Time;
    ULONG EntropyLength;
    UCHAR EntropyData[64];
} BOOT_ENTROPY_SOURCE_NT_RESULT, *PBOOT_ENTROPY_SOURCE_NT_RESULT;

// private
/**
 * The BOOT_ENTROPY_NT_RESULT structure contains the boot entropy nt result.
 */
typedef struct _BOOT_ENTROPY_NT_RESULT
{
    ULONG MaxEntropySources;
    BOOT_ENTROPY_SOURCE_NT_RESULT EntropySourceResult[10];
    UCHAR SeedBytesForCng[48];
} BOOT_ENTROPY_NT_RESULT, *PBOOT_ENTROPY_NT_RESULT;

// private
/**
 * The SYSTEM_VERIFIER_COUNTERS_INFORMATION structure contains system verifier counters information.
 */
typedef struct _SYSTEM_VERIFIER_COUNTERS_INFORMATION
{
    SYSTEM_VERIFIER_INFORMATION Legacy;
    ULONG RaiseIrqls;
    ULONG AcquireSpinLocks;
    ULONG SynchronizeExecutions;
    ULONG AllocationsWithNoTag;
    ULONG AllocationsFailed;
    ULONG AllocationsFailedDeliberately;
    SIZE_T LockedBytes;
    SIZE_T PeakLockedBytes;
    SIZE_T MappedLockedBytes;
    SIZE_T PeakMappedLockedBytes;
    SIZE_T MappedIoSpaceBytes;
    SIZE_T PeakMappedIoSpaceBytes;
    SIZE_T PagesForMdlBytes;
    SIZE_T PeakPagesForMdlBytes;
    SIZE_T ContiguousMemoryBytes;
    SIZE_T PeakContiguousMemoryBytes;
    ULONG ExecutePoolTypes; // REDSTONE2
    ULONG ExecutePageProtections;
    ULONG ExecutePageMappings;
    ULONG ExecuteWriteSections;
    ULONG SectionAlignmentFailures;
    ULONG UnsupportedRelocs;
    ULONG IATInExecutableSection;
} SYSTEM_VERIFIER_COUNTERS_INFORMATION, *PSYSTEM_VERIFIER_COUNTERS_INFORMATION;

// private
/**
 * The SYSTEM_ACPI_AUDIT_INFORMATION structure contains system ACPI audit information.
 */
typedef struct _SYSTEM_ACPI_AUDIT_INFORMATION
{
    ULONG RsdpCount;
    ULONG SameRsdt : 1;
    ULONG SlicPresent : 1;
    ULONG SlicDifferent : 1;
} SYSTEM_ACPI_AUDIT_INFORMATION, *PSYSTEM_ACPI_AUDIT_INFORMATION;

// private
/**
 * The SYSTEM_BASIC_PERFORMANCE_INFORMATION structure contains system basic performance information.
 */
typedef struct _SYSTEM_BASIC_PERFORMANCE_INFORMATION
{
    SIZE_T AvailablePages;
    SIZE_T CommittedPages;
    SIZE_T CommitLimit;
    SIZE_T PeakCommitment;
} SYSTEM_BASIC_PERFORMANCE_INFORMATION, *PSYSTEM_BASIC_PERFORMANCE_INFORMATION;

// begin_msdn

/**
 * The QUERY_PERFORMANCE_COUNTER_FLAGS structure defines the query performance counter flags.
 */
typedef struct _QUERY_PERFORMANCE_COUNTER_FLAGS
{
    union
    {
        struct
        {
            ULONG KernelTransition : 1;
            ULONG Reserved : 31;
        } DUMMYSTRUCTNAME;
        ULONG ul;
    } DUMMYUNIONNAME;
} QUERY_PERFORMANCE_COUNTER_FLAGS;

/**
 * The SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION structure contains system query performance counter information.
 */
typedef struct _SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION
{
    ULONG Version;
    QUERY_PERFORMANCE_COUNTER_FLAGS Flags;
    QUERY_PERFORMANCE_COUNTER_FLAGS ValidFlags;
} SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION, *PSYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION;

// end_msdn

// private
/**
 * The SYSTEM_PIXEL_FORMAT enumeration defines the system pixel format values.
 */
typedef enum _SYSTEM_PIXEL_FORMAT
{
    SystemPixelFormatUnknown,
    SystemPixelFormatR8G8B8,
    SystemPixelFormatR8G8B8X8,
    SystemPixelFormatB8G8R8,
    SystemPixelFormatB8G8R8X8
} SYSTEM_PIXEL_FORMAT;

// private
/**
 * The SYSTEM_BOOT_GRAPHICS_INFORMATION structure contains system boot graphics information.
 */
typedef struct _SYSTEM_BOOT_GRAPHICS_INFORMATION
{
    LARGE_INTEGER FrameBuffer;
    ULONG Width;
    ULONG Height;
    ULONG PixelStride;
    ULONG Flags;
    SYSTEM_PIXEL_FORMAT Format;
    ULONG DisplayRotation;
} SYSTEM_BOOT_GRAPHICS_INFORMATION, *PSYSTEM_BOOT_GRAPHICS_INFORMATION;

// private
/**
 * The MEMORY_SCRUB_INFORMATION structure contains memory scrub information.
 */
typedef struct _MEMORY_SCRUB_INFORMATION
{
    HANDLE Handle;
    SIZE_T PagesScrubbed;
} MEMORY_SCRUB_INFORMATION, *PMEMORY_SCRUB_INFORMATION;

// private
/**
 * The SYSTEM_BAD_PAGE_INFORMATION union contains system bad page information.
 */
typedef union _SYSTEM_BAD_PAGE_INFORMATION
{
#ifdef _WIN64
    ULONG_PTR PhysicalPageNumber : 52;
#else
    ULONG PhysicalPageNumber : 20;
#endif
    ULONG_PTR Reserved : 10;
    ULONG_PTR Pending : 1;
    ULONG_PTR Poisoned : 1;
} SYSTEM_BAD_PAGE_INFORMATION, *PSYSTEM_BAD_PAGE_INFORMATION;

// private
/**
 * The PEBS_DS_SAVE_AREA32 structure describes the PEBS ds save area32.
 */
typedef struct _PEBS_DS_SAVE_AREA32
{
    ULONG BtsBufferBase;
    ULONG BtsIndex;
    ULONG BtsAbsoluteMaximum;
    ULONG BtsInterruptThreshold;
    ULONG PebsBufferBase;
    ULONG PebsIndex;
    ULONG PebsAbsoluteMaximum;
    ULONG PebsInterruptThreshold;
    ULONG PebsGpCounterReset[8];
    ULONG PebsFixedCounterReset[4];
} PEBS_DS_SAVE_AREA32, *PPEBS_DS_SAVE_AREA32;

// private
/**
 * The PEBS_DS_SAVE_AREA64 structure describes the PEBS ds save area64.
 */
typedef struct _PEBS_DS_SAVE_AREA64
{
    ULONGLONG BtsBufferBase;
    ULONGLONG BtsIndex;
    ULONGLONG BtsAbsoluteMaximum;
    ULONGLONG BtsInterruptThreshold;
    ULONGLONG PebsBufferBase;
    ULONGLONG PebsIndex;
    ULONGLONG PebsAbsoluteMaximum;
    ULONGLONG PebsInterruptThreshold;
    ULONGLONG PebsGpCounterReset[8];
    ULONGLONG PebsFixedCounterReset[4];
} PEBS_DS_SAVE_AREA64, *PPEBS_DS_SAVE_AREA64;

// private
/**
 * The PEBS_DS_SAVE_AREA union describes the PEBS ds save area.
 */
typedef union _PEBS_DS_SAVE_AREA
{
    PEBS_DS_SAVE_AREA32 As32Bit;
    PEBS_DS_SAVE_AREA64 As64Bit;
} PEBS_DS_SAVE_AREA, *PPEBS_DS_SAVE_AREA;

// private
/**
 * The PROCESSOR_PROFILE_CONTROL_AREA structure describes the processor profile control area.
 */
typedef struct _PROCESSOR_PROFILE_CONTROL_AREA
{
    PEBS_DS_SAVE_AREA PebsDsSaveArea;
} PROCESSOR_PROFILE_CONTROL_AREA, *PPROCESSOR_PROFILE_CONTROL_AREA;

// private
/**
 * The SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA structure describes the system processor profile control area.
 */
typedef struct _SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
{
    PROCESSOR_PROFILE_CONTROL_AREA ProcessorProfileControlArea;
    BOOLEAN Allocate;
} SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA, *PSYSTEM_PROCESSOR_PROFILE_CONTROL_AREA;

// private
/**
 * The MEMORY_COMBINE_INFORMATION structure contains memory combine information.
 */
typedef struct _MEMORY_COMBINE_INFORMATION
{
    HANDLE EventHandle; // Optional event handle.
    SIZE_T PagesCombined;
} MEMORY_COMBINE_INFORMATION, *PMEMORY_COMBINE_INFORMATION;

// rev
#define MEMORY_COMBINE_FLAGS_COMMON_PAGES_ONLY 0x1 // MiCombineIdenticalPages only accepts bits 0 and 1; this bit selects the legacy/common-page path.
#define MEMORY_COMBINE_FLAGS_COMBINE_WORKING_SET 0x2 // Enables the working-set combine path; required when ProcessHandle is specified.

// private
/**
 * The MEMORY_COMBINE_INFORMATION_EX structure contains memory combine information.
 */
typedef struct _MEMORY_COMBINE_INFORMATION_EX
{
    HANDLE EventHandle; // Optional event handle.
    SIZE_T PagesCombined;
    ULONG Flags; // MEMORY_COMBINE_FLAGS_*
} MEMORY_COMBINE_INFORMATION_EX, *PMEMORY_COMBINE_INFORMATION_EX;

// private
/**
 * The MEMORY_COMBINE_INFORMATION_EX2 structure contains memory combine information.
 */
typedef struct _MEMORY_COMBINE_INFORMATION_EX2
{
    HANDLE EventHandle; // Optional event handle.
    SIZE_T PagesCombined;
    ULONG Flags; // MEMORY_COMBINE_FLAGS_*
    HANDLE ProcessHandle; // Requires MEMORY_COMBINE_FLAGS_COMBINE_WORKING_SET.
} MEMORY_COMBINE_INFORMATION_EX2, *PMEMORY_COMBINE_INFORMATION_EX2;

// private
/**
 * The SYSTEM_ENTROPY_TIMING_INFORMATION structure contains system entropy timing information.
 */
typedef struct _SYSTEM_ENTROPY_TIMING_INFORMATION
{
    VOID(NTAPI *EntropyRoutine)(PVOID, ULONG);
    VOID(NTAPI *InitializationRoutine)(PVOID, ULONG, PVOID);
    PVOID InitializationContext;
} SYSTEM_ENTROPY_TIMING_INFORMATION, *PSYSTEM_ENTROPY_TIMING_INFORMATION;

// private
/**
 * The SYSTEM_CONSOLE_INFORMATION structure contains system console information.
 */
typedef struct _SYSTEM_CONSOLE_INFORMATION
{
    ULONG DriverLoaded : 1;
    ULONG Spare : 31;
} SYSTEM_CONSOLE_INFORMATION, *PSYSTEM_CONSOLE_INFORMATION;

// private
/**
 * The SYSTEM_PLATFORM_BINARY_INFORMATION structure contains system platform binary information.
 */
typedef struct _SYSTEM_PLATFORM_BINARY_INFORMATION
{
    ULONG64 PhysicalAddress;
    PVOID HandoffBuffer;
    PVOID CommandLineBuffer;
    ULONG HandoffBufferSize;
    ULONG CommandLineBufferSize;
} SYSTEM_PLATFORM_BINARY_INFORMATION, *PSYSTEM_PLATFORM_BINARY_INFORMATION;

// private
typedef struct _SYSTEM_POLICY_INFORMATION
{
    PVOID InputData;
    PVOID OutputData;
    ULONG InputDataSize;
    ULONG OutputDataSize;
    ULONG Version;
} SYSTEM_POLICY_INFORMATION, *PSYSTEM_POLICY_INFORMATION;

// private
/**
 * The SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION structure contains system hypervisor processor count information.
 */
typedef struct _SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
{
    ULONG NumberOfLogicalProcessors;
    ULONG NumberOfCores;
} SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION, *PSYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION;

// private
/**
 * The SYSTEM_DEVICE_DATA_INFORMATION structure contains system device data information.
 */
typedef struct _SYSTEM_DEVICE_DATA_INFORMATION
{
    UNICODE_STRING DeviceId;
    UNICODE_STRING DataName;
    ULONG DataType;
    ULONG DataBufferLength;
    PVOID DataBuffer;
} SYSTEM_DEVICE_DATA_INFORMATION, *PSYSTEM_DEVICE_DATA_INFORMATION;

// private
/**
 * The PHYSICAL_CHANNEL_RUN structure describes the physical channel run.
 */
typedef struct _PHYSICAL_CHANNEL_RUN
{
    ULONG NodeNumber;
    ULONG ChannelNumber;
    ULONGLONG BasePage;
    ULONGLONG PageCount;
    ULONG Flags;
} PHYSICAL_CHANNEL_RUN, *PPHYSICAL_CHANNEL_RUN;

// private
/**
 * The SYSTEM_MEMORY_TOPOLOGY_INFORMATION structure contains system memory topology information.
 */
typedef struct _SYSTEM_MEMORY_TOPOLOGY_INFORMATION
{
    ULONGLONG NumberOfRuns;
    ULONG NumberOfNodes;
    ULONG NumberOfChannels;
    PHYSICAL_CHANNEL_RUN Run[1];
} SYSTEM_MEMORY_TOPOLOGY_INFORMATION, *PSYSTEM_MEMORY_TOPOLOGY_INFORMATION;

// private
/**
 * The SYSTEM_MEMORY_CHANNEL_INFORMATION structure contains system memory channel information.
 */
typedef struct _SYSTEM_MEMORY_CHANNEL_INFORMATION
{
    ULONG ChannelNumber;
    ULONG ChannelHeatIndex;
    ULONGLONG TotalPageCount;
    ULONGLONG ZeroPageCount;
    ULONGLONG FreePageCount;
    ULONGLONG StandbyPageCount;
} SYSTEM_MEMORY_CHANNEL_INFORMATION, *PSYSTEM_MEMORY_CHANNEL_INFORMATION;

// private
#define SYSTEM_BOOT_LOGO_FLAG_INTERNAL_0x800000 0x1 // Set when BgpFwQueryBootGraphicsInformation sees boot graphics state flag 0x800000.

// private
/**
 * The SYSTEM_BOOT_LOGO_INFORMATION structure contains system boot logo information.
 */
typedef struct _SYSTEM_BOOT_LOGO_INFORMATION
{
    ULONG Flags; // SYSTEM_BOOT_LOGO_FLAG_*
    ULONG BitmapOffset; // Offset to the trailing boot logo bitmap data; currently 8 in the query path.
} SYSTEM_BOOT_LOGO_INFORMATION, *PSYSTEM_BOOT_LOGO_INFORMATION;

// private
/**
 * The SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX structure contains system processor performance information.
 */
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
    ULONG Spare0;
    //
    // The amount of time that the processor has spent executing low priority (background) threads,
    // in 100-nanosecond intervals. This is the remainder of the "% Priority Time" raw counter
    // (counter set {b4fc721a-0378-476f-89ba-a5a79f810b36}, counter 15), whose raw value is exactly
    // IdleTime + AvailableTime. That counter is a PERF_100NSEC_TIMER_INV, so:
    //
    //     PercentPriorityTime = 100 * (1 - d(IdleTime + AvailableTime) / dElapsed100ns)
    //
    // giving the percentage of elapsed time spent executing threads that are not low priority.
    //
    LARGE_INTEGER AvailableTime;
    LARGE_INTEGER Spare1;
    LARGE_INTEGER Spare2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX;

// private
/**
 * The SYSTEM_CRITICAL_PROCESS_EXCEPTION_INFORMATION structure contains system critical process exception information.
 */
typedef struct _SYSTEM_CRITICAL_PROCESS_EXCEPTION_INFORMATION // CRITICAL_PROCESS_EXCEPTION_DATA
{
    GUID ReportId;
    UNICODE_STRING ModuleName;
    ULONG ModuleTimestamp;
    ULONG ModuleSize;
    ULONG_PTR Offset;
} SYSTEM_CRITICAL_PROCESS_EXCEPTION_INFORMATION, *PSYSTEM_CRITICAL_PROCESS_EXCEPTION_INFORMATION;

// private
/**
 * The SYSTEM_SECUREBOOT_POLICY_INFORMATION structure contains system secureboot policy information.
 */
typedef struct _SYSTEM_SECUREBOOT_POLICY_INFORMATION
{
    GUID PolicyPublisher;
    ULONG PolicyVersion;
    ULONG PolicyOptions;
} SYSTEM_SECUREBOOT_POLICY_INFORMATION, *PSYSTEM_SECUREBOOT_POLICY_INFORMATION;

// private
_Struct_size_bytes_(NextEntryOffset)
/**
 * The SYSTEM_PAGEFILE_INFORMATION_EX structure contains system pagefile information.
 */
typedef struct _SYSTEM_PAGEFILE_INFORMATION_EX
{
    union // union declaration for convenience (dmex)
    {
        SYSTEM_PAGEFILE_INFORMATION Info;
        struct
        {
            ULONG NextEntryOffset;
            ULONG TotalSize;
            ULONG TotalInUse;
            ULONG PeakUsage;
            UNICODE_STRING PageFileName;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    ULONG MinimumSize;
    ULONG MaximumSize;
} SYSTEM_PAGEFILE_INFORMATION_EX, *PSYSTEM_PAGEFILE_INFORMATION_EX;

// private
/**
 * The SYSTEM_SECUREBOOT_INFORMATION structure indicates whether Secure Boot is enabled and capable.
 */
typedef struct _SYSTEM_SECUREBOOT_INFORMATION
{
    BOOLEAN SecureBootEnabled;
    BOOLEAN SecureBootCapable;
} SYSTEM_SECUREBOOT_INFORMATION, *PSYSTEM_SECUREBOOT_INFORMATION;

// private
/**
 * The PROCESS_DISK_COUNTERS structure contains the process disk counters.
 */
typedef struct _PROCESS_DISK_COUNTERS
{
    ULONGLONG BytesRead;
    ULONGLONG BytesWritten;
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG FlushOperationCount;
} PROCESS_DISK_COUNTERS, *PPROCESS_DISK_COUNTERS;

// private
/**
 * The ENERGY_STATE_DURATION union describes the energy state duration.
 */
typedef union _ENERGY_STATE_DURATION
{
    ULONGLONG Value;
    struct
    {
        ULONG LastChangeTime;
        ULONG Duration : 31;
        ULONG IsInState : 1;
    } DUMMYSTRUCTNAME;
} ENERGY_STATE_DURATION, *PENERGY_STATE_DURATION;

/**
 * The PROCESS_ENERGY_VALUES_QOS_INDEX type represents the QoS (Quality of Service) /
 * thread-context bucket used as the first index of the Cycles, AttributedCycles, and
 * WorkOnBehalfCycles arrays in PROCESS_ENERGY_VALUES.
 */
typedef enum _PROCESS_ENERGY_VALUES_QOS_INDEX
{
    // Foreground / High QoS — threads running at foreground or high quality-of-service priority.
    ProcessEnergyValuesQoSHighForeground = 0,
    // Above-normal — threads running at above-normal priority.
    ProcessEnergyValuesQoSAboveNormal = 1,
    // Normal — threads running at normal priority.
    ProcessEnergyValuesQoSNormal = 2,
    // Background / Low QoS — threads running at background or low quality-of-service priority.
    ProcessEnergyValuesQoSLowBackground = 3,
    // The maximum number of QoS buckets.
    ProcessEnergyValuesQoSMax = 4
} PROCESS_ENERGY_VALUES_QOS_INDEX, *PPROCESS_ENERGY_VALUES_QOS_INDEX;

/**
 * The PROCESS_ENERGY_VALUES_CYCLE_TYPE_INDEX type represents the cycle type (user vs. kernel)
 * used as the second index of the Cycles, AttributedCycles, and WorkOnBehalfCycles.
 */
typedef enum _PROCESS_ENERGY_VALUES_CYCLE_TYPE_INDEX
{
    // User-mode cycles accumulated by threads in this QoS bucket.
    ProcessEnergyValuesCycleTypeUser = 0,
    // Kernel-mode cycles accumulated by threads in this QoS bucket.
    ProcessEnergyValuesCycleTypeKernel = 1,
    // The maximum number of cycle types.
    ProcessEnergyValuesCycleTypeMax = 2
} PROCESS_ENERGY_VALUES_CYCLE_TYPE_INDEX, *PPROCESS_ENERGY_VALUES_CYCLE_TYPE_INDEX;

/**
 * \brief Energy accounting values for a process, broken down by QoS bucket and cycle type.
 *
 * \details Contains CPU cycle counts, energy estimates, network/MBB byte counts,
 * activity durations, and DWM composition statistics accumulated for a process.
 * CPU cycles are indexed by QoS bucket (see PROCESS_ENERGY_VALUES_QOS_INDEX) and
 * cycle type (see PROCESS_ENERGY_VALUES_CYCLE_TYPE_INDEX).
 */
typedef struct _PROCESS_ENERGY_VALUES
{
    /**
     * CPU cycles accumulated per QoS bucket and cycle type.
     * First index: QoS bucket (PROCESS_ENERGY_VALUES_QOS_INDEX).
     * Second index: cycle type — user [0] or kernel [1] (PROCESS_ENERGY_VALUES_CYCLE_TYPE_INDEX).
     */
    ULONGLONG Cycles[ProcessEnergyValuesQoSMax][ProcessEnergyValuesCycleTypeMax];
    /**
     * Energy consumed by disk I/O, in arbitrary energy units.
     */
    ULONGLONG DiskEnergy;
    /**
     * Tail energy attributed to network activity.
     */
    ULONGLONG NetworkTailEnergy;
    /**
     * Tail energy attributed to Mobile Broadband (MBB) activity.
     */
    ULONGLONG MBBTailEnergy;
    /**
     * Total bytes transmitted and received over network interfaces.
     */
    ULONGLONG NetworkTxRxBytes;
    /**
     * Total bytes transmitted and received over Mobile Broadband (MBB) interfaces.
     */
    ULONGLONG MBBTxRxBytes;
    union
    {
        /**
         * Activity state durations: [0] foreground, [1] desktop visible, [2] PSM foreground.
         */
        ENERGY_STATE_DURATION Durations[3];
        struct
        {
            /**
             * Duration the process was in the foreground.
             */
            ENERGY_STATE_DURATION ForegroundDuration;
            /**
             * Duration the process was visible on the desktop.
             */
            ENERGY_STATE_DURATION DesktopVisibleDuration;
            /**
             * Duration the process was in the PSM (Process State Manager) foreground state.
             */
            ENERGY_STATE_DURATION PSMForegroundDuration;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    /**
     * Number of frames rendered by the DWM compositor on behalf of this process.
     */
    ULONG CompositionRendered;
    /**
     * Number of dirty regions generated by this process during DWM composition.
     */
    ULONG CompositionDirtyGenerated;
    /**
     *  Number of dirty regions propagated from this process to other windows during DWM composition.
     */
    ULONG CompositionDirtyPropagated;
    ULONG Reserved1;
    /**
     * CPU cycles attributed to this process (e.g. from work performed on its behalf).
     * Indexed identically to Cycles: [QoS bucket][cycle type].
     */
    ULONGLONG AttributedCycles[ProcessEnergyValuesQoSMax][ProcessEnergyValuesCycleTypeMax];
    /**
     * CPU cycles consumed while performing work on behalf of another process.
     * Indexed identically to Cycles: [QoS bucket][cycle type].
     */
    ULONGLONG WorkOnBehalfCycles[ProcessEnergyValuesQoSMax][ProcessEnergyValuesCycleTypeMax];
} PROCESS_ENERGY_VALUES, *PPROCESS_ENERGY_VALUES;

/**
 * \brief A compact activity timeline encoded as a bitmap with an end-time anchor.
 *
 * \details Each bit in the Bitmap field represents a fixed-size time slot.
 * A set bit indicates the process was active during that slot.
 * Each slot is 4096 milliseconds (~4.1 seconds) in duration.
 * The 32-bit bitmap covers approximately 131 seconds of recent history.
 * EndTime is a slot index (not wall-clock seconds); multiply by 4096 to get elapsed milliseconds.
 *
 * Timeline bitmap calculations:
 * - To compute active duration from a bitmap: popcount(Bitmap) * 4096 milliseconds
 * - To convert EndTime to elapsed time: EndTime * 4096 milliseconds
 * - Total bitmap window: 32 slots * 4096 ms = 131,072 ms ~ 131 seconds
 *
 * The slot index comes from kernel timer accounting:
 * KiTimelineBitmapTime = elapsed_ms >> 12,
 * where elapsed_ms is the time since boot in milliseconds
 * (from KUSER_SHARED_DATA.TickCountQuad).
 */
typedef union _TIMELINE_BITMAP
{
    /** Raw 64-bit value combining EndTime and Bitmap. */
    ULONGLONG Value;
    struct
    {
        /**
         * The slot index of the most recent time slot represented by the bitmap.
         * Real time ~ EndTime * 4096 milliseconds.
         */
        ULONG EndTime;
        /**
         * Bit-mask of activity slots; bit 0 is the most recent slot.
         * One set bit represents approximately 4.096 seconds of activity.
         * popcount(Bitmap) * 4096 ms ~ total active duration within window.
         */
        ULONG Bitmap;
    } DUMMYSTRUCTNAME;
} TIMELINE_BITMAP, *PTIMELINE_BITMAP;

/**
 * \brief Extended energy accounting values for a process, providing activity timelines
 * and additional duration/input statistics not present in PROCESS_ENERGY_VALUES.
 *
 * \details Added in REDSTONE2; the Timelines array grew from 9 to 14 entries in REDSTONE3.
 * The Durations union and the input/audio fields are REDSTONE3+.
 */
typedef struct _PROCESS_ENERGY_VALUES_EXTENSION
{
    union
    {
        /** Activity timelines indexed by resource type (9 entries pre-RS3, 14 entries RS3+). */
        TIMELINE_BITMAP Timelines[14]; // 9 for REDSTONE2, 14 for REDSTONE3/4/5
        struct
        {
            /**
             * CPU activity timeline.
             */
            TIMELINE_BITMAP CpuTimeline;
            /**
             * Disk I/O activity timeline.
             */
            TIMELINE_BITMAP DiskTimeline;
            /**
             * Network activity timeline.
             */
            TIMELINE_BITMAP NetworkTimeline;
            /**
             * Mobile Broadband (MBB) activity timeline.
             */
            TIMELINE_BITMAP MBBTimeline;
            /**
             * Foreground visibility timeline.
             */
            TIMELINE_BITMAP ForegroundTimeline;
            /**
             * Desktop visible timeline.
             */
            TIMELINE_BITMAP DesktopVisibleTimeline;
            /**
             * DWM composition rendered timeline.
             */
            TIMELINE_BITMAP CompositionRenderedTimeline;
            /**
             * DWM composition dirty-generated timeline.
             */
            TIMELINE_BITMAP CompositionDirtyGeneratedTimeline;
            /**
             * DWM composition dirty-propagated timeline.
             */
            TIMELINE_BITMAP CompositionDirtyPropagatedTimeline;
            /**
             * Input activity timeline (REDSTONE3+).
             */
            TIMELINE_BITMAP InputTimeline; // REDSTONE3
            /**
             * Audio input (microphone) activity timeline (REDSTONE3+).
             */
            TIMELINE_BITMAP AudioInTimeline;
            /**
             * Audio output (speaker/headphone) activity timeline (REDSTONE3+).
             */
            TIMELINE_BITMAP AudioOutTimeline;
            /**
             * Display-required (screen-on prevention) timeline (REDSTONE3+).
             */
            TIMELINE_BITMAP DisplayRequiredTimeline;
            /**
             * Keyboard input activity timeline (REDSTONE3+).
             */
            TIMELINE_BITMAP KeyboardInputTimeline;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    union // REDSTONE3
    {
        /**
         * Activity state durations for extended resource types (REDSTONE3+).
         */
        ENERGY_STATE_DURATION Durations[5];
        struct
        {
            /**
             * Duration the process received user input (REDSTONE3+).
             */
            ENERGY_STATE_DURATION InputDuration;
            /**
             * Duration the process used audio input (REDSTONE3+).
             */
            ENERGY_STATE_DURATION AudioInDuration;
            /**
             * Duration the process used audio output (REDSTONE3+).
             */
            ENERGY_STATE_DURATION AudioOutDuration;
            /**
             * Duration the process prevented display power-off (REDSTONE3+).
             */
            ENERGY_STATE_DURATION DisplayRequiredDuration;
            /**
             * Duration the process ran in PSM background state (REDSTONE3+).
             */
            ENERGY_STATE_DURATION PSMBackgroundDuration;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;

    /**
     * Number of keyboard input events attributed to the process (REDSTONE3+).
     */
    ULONG KeyboardInput;
    /**
     * Number of mouse input events attributed to the process (REDSTONE3+).
     */
    ULONG MouseInput;
} PROCESS_ENERGY_VALUES_EXTENSION, *PPROCESS_ENERGY_VALUES_EXTENSION;

/**
 * The PROCESS_EXTENDED_ENERGY_VALUES structure describes the process extended energy values.
 */
typedef struct _PROCESS_EXTENDED_ENERGY_VALUES
{
    PROCESS_ENERGY_VALUES Base;
    PROCESS_ENERGY_VALUES_EXTENSION Extension;
} PROCESS_EXTENDED_ENERGY_VALUES, *PPROCESS_EXTENDED_ENERGY_VALUES;

/**
 * The PROCESS_EXTENDED_ENERGY_VALUES_V1 structure describes the process extended energy values V1.
 */
typedef struct _PROCESS_EXTENDED_ENERGY_VALUES_V1
{
    PROCESS_ENERGY_VALUES Base;
    PROCESS_ENERGY_VALUES_EXTENSION Extension;
    ULONG64 NpuWorkUnits;
} PROCESS_EXTENDED_ENERGY_VALUES_V1, *PPROCESS_EXTENDED_ENERGY_VALUES_V1;

// private
/**
 * The SYSTEM_PROCESS_CLASSIFICATION enumeration defines the system process classification values.
 */
typedef enum _SYSTEM_PROCESS_CLASSIFICATION
{
    SystemProcessClassificationNormal,
    SystemProcessClassificationSystem,
    SystemProcessClassificationSecureSystem,
    SystemProcessClassificationMemCompression,
    SystemProcessClassificationRegistry, // REDSTONE4
    SystemProcessClassificationMaximum
} SYSTEM_PROCESS_CLASSIFICATION;

/**
 * Extended process information appended to SYSTEM_PROCESS_INFORMATION in full process enumeration queries.
 *
 * \details This structure provides additional process accounting, classification, and energy metrics
 * not present in the base SYSTEM_PROCESS_INFORMATION structure. It is returned when querying
 * SystemFullProcessInformation (information class 148) or SystemExtendedProcessInformation (information class 57)
 * via NtQuerySystemInformation.
 *
 * The structure is appended immediately after the SYSTEM_THREAD_INFORMATION array in
 * SYSTEM_EXTENDED_PROCESS_INFORMATION, and the offsets are relative to the start of this extension structure.
 *
 * \since Windows 10 Threshold (version 1507, build 10240)
 *
 * \remarks This structure contains variable-length data. The UserSidOffset, PackageFullNameOffset,
 * and AppIdOffset fields point to data stored immediately after this structure in memory.
 * Callers must use these offsets to locate the actual strings and SID data.
 */
typedef struct _SYSTEM_PROCESS_INFORMATION_EXTENSION
{
    /**
     * Cumulative disk I/O counters for the process (reads, writes, flushes).
     * Includes total bytes transferred and operation counts for read, write, and flush operations.
     */
    PROCESS_DISK_COUNTERS DiskCounters;

    /**
     * Total number of context switches performed by all threads in the process since creation.
     * Use this to measure scheduling overhead and CPU time-sharing behavior.
     */
    ULONGLONG ContextSwitches;

    /**
     * Process classification flags and security attributes.
     */
    union
    {
        /**
         * Raw flags value containing all classification bits.
         */
        ULONG Flags;

        struct
        {
            /**
             * If set, the process has a strong identity (e.g., packaged app with cryptographic signing).
             * Strong identities are used for security policy enforcement and resource isolation.
             */
            ULONG HasStrongId : 1;

            /**
             * Process classification type (SYSTEM_PROCESS_CLASSIFICATION).
             * Indicates whether this is a normal user process, system process, secure system process,
             * memory compression process, or registry process. Used by the kernel for resource
             * management, security policy, and scheduling decisions.
             */
            ULONG Classification : 4; // SYSTEM_PROCESS_CLASSIFICATION

            /**
             * If set, the process has had background activity moderation applied to it.
             * The system may throttle CPU, I/O, or network resources when the process is not in the foreground.
             * \since Windows 10 Redstone 2 (version 1703)
             */
            ULONG BackgroundActivityModerated : 1;

            /**
             * Reserved for future use.
             */
            ULONG Spare : 26;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    /**
     * Offset, in bytes, from the start of this structure to the user SID (Security Identifier).
     * If zero, no user SID is available. The SID data is stored in standard binary format.
     * Use this offset to locate the process owner's security identifier for access control
     * and auditing purposes.
     */
    ULONG UserSidOffset;

    /**
     * Offset, in bytes, from the start of this structure to a null-terminated WCHAR string
     * containing the full package name (e.g., "Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe").
     * If zero, the process is not packaged (classic Win32 application).
     * \since Windows 10 Threshold (version 1507)
     */
    ULONG PackageFullNameOffset; // since THRESHOLD

    /**
     * Detailed energy accounting values for the process, including CPU cycles, disk energy,
     * network/MBB tail energy, DWM composition metrics, and activity state durations.
     * Provides per-QoS-bucket breakdowns of energy consumption for foreground/background
     * resource usage analysis.
     * \since Windows 10 Threshold (version 1507)
     */
    PROCESS_ENERGY_VALUES EnergyValues; // since THRESHOLD

    /**
     * Offset, in bytes, from the start of this structure to a null-terminated WCHAR string
     * containing the Application User Model ID (AUMID) for packaged applications.
     * If zero, the process does not have an AppId (either not packaged or not a UWP app).
     * \since Windows 10 Threshold (version 1507)
     */
    ULONG AppIdOffset; // since THRESHOLD

    /**
     * Number of bytes of committed memory shared between this process and other processes
     * (e.g., memory-mapped sections, shared DLLs, or copy-on-write pages).
     * Use this to measure memory overhead due to sharing and to calculate true private bytes.
     * SharedCommitCharge + PrivatePageCount gives a more accurate picture of process memory usage.
     * \since Windows 10 Threshold 2 (version 1511)
     */
    SIZE_T SharedCommitCharge; // since THRESHOLD2

    /**
     * Identifier of the job object to which the process belongs, if any.
     * If zero, the process is not assigned to a job object. Job objects are used to group
     * processes and apply resource limits, accounting, and management policies.
     * \since Windows 10 Redstone (version 1607)
     */
    ULONG JobObjectId; // since REDSTONE

    /**
     * Reserved for future use.
     * \since Windows 10 Redstone (version 1607)
     */
    ULONG SpareUlong; // since REDSTONE

    /**
     * Unique monotonically-increasing sequence number assigned when the process was created.
     * Unlike ProcessId (which can be recycled), this value is never reused and provides
     * a stable identifier for correlation across logs and telemetry even after process termination.
     * \since Windows 10 Redstone (version 1607)
     */
    ULONGLONG ProcessSequenceNumber;
} SYSTEM_PROCESS_INFORMATION_EXTENSION, *PSYSTEM_PROCESS_INFORMATION_EXTENSION;

// private
/**
 * The SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION structure contains system portable workspace EFI launcher
 * information.
 */
typedef struct _SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
{
    BOOLEAN EfiLauncherEnabled;
} SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION, *PSYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION;

// private
/**
 * The SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX structure contains system kernel debugger information.
 */
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
{
    BOOLEAN DebuggerAllowed;
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

// rev
/**
 * The SYSTEM_BOOT_METADATA_INFORMATION structure contains system boot metadata information.
 */
typedef struct _SYSTEM_BOOT_METADATA_INFORMATION
{
    ULONG Size;
    UCHAR Data[1];
} SYSTEM_BOOT_METADATA_INFORMATION, *PSYSTEM_BOOT_METADATA_INFORMATION;

// rev
#define SYSTEM_SOFT_REBOOT_FLAGS_STATE_MASK 0x000000BBu // State-selection bits consumed by ExpSetSoftRebootFlags.
#define SYSTEM_SOFT_REBOOT_FLAGS_OPTION_MASK 0x25000000u // User-settable option bits accepted by ExpSetSoftRebootFlags in this build.
#define SYSTEM_SOFT_REBOOT_FLAGS_USER_MASK 0x250000BBu // Accepted user input mask in this build.
#define SYSTEM_SOFT_REBOOT_FLAGS_INTERNAL_PERSIST 0x40000000u // Kernel-managed bit preserved across transitions.
#define SYSTEM_SOFT_REBOOT_FLAGS_INTERNAL_TRANSITION 0x80000000u // Kernel-managed transition-in-progress bit.

// rev
/**
 * The SYSTEM_SOFT_REBOOT_INFORMATION structure contains system soft reboot information.
 */
typedef struct _SYSTEM_SOFT_REBOOT_INFORMATION
{
    ULONG Flags; // SYSTEM_SOFT_REBOOT_FLAGS_*
} SYSTEM_SOFT_REBOOT_INFORMATION, *PSYSTEM_SOFT_REBOOT_INFORMATION;

// private
/**
 * The SYSTEM_ELAM_CERTIFICATE_INFORMATION structure contains system ELAM certificate information.
 */
typedef struct _SYSTEM_ELAM_CERTIFICATE_INFORMATION
{
    HANDLE ElamDriverFile;
} SYSTEM_ELAM_CERTIFICATE_INFORMATION, *PSYSTEM_ELAM_CERTIFICATE_INFORMATION;

// private
/**
 * The OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2 structure describes the offline crashdump configuration table V2.
 */
typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
{
    ULONG Version;
    ULONG AbnormalResetOccurred;
    ULONG OfflineMemoryDumpCapable;
    PVOID ResetDataAddress;
    ULONG ResetDataSize;
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2, *POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2;

// private
/**
 * The OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1 structure describes the offline crashdump configuration table V1.
 */
typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1
{
    ULONG Version;
    ULONG AbnormalResetOccurred;
    ULONG OfflineMemoryDumpCapable;
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1, *POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1;

// SYSTEM_PROCESSOR_FEATURES_INFORMATION // ProcessorFeatureBits
// Processor feature bits (31 flags spanning bits 0-55 with documented gaps at bits 18-22)
// These flags indicate CPU capabilities detected by the kernel via CPUID and other detection mechanisms.
// Allocated bit ranges:
//   Bits  0-17  : Base CPU features (MMX, SSE, branch prediction, etc.) - 18 flags
//   Bits 18-22  : Reserved/unused (5 bit gap)
//   Bits 23-31  : Extended states and additional features (1 flag)
//   Bits 32-34  : Advanced features (RDRAND, SMAP, RDTSCP) - 3 flags
//   Bits 35-44  : Reserved/unused (10 bit gap)
//   Bits 45-46  : Huge pages and extended saves - 2 flags
//   Bits 47-51  : Reserved/unused (5 bit gap)
//   Bits 52-58  : Security and extended features (FPU_LEAKAGE, CAT, CET_SS, SSSE3, SSE4.x) - 7 flags
//   Bits 59-62  : Reserved/unused (4 bit gap)
//   Bit  63     : XFD (extended FPU data) - 1 flag
#define KF64_SMEP              0x0000000000000001ULL // Supervisor Mode Execution Protection
#define KF64_RDTSC             0x0000000000000002ULL // Read Time-Stamp Counter
#define KF64_CR4               0x0000000000000004ULL // CR4 Register Features
#define KF64_CMOV              0x0000000000000008ULL // Conditional Move Instructions
#define KF64_GLOBAL_PAGE       0x0000000000000010ULL // Global Pages Support
#define KF64_LARGE_PAGE        0x0000000000000020ULL // Large Page Support
#define KF64_MTRR              0x0000000000000040ULL // Memory Type Range Registers
#define KF64_CMPXCHG8B         0x0000000000000080ULL // CMPXCHG8B Instruction
#define KF64_MMX               0x0000000000000100ULL // MMX Instructions
#define KF64_DTS               0x0000000000000200ULL // Debug Store
#define KF64_PAT               0x0000000000000400ULL // Page Attribute Table
#define KF64_FXSR              0x0000000000000800ULL // FXSAVE and FXRSTOR Instructions
#define KF64_FAST_SYSCALL      0x0000000000001000ULL // Fast System Call
#define KF64_XMMI              0x0000000000002000ULL // Streaming SIMD Extensions
#define KF64_3DNOW             0x0000000000004000ULL // 3DNow! Instructions
#define KF64_AMDK6MTRR         0x0000000000008000ULL // AMD K6 Memory Type Range Registers
#define KF64_XMMI64            0x0000000000010000ULL // Streaming SIMD Extensions 2
#define KF64_BRANCH            0x0000000000020000ULL // Branch Prediction
#define KF64_XSTATE            0x0000000000800000ULL // Extended States
#define KF64_RDRAND            0x0000000100000000ULL // RDRAND Instruction
#define KF64_SMAP              0x0000000200000000ULL // Supervisor Mode Access Prevention
#define KF64_RDTSCP            0x0000000400000000ULL // RDTSCP Instruction
#define KF64_HUGEPAGE          0x0000002000000000ULL // Huge Page Support
#define KF64_XSAVES            0x0000004000000000ULL // XSAVES and XRSTORS Instructions
#define KF64_FPU_LEAKAGE       0x0000020000000000ULL // FPU Data Leakage Mitigations
#define KF64_CAT               0x0000100000000000ULL // Cache Allocation Technology
#define KF64_CET_SS            0x0000400000000000ULL // Control-flow Enforcement Technology - Shadow Stack
#define KF64_SSSE3             0x0000800000000000ULL // Supplemental Streaming SIMD Extensions 3
#define KF64_SSE4_1            0x0001000000000000ULL // Streaming SIMD Extensions 4.1
#define KF64_SSE4_2            0x0002000000000000ULL // Streaming SIMD Extensions 4.2
#define KF64_XFD               0x0080000000000000ULL // eXtended FPU Data

// private
/**
 * The SYSTEM_PROCESSOR_FEATURES_INFORMATION structure contains system processor features information.
 */
typedef struct _SYSTEM_PROCESSOR_FEATURES_INFORMATION
{
    ULONGLONG ProcessorFeatureBits;
    ULONGLONG Reserved[3];
} SYSTEM_PROCESSOR_FEATURES_INFORMATION, *PSYSTEM_PROCESSOR_FEATURES_INFORMATION;

// EDID v1.4 detailed timing descriptor (18 bytes)
/**
 * The SYSTEM_EDID_DETAILED_TIMING_DESCRIPTOR structure describes the system EDID detailed timing descriptor.
 */
typedef struct _SYSTEM_EDID_DETAILED_TIMING_DESCRIPTOR
{
    USHORT PixelClock;           // Pixel clock in 10 kHz units
    UCHAR HorizontalActiveLo;    // Horizontal active pixels (low 8 bits)
    UCHAR HorizontalBlankLo;     // Horizontal blanking pixels (low 8 bits)
    UCHAR HorizontalActiveBlankHi; // High bits for horizontal active/blanking
    UCHAR VerticalActiveLo;      // Vertical active lines (low 8 bits)
    UCHAR VerticalBlankLo;       // Vertical blanking lines (low 8 bits)
    UCHAR VerticalActiveBlankHi; // High bits for vertical active/blanking
    UCHAR HorizontalSyncOffsetLo;// Horizontal sync offset (low 8 bits)
    UCHAR HorizontalSyncPulseWidthLo; // Horizontal sync pulse width (low 8 bits)
    UCHAR VerticalSyncOffsetPulseWidthLo; // Vertical sync offset/pulse width (low 4 bits each)
    UCHAR SyncOffsetPulseWidthHi; // High bits for sync offset/pulse width
    UCHAR HorizontalImageSizeLo; // Horizontal image size in mm (low 8 bits)
    UCHAR VerticalImageSizeLo;   // Vertical image size in mm (low 8 bits)
    UCHAR ImageSizeHi;           // High bits for image size
    UCHAR HorizontalBorder;      // Horizontal border in pixels
    UCHAR VerticalBorder;        // Vertical border in lines
    UCHAR Flags;                 // Flags (interlaced, stereo, sync, etc.)
} SYSTEM_EDID_DETAILED_TIMING_DESCRIPTOR, *PSYSTEM_EDID_DETAILED_TIMING_DESCRIPTOR;

// EDID v1.4 standard data format
/**
 * The SYSTEM_EDID_INFORMATION structure contains system EDID information.
 */
typedef struct _SYSTEM_EDID_INFORMATION
{
    union
    {
        UCHAR Edid[128];
        struct
        {
            UCHAR Header[8];                 // 00h: EDID header (00 FF FF FF FF FF FF 00)
            UCHAR ManufacturerId[2];         // 08h: Manufacturer ID (big endian)
            UCHAR ProductCode[2];            // 0Ah: Product code (little endian)
            UCHAR SerialNumber[4];           // 0Ch: Serial number
            UCHAR WeekOfManufacture;         // 10h: Week of manufacture
            UCHAR YearOfManufacture;         // 11h: Year of manufacture (offset from 1990)
            UCHAR EdidVersion;               // 12h: EDID version (should be 1)
            UCHAR EdidRevision;              // 13h: EDID revision (should be 4)
            UCHAR VideoInputDefinition;      // 14h: Video input parameters
            UCHAR MaxHorizontalImageSize;    // 15h: Max horizontal image size (cm)
            UCHAR MaxVerticalImageSize;      // 16h: Max vertical image size (cm)
            UCHAR DisplayGamma;              // 17h: Display gamma (gamma*100 - 100)
            UCHAR FeatureSupport;            // 18h: DPMS features, color encoding, etc.
            UCHAR Chromaticity[10];          // 19h: Chromaticity coordinates
            UCHAR EstablishedTimings[3];     // 23h: Established timings
            UCHAR StandardTimings[16];       // 26h: Standard timings (8x2 bytes)
            SYSTEM_EDID_DETAILED_TIMING_DESCRIPTOR DetailedTiming[4]; // 36h: 4 detailed timing descriptors (18 bytes each)
            UCHAR ExtensionFlag;             // 7Eh: Number of (optional) 128-byte extension blocks
            UCHAR Checksum;                  // 7Fh: Checksum (sum of all 128 bytes = 0)
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} SYSTEM_EDID_INFORMATION, *PSYSTEM_EDID_INFORMATION;

// private
/**
 * The SYSTEM_MANUFACTURING_INFORMATION structure contains system manufacturing information.
 */
typedef struct _SYSTEM_MANUFACTURING_INFORMATION
{
    ULONG Options;
    UNICODE_STRING ProfileName;
} SYSTEM_MANUFACTURING_INFORMATION, *PSYSTEM_MANUFACTURING_INFORMATION;

// private
/**
 * The SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION structure contains the system energy estimation configuration.
 */
typedef struct _SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
{
    BOOLEAN Enabled;
} SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION, *PSYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION;

// private
/**
 * The HV_DETAILS structure describes the HV details.
 */
typedef struct _HV_DETAILS
{
    ULONG Data[4];
} HV_DETAILS, *PHV_DETAILS;

// private
/**
 * The SYSTEM_HYPERVISOR_DETAIL_INFORMATION structure contains system hypervisor detail information.
 */
typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION
{
    HV_DETAILS HvVendorAndMaxFunction;
    HV_DETAILS HypervisorInterface;
    HV_DETAILS HypervisorVersion;
    HV_DETAILS HvFeatures;
    HV_DETAILS HwFeatures;
    HV_DETAILS EnlightenmentInfo;
    HV_DETAILS ImplementationLimits;
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION, *PSYSTEM_HYPERVISOR_DETAIL_INFORMATION;

/**
 * The SYSTEM_PROCESSOR_CYCLE_STATS_BUCKET_INDEX type represents a frequency bucket
 * for processor cycle statistics, selected by PoGetFrequencyBucket based on the current
 * processor frequency relative to thresholds in _KPRCB.PowerState.FrequencyBucketThresholds.
 */
typedef enum _SYSTEM_PROCESSOR_CYCLE_STATS_BUCKET_INDEX
{
    // Lowest frequency bucket — processor running at or below the first frequency threshold.
    SystemProcessorCycleStatsBucketLowestFrequency = 0,
    // Low frequency bucket — processor running between the first and second frequency thresholds.
    SystemProcessorCycleStatsBucketLowFrequency = 1,
    // High frequency bucket — processor running between the second and third frequency thresholds.
    SystemProcessorCycleStatsBucketHighFrequency = 2,
    // Highest frequency bucket — processor running above the third frequency threshold.
    SystemProcessorCycleStatsBucketHighestFrequency = 3,
    // The maximum number of frequency buckets.
    SystemProcessorCycleStatsBucketMax = 4
} SYSTEM_PROCESSOR_CYCLE_STATS_BUCKET_INDEX, *PSYSTEM_PROCESSOR_CYCLE_STATS_BUCKET_INDEX;

/**
 * The SYSTEM_PROCESSOR_CYCLE_STATS_EFFICIENCY_CLASS_INDEX type represents the baseline architectural-efficiency group.
 *
 * \note In current kernel accounting this is effectively binary grouping (0/1), not an open-ended N-class index.
 * So think of it as Group A vs Group B for heterogeneity tracking.
 * It is not guaranteed to mean exactly “P-core vs E-core” on every platform, even though that may often correlate.
 */
typedef enum _SYSTEM_PROCESSOR_CYCLE_STATS_EFFICIENCY_CLASS_INDEX
{
    // Represents the baseline architectural-efficiency group (the group with the minimum class value in current kernel logic)
    // Baseline efficiency-class group (minimum architectural efficiency class).
    SystemProcessorCycleStatsEfficiencyClassPrimary = 0,
    // Represents processors not in that baseline group (all non-min class values are folded into this second bucket)
    // Non-baseline efficiency-class group (all other architectural efficiency classes).
    SystemProcessorCycleStatsEfficiencyClassSecondary = 1,
    // The current maximum number of architectural-efficiency classes (subject to change).
    SystemProcessorCycleStatsEfficiencyClassMax = 2
} SYSTEM_PROCESSOR_CYCLE_STATS_EFFICIENCY_CLASS_INDEX, *PSYSTEM_PROCESSOR_CYCLE_STATS_EFFICIENCY_CLASS_INDEX;

// private
//
// Query notes:
//
// This class is only serviced by NtQuerySystemInformationEx. The plain NtQuerySystemInformation
// form fails with STATUS_INVALID_PARAMETER at every buffer size. The input buffer is a
// USHORT ProcessorGroup.
//
// The output is a bare array of one structure per active processor in the group, with no header and
// no offset table. An undersized buffer fails with either STATUS_INFO_LENGTH_MISMATCH or
// STATUS_BUFFER_TOO_SMALL depending on how short it is, so a retry loop must accept both. Both set
// ReturnLength to the required size.
//
// The cycle counts are attributed to a coarse frequency band and efficiency class for heterogeneous
// scheduler telemetry. They are not a continuous unhalted cycle counter and carry no delivered
// frequency resolution, so they cannot be used to compute processor utility or performance; use
// SystemProcessorPerformanceDistribution for that. On a homogeneous processor every cycle lands in
// Cycles[SystemProcessorCycleStatsBucketHighestFrequency][SystemProcessorCycleStatsEfficiencyClassPrimary]
// and the remaining cells stay zero.
//
/**
 * The SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION structure contains per-processor cycle counts bucketed by frequency
 * band and architectural efficiency class for heterogeneous scheduler telemetry
 * (SystemProcessorCycleStatsInformation, queried via NtQuerySystemInformationEx).
 */
typedef struct _SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION
{
    //
    // First index is bucket (see: PoGetFrequencyBucket) selected based on latest frequency percent
    // using _KPRCB.PowerState.FrequencyBucketThresholds.
    //
    // Second index is _KPRCB.PowerState.ArchitecturalEfficiencyClass, accounting for architecture
    // dependent KeHeteroSystem and using _KPRCB.PowerState.EarlyBootArchitecturalEfficiencyClass
    // instead, when appropriate.
    //
    ULONGLONG Cycles[SystemProcessorCycleStatsBucketMax][SystemProcessorCycleStatsEfficiencyClassMax];
} SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION, *PSYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION;

// private
#define SYSTEM_TPM_FLAG_BOOT_DRIVER_LOADED 0x1 // SepOsLoaderTpmDriverLoaded
#define SYSTEM_TPM_FLAG_READY 0x2 // PnpCoreDriverGroupLoadPhase > 2

// private
/**
 * The SYSTEM_TPM_INFORMATION structure contains system TPM information.
 */
typedef struct _SYSTEM_TPM_INFORMATION
{
    ULONG Flags; // SYSTEM_TPM_FLAG_*
} SYSTEM_TPM_INFORMATION, *PSYSTEM_TPM_INFORMATION;

// private
/**
 * The SYSTEM_VSM_PROTECTION_INFORMATION structure contains system VSM protection information.
 */
typedef struct _SYSTEM_VSM_PROTECTION_INFORMATION
{
    BOOLEAN DmaProtectionsAvailable;
    BOOLEAN DmaProtectionsInUse;
    BOOLEAN HardwareMbecAvailable; // REDSTONE4 (CVE-2018-3639)
    BOOLEAN ApicVirtualizationAvailable; // 20H1
} SYSTEM_VSM_PROTECTION_INFORMATION, *PSYSTEM_VSM_PROTECTION_INFORMATION;

// private
/**
 * The SYSTEM_KERNEL_DEBUGGER_FLAGS structure defines the system kernel debugger flags.
 */
typedef struct _SYSTEM_KERNEL_DEBUGGER_FLAGS
{
    BOOLEAN KernelDebuggerIgnoreUmExceptions;
} SYSTEM_KERNEL_DEBUGGER_FLAGS, *PSYSTEM_KERNEL_DEBUGGER_FLAGS;

// SYSTEM_CODEINTEGRITY_POLICY_INFORMATION Options
#define CODEINTEGRITYPOLICY_OPTION_ENABLED 0x01
#define CODEINTEGRITYPOLICY_OPTION_AUDIT 0x02
#define CODEINTEGRITYPOLICY_OPTION_REQUIRE_WHQL 0x04
#define CODEINTEGRITYPOLICY_OPTION_DISABLED_FLIGHTSIGNING 0x08
#define CODEINTEGRITYPOLICY_OPTION_ENABLED_UMCI 0x10
#define CODEINTEGRITYPOLICY_OPTION_ENABLED_UPDATE_POLICY_NOREBOOT 0x20
#define CODEINTEGRITYPOLICY_OPTION_ENABLED_SECURE_SETTING_POLICY 0x40
#define CODEINTEGRITYPOLICY_OPTION_ENABLED_UNSIGNED_SYSTEMINTEGRITY_POLICY 0x80
#define CODEINTEGRITYPOLICY_OPTION_DYNAMIC_CODE_POLICY_ENABLED 0x100
#define CODEINTEGRITYPOLICY_OPTION_RELOAD_POLICY_NO_REBOOT 0x10000000 // NtSetSystemInformation reloads SiPolicy.p7b
#define CODEINTEGRITYPOLICY_OPTION_CONDITIONAL_LOCKDOWN 0x20000000
#define CODEINTEGRITYPOLICY_OPTION_NOLOCKDOWN 0x40000000
#define CODEINTEGRITYPOLICY_OPTION_LOCKDOWN 0x80000000

// SYSTEM_CODEINTEGRITY_POLICY_INFORMATION HVCIOptions
#define CODEINTEGRITYPOLICY_HVCIOPTION_ENABLED 0x01
#define CODEINTEGRITYPOLICY_HVCIOPTION_STRICT 0x02
#define CODEINTEGRITYPOLICY_HVCIOPTION_DEBUG 0x04

// private
/**
 * \brief Code Integrity Policy configuration and HVCI (Hypervisor-enforced Code Integrity) settings.
 *
 * Contains the kernel's code integrity policy enforcement options and Hardware-enforced Code Integrity (HVCI)
 * configuration state. Enables applications to query the security posture of code integrity enforcement and
 * virtualization-based security features. Available via NtQuerySystemInformation(SystemCodeIntegrityInformation).
 *
 * \since Windows 10
 */
typedef struct _SYSTEM_CODEINTEGRITY_POLICY_INFORMATION
{
    /**
     * \brief Code integrity policy options (Options union).
     *
     * Union providing both raw 32-bit access and bitfield access to policy flags:
     * - Enabled: Code integrity enforcement is active
     * - Audit: Code integrity operates in audit mode (violations logged, not blocked)
     * - RequireWHQL: Windows Hardware Quality Labs certification required for drivers
     * - DisabledFlightSigning: Flight-signed binaries are blocked from loading
     * - EnabledUMCI: User-mode Code Integrity enforcement enabled (signed DLL requirement)
     * - EnabledUpdatePolicyNoReboot: Code integrity policy updates without system reboot
     * - EnabledSecureSettingPolicy: Secure settings policy enforcement enabled
     * - EnabledUnsignedSystemIntegrityPolicy: Unsigned system integrity policies allowed
     * - DynamicCodePolicyEnabled: Dynamic code generation and modification is restricted
     * - Spare: 19 reserved bits for future expansion
     * - ReloadPolicyNoReboot: Policy reloaded without reboot (bit 28)
     * - ConditionalLockdown: Conditional code integrity lockdown mode (bit 29)
     * - NoLockdown: Code integrity lockdown is not active (bit 30)
     * - Lockdown: Code integrity lockdown mode is enforced (bit 31)
     */
    union
    {
        ULONG Options;
        struct
        {
            ULONG Enabled : 1;                          ///< Code integrity enforcement enabled
            ULONG Audit : 1;                            ///< Audit mode (log violations, don't block)
            ULONG RequireWHQL : 1;                      ///< Require WHQL certification
            ULONG DisabledFlightSigning : 1;            ///< Block flight-signed binaries
            ULONG EnabledUMCI : 1;                      ///< User-mode code integrity enabled
            ULONG EnabledUpdatePolicyNoReboot : 1;      ///< Update policy without reboot
            ULONG EnabledSecureSettingPolicy : 1;       ///< Secure settings policy active
            ULONG EnabledUnsignedSystemIntegrityPolicy : 1;  ///< Allow unsigned system integrity policies
            ULONG DynamicCodePolicyEnabled : 1;         ///< Restrict dynamic code/JIT
            ULONG Spare : 19;                           ///< Reserved for future use
            ULONG ReloadPolicyNoReboot : 1;             ///< Policy reloaded without reboot
            ULONG ConditionalLockdown : 1;              ///< Conditional lockdown mode
            ULONG NoLockdown : 1;                       ///< Lockdown not enforced
            ULONG Lockdown : 1;                         ///< Lockdown mode enforced
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    /**
     * \brief Hardware-enforced Code Integrity (HVCI) options.
     *
     * Union providing both raw access and bitfield access to HVCI/VBS configuration:
     * - HVCIEnabled: HVCI is active (code integrity enforcement via hypervisor)
     * - HVCIStrict: Strict mode enforcement (higher security, lower performance)
     * - HVCIDebug: Debug mode enabled (diagnostic/troubleshooting)
     * - HVCISpare: 29 reserved bits for future HVCI expansion
     */
    union
    {
        ULONG HVCIOptions;
        struct
        {
            ULONG HVCIEnabled : 1;                      ///< HVCI enforced by hypervisor
            ULONG HVCIStrict : 1;                       ///< Strict HVCI mode enforcement
            ULONG HVCIDebug : 1;                        ///< HVCI debug mode active
            ULONG HVCISpare : 29;                       ///< Reserved for future use
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    /**
     * \brief Code integrity policy version.
     *
     * Version number incremented when the kernel reloads/updates the code integrity policy.
     * Used to detect policy changes without requiring system restart.
     */
    ULONGLONG Version;
    /**
     * \brief Code integrity policy GUID.
     *
     * Uniquely identifies the loaded code integrity policy file. Changes when a different
     * policy becomes active; can be used to correlate policy audit logs.
     */
    GUID PolicyGuid;
} SYSTEM_CODEINTEGRITY_POLICY_INFORMATION, *PSYSTEM_CODEINTEGRITY_POLICY_INFORMATION;

// private
/**
 * \brief Isolated User Mode (IUM) and virtualization-based security (VBS) status.
 *
 * Queries the state of Virtualization-Based Security (VBS) infrastructure, including Hyper-V Code Integrity (HVCI),
 * Secure Kernel, trustlets, and hardware-enforced security features. Enables applications to detect when running
 * in a hardened security posture and to determine available cryptographic protections.
 * Available via NtQuerySystemInformation(SystemIsolatedUserModeInformation).
 *
 * \since Windows 10 (RS2+)
 */
typedef struct _SYSTEM_ISOLATED_USER_MODE_INFORMATION
{
    ///< \brief Virtualization-based Security core status (byte 0):
    BOOLEAN SecureKernelRunning : 1;                   ///< Secure Kernel (hypervisor-based isolation) is active
    BOOLEAN HvciEnabled : 1;                           ///< Hypervisor-enforced Code Integrity enabled
    BOOLEAN HvciStrictMode : 1;                        ///< HVCI in strict enforcement mode
    BOOLEAN DebugEnabled : 1;                          ///< Kernel debugger enabled (may weaken security)
    BOOLEAN FirmwarePageProtection : 1;                ///< UEFI Secure Boot firmware page protection active
    BOOLEAN EncryptionKeyAvailable : 1;                ///< Isolation-backed encryption key available from Secure Kernel
    BOOLEAN SpareFlags : 2;                            ///< Reserved for future VBS flags (bits 6-7)

    ///< \brief Isolated execution and security features (byte 1):
    BOOLEAN TrustletRunning : 1;                       ///< Trustlet (isolated edge function) is running
    BOOLEAN HvciDisableAllowed : 1;                    ///< HVCI can be disabled without reboot (policy-driven)
    BOOLEAN HardwareEnforcedVbs : 1;                   ///< VBS enforced by processor/platform (e.g., AMD SME, Intel TXT)
    BOOLEAN NoSecrets : 1;                             ///< No cryptographic secrets loaded in isolated user mode
    BOOLEAN EncryptionKeyPersistent : 1;               ///< Encryption key persists across reboots
    BOOLEAN HardwareEnforcedHvpt : 1;                  ///< Hardware enforces Hypervisor Page Table (HVPT) isolation
    BOOLEAN HardwareHvptAvailable : 1;                 ///< CPU supports hardware-enforced HVPT (architectural feature)
    BOOLEAN SpareFlags2 : 1;                           ///< Reserved for future feature flag (bit 15)
    BOOLEAN EncryptionKeyTpmBound : 1;                 ///< Encryption key bound to TPM (Trusted Platform Module)

    ///< \brief Reserved for future expansion (binary compatibility):
    BOOLEAN Spare0[5];                                 ///< Reserved bytes for future isolated user mode flags
    ULONGLONG Spare1;                                  ///< Reserved 8 bytes for future isolated user mode expansion
} SYSTEM_ISOLATED_USER_MODE_INFORMATION, *PSYSTEM_ISOLATED_USER_MODE_INFORMATION;

// private
/**
 * The SYSTEM_HARDWARE_SECURITY_TEST_INTERFACE_RESULTS_INFORMATION structure contains system hardware security test
 * interface results information.
 */
typedef struct _SYSTEM_HARDWARE_SECURITY_TEST_INTERFACE_RESULTS_INFORMATION
{
    UCHAR Results[1];
} SYSTEM_HARDWARE_SECURITY_TEST_INTERFACE_RESULTS_INFORMATION, *PSYSTEM_HARDWARE_SECURITY_TEST_INTERFACE_RESULTS_INFORMATION;

// private
/**
 * The SYSTEM_SINGLE_MODULE_INFORMATION structure contains system single module information.
 */
typedef struct _SYSTEM_SINGLE_MODULE_INFORMATION
{
    PVOID TargetModuleAddress;
    RTL_PROCESS_MODULE_INFORMATION_EX ExInfo;
} SYSTEM_SINGLE_MODULE_INFORMATION, *PSYSTEM_SINGLE_MODULE_INFORMATION;

// private
/**
 * The SYSTEM_INTERRUPT_CPU_SET_INFORMATION structure contains system interrupt CPU set information.
 */
typedef struct _SYSTEM_INTERRUPT_CPU_SET_INFORMATION
{
    ULONG Gsiv;
    USHORT Group;
    ULONGLONG CpuSets;
} SYSTEM_INTERRUPT_CPU_SET_INFORMATION, *PSYSTEM_INTERRUPT_CPU_SET_INFORMATION;

// private
/**
 * The SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION structure contains system secureboot policy full information.
 */
typedef struct _SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
{
    SYSTEM_SECUREBOOT_POLICY_INFORMATION PolicyInformation;
    ULONG PolicySize;
    _Field_size_bytes_(PolicySize) UCHAR Policy[1];
} SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION, *PSYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION;

// rev
#define SYSTEM_CODE_INTEGRITY_POLICY_HEADER_VERSION 8

// rev
/**
 * The SYSTEM_CODE_INTEGRITY_POLICY_HEADER structure describes the header of a Code Integrity policy.
 */
typedef struct _SYSTEM_CODE_INTEGRITY_POLICY_HEADER
{
    UCHAR Magic[4];                    // "WDAC"
    ULONG Version;                     // Policy version/format number
    ULONG TypeAndOptions;              // Policy type flags and options
    ULONG TimestampLow;                // Creation/modification timestamp (low)
    ULONG TimestampHigh;               // Creation/modification timestamp (high)
    UCHAR Hash[32];                    // SHA-256 policy hash/identifier
} SYSTEM_CODE_INTEGRITY_POLICY_HEADER, *PSYSTEM_CODE_INTEGRITY_POLICY_HEADER;

// rev // Hash Rule Entry (Variable length)
/**
 * The SYSTEM_CODE_INTEGRITY_POLICY_RULE_ENTRY structure describes a single rule in a Code Integrity policy.
 */
typedef struct _SYSTEM_CODE_INTEGRITY_POLICY_RULE_ENTRY
{
    ULONG Marker;                      // 8-byte marker (part of rule identification)
    ULONG RuleMarkerHigh;
    ULONG DataLength;                  // 4-byte length of hash data
    UCHAR FixedPrefix[12];             // 12-byte fixed prefix (rule type, attributes)
    UCHAR Hash[ANYSIZE_ARRAY];         // Variable-length hash (SHA-256, SHA-1, etc.)
} SYSTEM_CODE_INTEGRITY_POLICY_RULE_ENTRY, *PSYSTEM_CODE_INTEGRITY_POLICY_RULE_ENTRY;

// rev // String Table Entry (Variable length, 4-byte aligned)
/**
 * The SYSTEM_CODE_INTEGRITY_POLICY_STRING_ENTRY structure describes a single string entry in a Code Integrity policy.
 */
typedef struct _SYSTEM_CODE_INTEGRITY_POLICY_STRING_ENTRY
{
    USHORT Length;                     // Length in bytes (not including null terminator)
    WCHAR String[ANYSIZE_ARRAY];       // UTF-16LE string
    // UCHAR Padding[ANYSIZE_ARRAY]    // Followed by Padding[] to align to 4-byte boundary
} SYSTEM_CODE_INTEGRITY_POLICY_STRING_ENTRY, *PSYSTEM_CODE_INTEGRITY_POLICY_STRING_ENTRY;

// rev // Numeric Index Table (used for Signers, FileRules, etc.)
/**
 * The SYSTEM_CODE_INTEGRITY_POLICY_INDEX_TABLE_ENTRY structure describes a single index-table entry in a Code
 * Integrity policy.
 */
typedef struct _SYSTEM_CODE_INTEGRITY_POLICY_INDEX_TABLE_ENTRY
{
    // Width determines interpretation:
    // Width=8: Signer entry {StringIndex(2), RuleRefCount(2), RuleRefs[RuleRefCount](4 each)}
    // Width=4: FileRule index referencing a string from string table
    UCHAR Entry[ANYSIZE_ARRAY];
} SYSTEM_CODE_INTEGRITY_POLICY_INDEX_TABLE_ENTRY, *PSYSTEM_CODE_INTEGRITY_POLICY_INDEX_TABLE_ENTRY;

// rev
/**
 * The SYSTEM_CODE_INTEGRITY_POLICY_FULL_INFORMATION structure contains full information about a Code Integrity policy.
 */
typedef struct _SYSTEM_CODE_INTEGRITY_POLICY_FULL_INFORMATION
{
    SYSTEM_CODE_INTEGRITY_POLICY_HEADER Header;
    UCHAR RuleBody[ANYSIZE_ARRAY]; // Followed by sections (offsets determined by header)
    // UCHAR StringTable[ANYSIZE_ARRAY]; // Followed by StringTable
    // UCHAR IndexTables[ANYSIZE_ARRAY]; // Followed by NumericTables (Signers, FileRules, etc.)
} SYSTEM_CODE_INTEGRITY_POLICY_FULL_INFORMATION, *PSYSTEM_CODE_INTEGRITY_POLICY_FULL_INFORMATION;

// private
/**
 * The KAFFINITY_EX structure represents an extended processor affinity mask that spans multiple processor groups.
 */
typedef struct _KAFFINITY_EX
{
    USHORT Count;
    USHORT Size;
    ULONG Reserved;
    union
    {
        ULONG_PTR Bitmap[1];
        ULONG_PTR StaticBitmap[32];
    } DUMMYUNIONNAME;
} KAFFINITY_EX, *PKAFFINITY_EX;

// private
/**
 * The SYSTEM_ROOT_SILO_INFORMATION structure contains system root silo information.
 */
typedef struct _SYSTEM_ROOT_SILO_INFORMATION
{
    ULONG NumberOfSilos;
    ULONG SiloIdList[1];
} SYSTEM_ROOT_SILO_INFORMATION, *PSYSTEM_ROOT_SILO_INFORMATION;

// private
/**
 * The SYSTEM_CPU_SET_TAG_INFORMATION structure contains system CPU set tag information.
 */
typedef struct _SYSTEM_CPU_SET_TAG_INFORMATION
{
    ULONGLONG Tag;
    ULONGLONG CpuSets[1];
} SYSTEM_CPU_SET_TAG_INFORMATION, *PSYSTEM_CPU_SET_TAG_INFORMATION;

// private
/**
 * The SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION structure contains system secure kernel hyperguard profile
 * information.
 */
typedef struct _SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
{
    ULONG ExtentCount;
    ULONG ValidStructureSize;
    ULONG NextExtentIndex;
    ULONG ExtentRestart;
    ULONG CycleCount;
    ULONG TimeoutCount;
    ULONGLONG CycleTime;
    ULONGLONG CycleTimeMax;
    ULONGLONG ExtentTime;
    ULONG ExtentTimeIndex;
    ULONG ExtentTimeMaxIndex;
    ULONGLONG ExtentTimeMax;
    ULONGLONG HyperFlushTimeMax;
    ULONGLONG TranslateVaTimeMax;
    ULONGLONG DebugExemptionCount;
    ULONGLONG TbHitCount;
    ULONGLONG TbMissCount;
    ULONGLONG VinaPendingYield;
    ULONGLONG HashCycles;
    ULONG HistogramOffset;
    ULONG HistogramBuckets;
    ULONG HistogramShift;
    ULONG Reserved1;
    ULONGLONG PageNotPresentCount;
} SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION, *PSYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION;

// private
/**
 * The SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION structure contains system secureboot platform manifest
 * information.
 */
typedef struct _SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION
{
    ULONG PlatformManifestSize;
    _Field_size_bytes_(PlatformManifestSize) UCHAR PlatformManifest[1];
} SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION, *PSYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION;

// private
/**
 * The SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT structure specifies the input parameters for a system interrupt
 * steering information query.
 */
typedef struct _SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT
{
    ULONG Gsiv;
    UCHAR ControllerInterrupt;
    UCHAR EdgeInterrupt;
    UCHAR IsPrimaryInterrupt;
    GROUP_AFFINITY TargetAffinity;
} SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, *PSYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT;

// private
/**
 * The SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT union receives the output of a system interrupt steering
 * information query.
 */
typedef union _SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT
{
    ULONG AsULONG;
    struct
    {
        ULONG Enabled : 1;
        ULONG Reserved : 31;
    } DUMMYSTRUCTNAME;
} SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT, *PSYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT;

#if !defined(NTDDI_WIN10_FE)
// private
typedef struct _SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION
{
    ULONG Machine : 16;
    ULONG KernelMode : 1;
    ULONG UserMode : 1;
    ULONG Native : 1;
    ULONG Process : 1;
    ULONG WoW64Container : 1;
    ULONG ReservedZero0 : 11;
} SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION, *PSYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION;
#endif

// private
/**
 * The SYSTEM_MEMORY_USAGE_INFORMATION structure contains information about the memory usage of the system.
 */
typedef struct _SYSTEM_MEMORY_USAGE_INFORMATION
{
    ULONGLONG TotalPhysicalBytes;
    ULONGLONG AvailableBytes;
    LONGLONG ResidentAvailableBytes;
    ULONGLONG CommittedBytes;
    ULONGLONG SharedCommittedBytes;
    ULONGLONG CommitLimitBytes;
    ULONGLONG PeakCommitmentBytes;
} SYSTEM_MEMORY_USAGE_INFORMATION, *PSYSTEM_MEMORY_USAGE_INFORMATION;

// rev
/**
 * The SYSTEM_CODEINTEGRITY_IMAGE_TYPE constant is used for validating user-mode images (EXE/DLL).
 */
typedef enum _SYSTEM_CODEINTEGRITY_IMAGE_TYPE
{
    SystemCodeIntegrityImageTypeUser,
    SystemCodeIntegrityImageTypeKernel,
    SystemCodeIntegrityImageTypeBoot
} SYSTEM_CODEINTEGRITY_IMAGE_TYPE;

/**
 * The SYSTEM_CODEINTEGRITY_IMAGE_TYPE_USER constant is used for validating user-mode images (EXE/DLL).
 *
 * Validation includes:
 * - Digital signature
 * - User-mode certificate chain validity.
 * - Compliance policies for user-mode binaries.
 */
#define SYSTEM_CODEINTEGRITY_IMAGE_TYPE_USER     0

/**
 * The SYSTEM_CODEINTEGRITY_IMAGE_TYPE_KERNEL constant is used for validating kernel-mode images (SYS/Native).
 *
 * Validation includes:
 * - Signed by a trusted certificate authority (or cross-signed).
 * - Compliance policies for kernel-mode binaries.
 */
#define SYSTEM_CODEINTEGRITY_IMAGE_TYPE_KERNEL   1

/**
 * The SYSTEM_CODEINTEGRITY_IMAGE_TYPE_BOOT constant is used for validating boot-critical images (SYS/Native).
 *
 * Validation includes:
 * - Signed only by Microsoft.
 * - Compliance policies for boot-critical binaries (Strict WHQL, Secure Boot requirements).
 */
#define SYSTEM_CODEINTEGRITY_IMAGE_TYPE_BOOT    2

/**
 * The SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION structure contains information to validate the integrity of an image.
 *
 * \note The return status of NtQuerySystemInformation indicates the result of the code integrity validation as determined by the type specified.
 */
typedef struct _SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
{
    HANDLE ImageFile;   // in: Handle to a file or image to validate.
    ULONG Type;         // in: The type of code integrity policy. // REDSTONE4
} SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION, *PSYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION;

/**
 * The SYSTEM_PHYSICAL_MEMORY_INFORMATION structure retrieves the physical memory layout of the system.
 *
 * \remarks The addresses are physical, not virtual.
 */
typedef struct _SYSTEM_PHYSICAL_MEMORY_INFORMATION
{
    ULONGLONG TotalPhysicalBytes;           // Total amount of physical RAM present, in bytes.
    ULONGLONG LowestPhysicalAddress;        // Lowest accessible physical address (byte address).
    ULONGLONG HighestPhysicalAddress;       // Highest accessible physical address (byte address, inclusive).
} SYSTEM_PHYSICAL_MEMORY_INFORMATION, *PSYSTEM_PHYSICAL_MEMORY_INFORMATION;

/**
 * The SYSTEM_ACTIVITY_MODERATION_STATE type contains the moderation state applied to an application,
 * with respect to background throttling, resource reduction, and related heuristics.
 *
 * \remarks The state may be assigned automatically by the system or explicitly overridden by the user.
 */
typedef enum _SYSTEM_ACTIVITY_MODERATION_STATE
{
    SystemActivityModerationStateSystemManaged, // The system applies heuristics based on the appropriate moderation behavior.
    SystemActivityModerationStateUserManagedAllowThrottling, // User allows the system to throttle the application.
    SystemActivityModerationStateUserManagedDisableThrottling, // User disables throttling for the application.
    MaxSystemActivityModerationState // Upper bound for validation; not a real state.
} SYSTEM_ACTIVITY_MODERATION_STATE;

// private - REDSTONE2
/**
 * The SYSTEM_ACTIVITY_MODERATION_EXE_STATE structure describes the system activity moderation exe state.
 */
typedef struct _SYSTEM_ACTIVITY_MODERATION_EXE_STATE // REDSTONE3: Renamed SYSTEM_ACTIVITY_MODERATION_INFO
{
    UNICODE_STRING ExePathNt;
    SYSTEM_ACTIVITY_MODERATION_STATE ModerationState;
} SYSTEM_ACTIVITY_MODERATION_EXE_STATE, *PSYSTEM_ACTIVITY_MODERATION_EXE_STATE;

/**
 * The SYSTEM_ACTIVITY_MODERATION_APP_TYPE enumeration defines the system activity moderation app types.
 */
typedef enum _SYSTEM_ACTIVITY_MODERATION_APP_TYPE
{
    SystemActivityModerationAppTypeClassic,
    SystemActivityModerationAppTypePackaged,
    MaxSystemActivityModerationAppType
} SYSTEM_ACTIVITY_MODERATION_APP_TYPE;

// private - REDSTONE3
/**
 * The SYSTEM_ACTIVITY_MODERATION_INFO structure contains system activity moderation information.
 */
typedef struct _SYSTEM_ACTIVITY_MODERATION_INFO
{
    UNICODE_STRING Identifier;
    SYSTEM_ACTIVITY_MODERATION_STATE ModerationState;
    SYSTEM_ACTIVITY_MODERATION_APP_TYPE AppType;
} SYSTEM_ACTIVITY_MODERATION_INFO, *PSYSTEM_ACTIVITY_MODERATION_INFO;

// rev
/**
 * The SYSTEM_ACTIVITY_MODERATION_APP_SETTINGS structure describes the moderation state
 * and classification of an application as used by the system's activity moderation framework.
 * These settings influence how aggressively the system may throttle, defer, or
 * suppress certain background activities for the application.
 *
 * The structure maintains a stable binary layout because it is stored in
 * serialized policy blobs and consumed by system components that expect
 * fixed field offsets.
 */
typedef struct _SYSTEM_ACTIVITY_MODERATION_APP_SETTINGS
{
    LARGE_INTEGER LastUpdatedTime; // Timestamp of the last update to this settings block.
    SYSTEM_ACTIVITY_MODERATION_STATE ModerationState; // Current moderation state assigned to the application.
    UCHAR Reserved[4]; // Reserved for future expansion
    SYSTEM_ACTIVITY_MODERATION_APP_TYPE AppType; // Current application type for moderation purposes.
    ULONG Flags; // Additional moderation flags.
} SYSTEM_ACTIVITY_MODERATION_APP_SETTINGS, *PSYSTEM_ACTIVITY_MODERATION_APP_SETTINGS;

/**
 * The SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS structure provides the activity-moderation
 * registry location where moderation policies or overrides may be stored.
 */
typedef struct _SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
{
    HANDLE UserKeyHandle; // Handle to the user registry key for activity moderation settings.
} SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS, *PSYSTEM_ACTIVITY_MODERATION_USER_SETTINGS;

// rev
/**
 * The SYSTEM_CODE_INTEGRITY_POLICIES_FULL_INFORMATION structure contains full information about the active Code
 * Integrity policies.
 */
typedef struct _SYSTEM_CODE_INTEGRITY_POLICIES_FULL_INFORMATION
{
    ULONG PolicyCount;
    UCHAR PolicyBlobs[ANYSIZE_ARRAY];
} SYSTEM_CODE_INTEGRITY_POLICIES_FULL_INFORMATION, *PSYSTEM_CODE_INTEGRITY_POLICIES_FULL_INFORMATION;

/**
 * The SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION structure contains Code Integrity unlock state and validation token.
 *
 * **Purpose:**
 *
 * The UnlockId field is a 32-byte cryptographic validation token used to authenticate requests to temporarily
 * disable Code Integrity (CI) enforcement. It works in conjunction with the three flag bits (Locked, UnlockApplied, UnlockIdValid)
 * to control the application of code integrity bypass authorization.
 *
 * **Mechanism:**
 *
 * \b Token \b Generation: When needing to disable CI, a component (bootloader, recovery environment, or factory process)
 * computes a 32-byte UnlockId using:
 * - HMAC-SHA256 or similar cryptographic hash function
 * - A kernel-embedded or TPM-stored secret key
 * - Machine-specific data (boot state, firmware version, hardware configuration, etc.)
 *
 * \b Validation: The kernel validates the UnlockId by:
 * - Recomputing the expected HMAC-SHA256 using its stored secret and machine state
 * - Comparing against the provided UnlockId (32-byte comparison)
 * - Setting the UnlockIdValid flag if the cryptographic match succeeds
 * - Rejecting any token that fails validation
 *
 * \b Application: Once validated:
 * - UnlockApplied flag is set (unlock request accepted by the kernel)
 * - Locked flag may be cleared (CI enforcement disabled for this session)
 * - Temporary bypass of code integrity checks is granted for authorized operations
 *
 * **Security Properties:**
 *
 * - \b 256-bit \b Token: The 32-byte (256-bit) size is standard for HMAC-SHA256 output, providing strong cryptographic security
 * - \b Microsoft-Controlled \b Secret: UnlockId tokens are derived from a Microsoft-controlled secret key, preventing unauthorized bypasses
 * - \b Machine \b Binding: Machine-specific data ensures tokens are valid only for the intended system
 * - \b Temporal \b Scope: Unlock is session-scoped and typically used during controlled recovery or factory processes
 *
 * **Use Cases:**
 *
 * - \b Factory \b Reset (OOBE): Allow boot in non-secure mode during device initial setup and provisioning
 * - \b Recovery \b Environment: Enable recovery tools to bypass CI during authorized system repairs
 * - \b Secure \b Boot \b Bypass: Controlled disabling of code verification during authorized recovery scenarios
 * - \b Development/Debugging: Microsoft-signed tokens for internal kernel validation and testing on development systems
 *
 * \note The UnlockId prevents unauthorized bypasses of code integrity protection and is only trusted after cryptographic validation succeeds.
 * \note This structure is private to the kernel and not part of the public API.
 * \note Available since Windows Redstone 4 (Windows 10 version 1803).
 */
// private
/**
 * The SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION structure contains the Code Integrity unlock identifier.
 */
typedef struct _SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            /** \brief Code Integrity is currently locked (enforced).
             *
             * When set (1), Code Integrity enforcement is active and code execution restrictions are applied.
             * When clear (0), Code Integrity may be disabled if UnlockApplied is set and a valid token was provided.
             */
            ULONG Locked : 1;

            /** \brief Unlock request has been validated and applied.
             *
             * Set by the kernel when the provided UnlockId passes cryptographic validation and the unlock is authorized.
             * When set, this flag indicates that CI enforcement has been temporarily disabled for this session.
             * Field removed after Windows 10 v1909 (19H1) in newer releases.
             */
            ULONG UnlockApplied : 1;

            /** \brief UnlockId contains a valid, authenticated cryptographic token.
             *
             * Set by the kernel when the provided UnlockId passes HMAC-SHA256 validation against the kernel's stored secret.
             * This flag indicates that the token is cryptographically valid and can authorize CI bypass.
             */
            ULONG UnlockIdValid : 1;

            /** \brief Reserved flag bits for future use. */
            ULONG Reserved : 29;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    /** \brief 32-byte cryptographic validation token for Code Integrity unlock requests.
     *
     * This HMAC-SHA256 token authorizes temporary disabling of Code Integrity enforcement.
     * The token is computed using a kernel-embedded secret key, machine-specific data, and cryptographic derivation.
     *
     * **Format:**
     * - Size: 32 bytes (256 bits)
     * - Algorithm: HMAC-SHA256
     * - Derivation: Microsoft-controlled secret key + machine state
     * - Validation: Kernel verifies token before granting CI bypass
     *
     * **Validation Process:**
     * 1. Kernel recomputes expected HMAC-SHA256 from stored secret and current machine state
     * 2. Compares computed HMAC against the provided UnlockId (byte-for-byte)
     * 3. Sets UnlockIdValid flag if match succeeds; fails otherwise
     * 4. If validation succeeds, kernel sets UnlockApplied and may clear Locked flag
     *
     * **Authorization Scenarios:**
     * - Factory Reset (OOBE): Token allows non-secure boot during device provisioning
     * - Recovery Mode: Token allows recovery environment to bypass code verification checks
     * - Development/Debug: Microsoft-signed tokens for test systems and kernel development
     *
     * \note Available since Windows 10 Redstone 4 (version 1803, NTDDI_WIN10_RS4).
     */
    UCHAR UnlockId[32];
} SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION, *PSYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION;

// private
/**
 * The SYSTEM_FLUSH_INFORMATION structure contains system flush information.
 */
typedef struct _SYSTEM_FLUSH_INFORMATION
{
    union
    {
        ULONG SupportedFlushMethods;
        struct
        {
            ULONG MethodAlwaysPresent : 1;   // 0x1
            ULONG MethodProcessorFeatureBit35 : 1; // 0x2
            ULONG MethodProcessorFeatureBit36 : 1; // 0x4
            ULONG ReservedMethods : 29;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    ULONG ProcessorCacheFlushSize;

    union
    {
        ULONGLONG SystemFlushCapabilities;
        struct
        {
            ULONGLONG NfitType7FlushCapable : 1; // 0x1
            ULONGLONG ReservedCapabilities : 63;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;

    ULONGLONG Reserved[2];
} SYSTEM_FLUSH_INFORMATION, *PSYSTEM_FLUSH_INFORMATION;

// private
/**
 * The SYSTEM_WRITE_CONSTRAINT_INFORMATION structure contains system write constraint information.
 */
typedef struct _SYSTEM_WRITE_CONSTRAINT_INFORMATION
{
    ULONG WriteConstraintPolicy;
    ULONG Reserved;
} SYSTEM_WRITE_CONSTRAINT_INFORMATION, *PSYSTEM_WRITE_CONSTRAINT_INFORMATION;

// private
/**
 * The SYSTEM_KERNEL_VA_SHADOW_INFORMATION structure contains the state of kernel virtual address (KVA) shadowing.
 */
typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION
{
    union
    {
        ULONG KvaShadowFlags;
        struct
        {
            ULONG KvaShadowEnabled : 1;
            ULONG KvaShadowUserGlobal : 1;
            ULONG KvaShadowPcid : 1;
            ULONG KvaShadowInvpcid : 1;
            ULONG KvaShadowRequired : 1; // REDSTONE4
            ULONG KvaShadowRequiredAvailable : 1;
            ULONG InvalidPteBit : 6;
            ULONG L1DataCacheFlushSupported : 1;
            ULONG L1TerminalFaultMitigationPresent : 1;
            ULONG Reserved : 18;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, *PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

// private
/**
 * The SYSTEM_CODEINTEGRITY_VERIFICATION_INFORMATION structure contains information
 * required for code integrity verification of an image.
 *
 * Two verification modes are supported:
 * - File-backed: supply a non-null FileHandle (handle to an open file); Image and ImageSize are ignored.
 * - Memory-backed: supply a null FileHandle, set Image to the base address of a mapped/loaded PE image
 *   in memory, and ImageSize to its size in bytes. The kernel reads image content directly from the buffer.
 */
typedef struct _SYSTEM_CODEINTEGRITY_VERIFICATION_INFORMATION
{
    HANDLE FileHandle; // Handle to an open file for file-backed verification, or NULL for memory-backed verification.
    ULONG ImageSize;   // Size in bytes of the image buffer; used only when FileHandle is NULL.
    PVOID Image;       // Base address of the PE image buffer for memory-backed verification; ignored when FileHandle is non-null.
} SYSTEM_CODEINTEGRITY_VERIFICATION_INFORMATION, *PSYSTEM_CODEINTEGRITY_VERIFICATION_INFORMATION;

// rev
/**
 * The SYSTEM_HYPERVISOR_USER_SHARED_DATA structure contains information shared with the hypervisor and user-mode.
 *
 * This structure is populated by the hypervisor (when present) to allow user-mode components to perform
 * high-resolution time calculations without requiring a hypercall or kernel transition.
 */
typedef struct _SYSTEM_HYPERVISOR_USER_SHARED_DATA
{
    /**
     * Lock used to synchronize updates to the timing fields.
     *
     * The hypervisor increments this value before and after updating the
     * QPC multiplier and bias. User-mode callers can sample this value
     * before and after reading the timing fields to detect whether an
     * update occurred mid-read and retry if necessary.
     */
    volatile ULONG TimeUpdateLock;

    /**
     * Reserved field - The hypervisor does not assign this field.
     */
    ULONG Reserved0;

    /**
     * Multiplier used to convert hypervisor QPC ticks to host time.
     *
     * This value is applied to the hypervisor's virtualized performance
     * counter to compute a stable, high-resolution timebase. The multiplier
     * is chosen by the hypervisor based on the underlying hardware timer
     * source and virtualization mode.
     */
    ULONGLONG QpcMultiplier;

    /**
     * Bias applied after QPC multiplication to produce final time.
     *
     * The hypervisor uses this bias to align the virtualized QPC value with
     * the host's notion of system time. Combined with QpcMultiplier, this
     * allows user-mode components to compute consistent time values even
     * under virtualization.
     */
    ULONGLONG QpcBias;

    ULONGLONG InterruptTimeQpcBaseline;
    ULONGLONG QpcMultiplierFactor; // ARM64
} SYSTEM_HYPERVISOR_USER_SHARED_DATA, *PSYSTEM_HYPERVISOR_USER_SHARED_DATA;

/**
 * The SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION structure describes
 * the user-mode mapping of the hypervisor shared page.
 *
 * This structure provides the virtual address at which the hypervisor's
 * user-accessible shared data page is mapped. When a hypervisor is present,
 * the kernel maps a read-only page into user mode containing timing and
 * virtualization-related information (see SYSTEM_HYPERVISOR_USER_SHARED_DATA).
 *
 * User-mode components can read this page directly to obtain high-resolution
 * time conversion parameters or other hypervisor-provided data without
 * requiring a hypercall or kernel transition.
 */
typedef struct _SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION
{
    /**
     * User-mode virtual address of the hypervisor shared data page.
     * If no hypervisor is present, this pointer is NULL.
     */
    PSYSTEM_HYPERVISOR_USER_SHARED_DATA HypervisorSharedUserVa;
} SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION, *PSYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION;

// private
/**
 * The SYSTEM_FIRMWARE_PARTITION_INFORMATION structure contains system firmware partition information.
 */
typedef struct _SYSTEM_FIRMWARE_PARTITION_INFORMATION
{
    UNICODE_STRING FirmwarePartition;
} SYSTEM_FIRMWARE_PARTITION_INFORMATION, *PSYSTEM_FIRMWARE_PARTITION_INFORMATION;

// private
/**
 * The SYSTEM_SPECULATION_CONTROL_INFORMATION structure contains the state of the processor speculation-control
 * mitigations.
 */
typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG BpbEnabled : 1;
            ULONG BpbDisabledSystemPolicy : 1;
            ULONG BpbDisabledNoHardwareSupport : 1;
            ULONG SpecCtrlEnumerated : 1;
            ULONG SpecCmdEnumerated : 1;
            ULONG IbrsPresent : 1;
            ULONG StibpPresent : 1;
            ULONG SmepPresent : 1;
            ULONG SpeculativeStoreBypassDisableAvailable : 1; // REDSTONE4 (CVE-2018-3639)
            ULONG SpeculativeStoreBypassDisableSupported : 1;
            ULONG SpeculativeStoreBypassDisabledSystemWide : 1;
            ULONG SpeculativeStoreBypassDisabledKernel : 1;
            ULONG SpeculativeStoreBypassDisableRequired : 1;
            ULONG BpbDisabledKernelToUser : 1;
            ULONG SpecCtrlRetpolineEnabled : 1;
            ULONG SpecCtrlImportOptimizationEnabled : 1;
            ULONG EnhancedIbrs : 1; // since 19H1
            ULONG HvL1tfStatusAvailable : 1;
            ULONG HvL1tfProcessorNotAffected : 1;
            ULONG HvL1tfMigitationEnabled : 1;
            ULONG HvL1tfMigitationNotEnabled_Hardware : 1;
            ULONG HvL1tfMigitationNotEnabled_LoadOption : 1;
            ULONG HvL1tfMigitationNotEnabled_CoreScheduler : 1;
            ULONG EnhancedIbrsReported : 1;
            ULONG MdsHardwareProtected : 1; // since 19H2
            ULONG MbClearEnabled : 1;
            ULONG MbClearReported : 1;
            ULONG ReservedTaa : 4;
            ULONG Reserved : 1;
        } DUMMYSTRUCTNAME;
    } SpeculationControlFlags;
    union
    {
        ULONG Flags; // since 23H2
        struct
        {
            ULONG SbdrSsdpHardwareProtected : 1;
            ULONG FbsdpHardwareProtected : 1;
            ULONG PsdpHardwareProtected : 1;
            ULONG FbClearEnabled : 1;
            ULONG FbClearReported : 1;
            ULONG BhbEnabled : 1;
            ULONG BhbDisabledSystemPolicy : 1;
            ULONG BhbDisabledNoHardwareSupport : 1;
            ULONG BranchConfusionStatus : 2;
            ULONG BranchConfusionReported : 1;
            ULONG RdclHardwareProtectedReported : 1;
            ULONG RdclHardwareProtected : 1;
            ULONG Reserved3 : 4;
            ULONG Reserved4 : 3;
            ULONG DivideByZeroReported : 1;
            ULONG DivideByZeroStatus : 1;
            ULONG Reserved5 : 3;
            ULONG Reserved : 7;
        } DUMMYSTRUCTNAME;
    } SpeculationControlFlags2;
} SYSTEM_SPECULATION_CONTROL_INFORMATION, *PSYSTEM_SPECULATION_CONTROL_INFORMATION;

// private
/**
 * The SYSTEM_DMA_GUARD_POLICY_INFORMATION structure contains the kernel DMA protection policy state.
 */
typedef struct _SYSTEM_DMA_GUARD_POLICY_INFORMATION
{
    BOOLEAN DmaGuardPolicyEnabled;
} SYSTEM_DMA_GUARD_POLICY_INFORMATION, *PSYSTEM_DMA_GUARD_POLICY_INFORMATION;

// private
/**
 * The SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION structure contains system enclave launch control information.
 */
typedef struct _SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
{
    UCHAR EnclaveLaunchSigner[32];
} SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION, *PSYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION;

// private
/**
 * The SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION structure contains system workload allowed CPU set information.
 */
typedef struct _SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
{
    ULONGLONG WorkloadClass;
    ULONGLONG CpuSets[1];
} SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION, *PSYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION;

// private
/**
 * The SYSTEM_SECURITY_MODEL_INFORMATION structure contains system security model information.
 */
typedef struct _SYSTEM_SECURITY_MODEL_INFORMATION
{
    union
    {
        ULONG SecurityModelFlags;
        struct
        {
            ULONG ReservedFlag : 1; // SModeAdminlessEnabled
            ULONG AllowDeviceOwnerProtectionDowngrade : 1;
            ULONG Reserved : 30;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} SYSTEM_SECURITY_MODEL_INFORMATION, *PSYSTEM_SECURITY_MODEL_INFORMATION;

// private
/**
 * The SECURE_SPECULATION_CONTROL_INFORMATION union contains secure speculation control information.
 */
typedef union _SECURE_SPECULATION_CONTROL_INFORMATION
{
    ULONG KvaShadowSupported : 1;
    ULONG KvaShadowEnabled : 1;
    ULONG KvaShadowUserGlobal : 1;
    ULONG KvaShadowPcid : 1;
    ULONG MbClearEnabled : 1;
    ULONG L1TFMitigated : 1; // since 20H2
    ULONG BpbEnabled : 1;
    ULONG IbrsPresent : 1;
    ULONG EnhancedIbrs : 1;
    ULONG StibpPresent : 1;
    ULONG SsbdSupported : 1;
    ULONG SsbdRequired : 1;
    ULONG BpbKernelToUser : 1;
    ULONG BpbUserToKernel : 1;
    ULONG ReturnSpeculate : 1;
    ULONG BranchConfusionSafe : 1;
    ULONG SsbsEnabledAlways : 1; // 24H2
    ULONG SsbsEnabledKernel : 1;
    ULONG Reserved : 14;
} SECURE_SPECULATION_CONTROL_INFORMATION, *PSECURE_SPECULATION_CONTROL_INFORMATION;

// private
/**
 * The SYSTEM_FIRMWARE_RAMDISK_INFORMATION structure contains system firmware ramdisk information.
 */
typedef struct _SYSTEM_FIRMWARE_RAMDISK_INFORMATION
{
    ULONG Version;
    ULONG BlockSize;
    ULONG_PTR BaseAddress;
    SIZE_T Size;
} SYSTEM_FIRMWARE_RAMDISK_INFORMATION, *PSYSTEM_FIRMWARE_RAMDISK_INFORMATION;

// rev
/**
 * The SYSTEM_WHEA_IPMI_HARDWARE_INFORMATION_WIN10 structure contains system WHEA IPMI hardware information.
 */
typedef struct _SYSTEM_WHEA_IPMI_HARDWARE_INFORMATION_WIN10
{
    ULONGLONG RecordId;     // IPMI SEL (System Event Log) record identifier
    UCHAR EventType;        // IPMI event/reading type code
    UCHAR SensorType;       // IPMI sensor type (e.g. temperature, voltage, processor)
    USHORT GeneratorId;     // ID of the entity that logged the event
    UCHAR EvmRevision;      // Event Message format revision
    UCHAR RecordType;       // SEL record type (e.g. system event vs OEM)
    UCHAR Data[4];          // Event-specific data bytes
} SYSTEM_WHEA_IPMI_HARDWARE_INFORMATION, *PSYSTEM_WHEA_IPMI_HARDWARE_INFORMATION;

// private
/**
 * The SYSTEM_SHADOW_STACK_INFORMATION structure contains hardware-enforced shadow stack (CET) capability and
 * enablement flags for user and kernel mode.
 */
typedef struct _SYSTEM_SHADOW_STACK_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG CetCapable : 1;
            ULONG UserCetAllowed : 1;
            ULONG ReservedForUserCet : 6;
            ULONG KernelCetEnabled : 1;
            ULONG KernelCetAuditModeEnabled : 1;
            ULONG ReservedForKernelCet : 6; // since Windows 10 build 21387
            ULONG Reserved : 16;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} SYSTEM_SHADOW_STACK_INFORMATION, *PSYSTEM_SHADOW_STACK_INFORMATION;

// private
/**
 * The SYSTEM_SPACES_BOOT_INFORMATION structure contains system spaces boot information.
 */
typedef struct _SYSTEM_SPACES_BOOT_INFORMATION
{
    /**
     * Opaque variable-length blob copied from ExpSpacesBootInformation.
     *
     * The returned byte count is reported via ReturnLength.
     * NtQuerySystemInformationEx rejects user-mode callers for this class on this build.
     */
    UCHAR Data[1];
} SYSTEM_SPACES_BOOT_INFORMATION, *PSYSTEM_SPACES_BOOT_INFORMATION;

// private
/**
 * The SYSTEM_BUILD_VERSION_INFORMATION_INPUT structure specifies the input parameters for a system build version
 * information query.
 */
typedef struct _SYSTEM_BUILD_VERSION_INFORMATION_INPUT
{
    ULONG LayerNumber;
} SYSTEM_BUILD_VERSION_INFORMATION_INPUT, *PSYSTEM_BUILD_VERSION_INFORMATION_INPUT;

// private
/**
 * The SYSTEM_BUILD_VERSION_INFORMATION_FLAGS union defines the system build version information flags.
 */
typedef union _SYSTEM_BUILD_VERSION_INFORMATION_FLAGS
{
    ULONG Value32;
    struct
    {
        ULONG IsTopLevel : 1;
        ULONG IsChecked : 1;

        ULONG Reserved  : 1;
        ULONG HasMajorVersion : 1;  // MajorVersion present
        ULONG HasMinorVersion : 1;  // MinorVersion present
        ULONG HasBuildNumber  : 1;  // BuildNumber present
        ULONG HasBuildQfe     : 1;  // BuildQfe present
        ULONG HasString0 : 1;       // optional string #1 present
        ULONG HasString1 : 1;       // optional string #2 present
        ULONG HasString2 : 1;       // optional string #3 present
        ULONG HasString3 : 1;       // optional string #4 present
        ULONG HasString4 : 1;       // optional string #5 present
        ULONG Spare : 20;
    } DUMMYSTRUCTNAME;
} SYSTEM_BUILD_VERSION_INFORMATION_FLAGS, *PSYSTEM_BUILD_VERSION_INFORMATION_FLAGS;

// private
/**
 * The SYSTEM_BUILD_VERSION_INFORMATION structure contains system build version information.
 */
typedef struct _SYSTEM_BUILD_VERSION_INFORMATION
{
    USHORT LayerNumber;
    USHORT LayerCount;
    ULONG OsMajorVersion;
    ULONG OsMinorVersion;
    ULONG NtBuildNumber;
    ULONG NtBuildQfe;
    UCHAR LayerName[128];
    UCHAR NtBuildBranch[128];
    UCHAR NtBuildLab[128];
    UCHAR NtBuildLabEx[128];
    UCHAR NtBuildStamp[26];
    UCHAR NtBuildArch[16];
    SYSTEM_BUILD_VERSION_INFORMATION_FLAGS Flags;
} SYSTEM_BUILD_VERSION_INFORMATION, *PSYSTEM_BUILD_VERSION_INFORMATION;

// private
/**
 * The SYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION_INPUT structure specifies the input parameters for a system secure
 * kernel debugger information query.
 */
typedef struct _SYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION_INPUT
{
    ULONG Version;
    ULONG Reserved[3];
    ULONG MinimumImageVersion;
} SYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION_INPUT, *PSYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION_INPUT;

// private
/**
 * The SYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION structure contains system secure kernel debugger information.
 */
typedef struct _SYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION
{
    ULONG Version;
    BOOLEAN Enabled;
} SYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_SECURE_KERNEL_DEBUGGER_INFORMATION;

// private
/**
 * The SYSTEM_POOL_LIMIT_MEM_INFO structure contains system pool limit mem information.
 */
typedef struct _SYSTEM_POOL_LIMIT_MEM_INFO
{
    ULONGLONG MemoryLimit;
    ULONGLONG NotificationLimit;
} SYSTEM_POOL_LIMIT_MEM_INFO, *PSYSTEM_POOL_LIMIT_MEM_INFO;

// private
/**
 * The SYSTEM_POOL_LIMIT_INFO structure contains system pool limit information.
 */
typedef struct _SYSTEM_POOL_LIMIT_INFO
{
    ULONG PoolTag;
    SYSTEM_POOL_LIMIT_MEM_INFO MemLimits[2];
    WNF_STATE_NAME NotificationHandle;
} SYSTEM_POOL_LIMIT_INFO, *PSYSTEM_POOL_LIMIT_INFO;

// private
/**
 * The SYSTEM_POOL_LIMIT_INFORMATION structure contains system pool limit information.
 */
typedef struct _SYSTEM_POOL_LIMIT_INFORMATION
{
    ULONG Version;
    ULONG EntryCount;
    _Field_size_(EntryCount) SYSTEM_POOL_LIMIT_INFO LimitEntries[1];
} SYSTEM_POOL_LIMIT_INFORMATION, *PSYSTEM_POOL_LIMIT_INFORMATION;

// rev
/**
 * The SYSTEM_CODE_INTEGRITY_DYNAMIC_STORE structure describes the Code Integrity dynamic policy store.
 */
typedef struct _SYSTEM_CODE_INTEGRITY_DYNAMIC_STORE
{
    HANDLE StoreHandle;
    ULONG StoreFlags;
    PVOID StoreData;
    SIZE_T StoreSize;
} SYSTEM_CODE_INTEGRITY_DYNAMIC_STORE, *PSYSTEM_CODE_INTEGRITY_DYNAMIC_STORE;

// private
//typedef struct _SYSTEM_POOL_ZEROING_INFORMATION
//{
//    BOOLEAN PoolZeroingSupportPresent;
//} SYSTEM_POOL_ZEROING_INFORMATION, *PSYSTEM_POOL_ZEROING_INFORMATION;

// private
/**
 * The HV_MINROOT_NUMA_LPS structure describes the HV minroot NUMA lps.
 */
typedef struct _HV_MINROOT_NUMA_LPS
{
    ULONG NodeIndex;
    ULONG_PTR Mask[16];
} HV_MINROOT_NUMA_LPS, *PHV_MINROOT_NUMA_LPS;

// private
/**
 * The SYSTEM_XFG_FAILURE_INFORMATION structure contains system XFG failure information.
 */
typedef struct _SYSTEM_XFG_FAILURE_INFORMATION
{
    PVOID ReturnAddress;
    PVOID TargetAddress;
    ULONG DispatchMode;
    ULONGLONG XfgValue;
} SYSTEM_XFG_FAILURE_INFORMATION, *PSYSTEM_XFG_FAILURE_INFORMATION;

// private
/**
 * The SYSTEM_IOMMU_STATE enumeration defines the possible system IOMMU states.
 */
typedef enum _SYSTEM_IOMMU_STATE
{
    IommuStateBlock,
    IommuStateUnblock
} SYSTEM_IOMMU_STATE;

// private
/**
 * The SYSTEM_IOMMU_STATE_INFORMATION structure contains system IOMMU state information.
 */
typedef struct _SYSTEM_IOMMU_STATE_INFORMATION
{
    SYSTEM_IOMMU_STATE State;
    PVOID Pdo;
} SYSTEM_IOMMU_STATE_INFORMATION, *PSYSTEM_IOMMU_STATE_INFORMATION;

// private
/**
 * The SYSTEM_HYPERVISOR_MINROOT_INFORMATION structure contains system hypervisor minroot information.
 */
typedef struct _SYSTEM_HYPERVISOR_MINROOT_INFORMATION
{
    ULONG NumProc;
    ULONG RootProc;
    ULONG RootProcNumaNodesSpecified;
    USHORT RootProcNumaNodes[64];
    ULONG RootProcPerCore;
    ULONG RootProcPerNode;
    ULONG RootProcNumaNodesLpsSpecified;
    HV_MINROOT_NUMA_LPS RootProcNumaNodeLps[64];
} SYSTEM_HYPERVISOR_MINROOT_INFORMATION, *PSYSTEM_HYPERVISOR_MINROOT_INFORMATION;

// private
/**
 * The SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION structure contains system hypervisor boot pages information.
 */
typedef struct _SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
{
    ULONG RangeCount;
    ULONG_PTR RangeArray[1];
} SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION, *PSYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION;

// private
/**
 * The SYSTEM_POINTER_AUTH_INFORMATION structure contains system pointer auth information.
 */
typedef struct _SYSTEM_POINTER_AUTH_INFORMATION
{
    union
    {
        USHORT SupportedFlags;
        struct
        {
            USHORT AddressAuthSupported : 1;
            USHORT AddressAuthQarma : 1;
            USHORT GenericAuthSupported : 1;
            USHORT GenericAuthQarma : 1;
            USHORT AddressAuthFaulting : 1;
            USHORT SupportedReserved : 11;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    union
    {
        USHORT EnabledFlags;
        struct
        {
            USHORT UserPerProcessIpAuthEnabled : 1;
            USHORT UserGlobalIpAuthEnabled : 1;
            USHORT UserEnabledReserved : 6;
            USHORT KernelIpAuthEnabled : 1;
            USHORT KernelEnabledReserved : 7;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME2;
} SYSTEM_POINTER_AUTH_INFORMATION, *PSYSTEM_POINTER_AUTH_INFORMATION;

// rev
#define SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_VERSION 1 // Current protocol version for input/output structures.

/**
 * Query interface for checking whether a named Windows feature flag is enabled for an image's
 * "born-on" Windows version — the OS version the image was originally built or linked against.
 * In observed logic, the decision is based on OriginalImageVersion for the image context plus the
 * caller-provided BornOnVersion. This is image-compat metadata, not simply current OS version.
 * A plain OS upgrade does not automatically guarantee the result flips to enabled for an existing
 * old image. It can become enabled if the relevant image/component is updated or replaced so its
 * original-image version context is newer and passes the threshold. The code path only reports
 * eligibility in FeatureIsEnabled and does not directly enable a feature system-wide.
 * So think of it as compatibility gating tied to image provenance, not a global switch that turns on when Windows version increases.
 */
typedef struct _SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT
{
    ULONG Version;       // Must be set to SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_VERSION (1).
    PWSTR FeatureName;   // Wide string naming the feature to query. Not consulted by the kernel in observed builds; reserved for future use.
    ULONG BornOnVersion; // Windows version number the image was originally targeted at; compared against OriginalImageVersion.
} SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, *PSYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT;

// private
/**
 * The SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT structure receives the output of a system original image
 * feature information query.
 */
typedef struct _SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT
{
    ULONG Version;           // Echoes back the protocol version.
    BOOLEAN FeatureIsEnabled; // Eligibility result only; TRUE/FALSE does not directly toggle a system-wide feature state.
} SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT, *PSYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT;

// private
/**
 * The SYSTEM_MEMORY_NUMA_INFORMATION_INPUT structure specifies the input parameters for a system memory NUMA
 * information query.
 */
typedef struct _SYSTEM_MEMORY_NUMA_INFORMATION_INPUT
{
    ULONG Version;
    ULONG TargetNodeNumber;
    ULONG Flags;
} SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, *PSYSTEM_MEMORY_NUMA_INFORMATION_INPUT;

// private
/**
 * The SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT structure receives the output of a system memory NUMA information query.
 */
typedef struct _SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT
{
    ULONG Version;
    ULONG Size;
    ULONG InitiatorNode;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG IsAttached : 1;
            ULONG Reserved : 31;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT, *PSYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT;

// private
/**
 * The SYSTEM_MEMORY_NUMA_PERFORMANCE_QUERY_DATA_TYPES enumeration defines the system memory NUMA performance query
 * data types values.
 */
typedef enum _SYSTEM_MEMORY_NUMA_PERFORMANCE_QUERY_DATA_TYPES
{
    SystemMemoryNumaPerformanceQuery_ReadLatency,
    SystemMemoryNumaPerformanceQuery_ReadBandwidth,
    SystemMemoryNumaPerformanceQuery_WriteLatency,
    SystemMemoryNumaPerformanceQuery_WriteBandwidth,
    SystemMemoryNumaPerformanceQuery_Latency,
    SystemMemoryNumaPerformanceQuery_Bandwidth,
    SystemMemoryNumaPerformanceQuery_AllDataTypes,
    SystemMemoryNumaPerformanceQuery_MaxDataType
} SYSTEM_MEMORY_NUMA_PERFORMANCE_QUERY_DATA_TYPES;

// private
/**
 * The SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT structure specifies the input parameters for a system memory
 * NUMA performance information query.
 */
typedef struct _SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT
{
    ULONG Version;
    ULONG TargetNodeNumber;
    SYSTEM_MEMORY_NUMA_PERFORMANCE_QUERY_DATA_TYPES QueryDataType;
    ULONG Flags;
} SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, *PSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT;

// private
/**
 * The SYSTEM_MEMORY_NUMA_PERFORMANCE_ENTRY structure describes a single system memory NUMA performance entry.
 */
typedef struct _SYSTEM_MEMORY_NUMA_PERFORMANCE_ENTRY
{
    ULONG InitiatorNodeNumber;
    ULONG TargetNodeNumber;
    SYSTEM_MEMORY_NUMA_PERFORMANCE_QUERY_DATA_TYPES DataType;
    union
    {
        BOOLEAN Flags;
        struct
        {
            BOOLEAN MinTransferSizeToAchieveValues : 1;
            BOOLEAN NonSequentialTransfers : 1;
            BOOLEAN Reserved : 6;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    SIZE_T MinTransferSizeInBytes;
    ULONG_PTR EntryValue;
} SYSTEM_MEMORY_NUMA_PERFORMANCE_ENTRY, *PSYSTEM_MEMORY_NUMA_PERFORMANCE_ENTRY;

// private
/**
 * The SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT structure receives the output of a system memory NUMA
 * performance information query.
 */
typedef struct _SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT
{
    ULONG Version;
    ULONG Size;
    ULONG EntryCount;
    SYSTEM_MEMORY_NUMA_PERFORMANCE_ENTRY PerformanceEntries[1];
} SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT, *PSYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT;

/**
 * The SYSTEM_OSL_RAMDISK_ENTRY structure describes a single RAM disk region
 * used by the operating system loader.
 */
typedef struct _SYSTEM_OSL_RAMDISK_ENTRY
{
    ULONG BlockSize;
    PVOID BaseAddress;
    SIZE_T Size;
} SYSTEM_OSL_RAMDISK_ENTRY, *PSYSTEM_OSL_RAMDISK_ENTRY;

// rev
/**
 * The SYSTEM_CODE_INTEGRITY_SIGNED_POLICIES structure describes the signed Code Integrity policies.
 */
typedef struct _SYSTEM_CODE_INTEGRITY_SIGNED_POLICIES
{
    BOOLEAN EnabledPolicies;
    ULONGLONG SignedPoliciesData;
    ULONG PolicySize;
    ULONG SignatureSize;
    UCHAR SignatureBuffer[0x100];
} SYSTEM_CODE_INTEGRITY_SIGNED_POLICIES, *PSYSTEM_CODE_INTEGRITY_SIGNED_POLICIES;

// rev
/**
 * The SYSTEM_SECURE_CORE_INFORMATION structure contains system secure core information.
 */
typedef struct _SYSTEM_SECURE_CORE_INFORMATION
{
    BOOLEAN IsSecureCore;
    ULONGLONG SecureKernelRunning;
    ULONGLONG VslFeatures;
} SYSTEM_SECURE_CORE_INFORMATION, *PSYSTEM_SECURE_CORE_INFORMATION;

/**
 * The SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION structure describes runtime
 * information related to Trusted Apps support.
 */
typedef struct _SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
{
    union
    {
        ULONGLONG Flags;
        struct
        {
            ULONGLONG Supported : 1;
            ULONGLONG Spare : 63;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    PVOID RemoteBreakingRoutine;
} SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION, *PSYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION;

/**
 * The SYSTEM_OSL_RAMDISK_INFORMATION structure describes a variable-length
 * array of RAM disk entries used by the operating system loader.
 */
typedef struct _SYSTEM_OSL_RAMDISK_INFORMATION
{
    ULONG Version;
    ULONG Count;
    SYSTEM_OSL_RAMDISK_ENTRY Entries[1];
} SYSTEM_OSL_RAMDISK_INFORMATION, *PSYSTEM_OSL_RAMDISK_INFORMATION;

/**
 * The SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION enumeration specifies the type of Code Integrity
 * policy management operation requested.
 */
typedef enum _SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION
{
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_NONE = 0,
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_OPEN_TX = 1,
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_COMMIT_TX = 2,
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_CLOSE_TX = 3,
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_ADD_POLICY = 4,
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_REMOVE_POLICY = 5,
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_GET_POLICY = 6,
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_GET_POLICY_IDS = 7,
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION_MAX = 8
} SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION;

/**
 * The SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT structure describes parameters
 * used to manage Code Integrity policies through the system information
 * interface.
 */
typedef struct _SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT
{
    SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT_OPERATION Operation;
    UCHAR UseInProgressState;
    ULONG Arg1Len;
    PUCHAR Arg1;
    ULONG Arg2Len;
    PUCHAR Arg2;
} SYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT, *PSYSTEM_CODEINTEGRITY_POLICY_MANAGEMENT;

// rev
/**
 * The SYSTEM_MEMORY_NUMA_CACHE_ENTRY structure describes a single system memory NUMA cache entry.
 */
typedef struct _SYSTEM_MEMORY_NUMA_CACHE_ENTRY
{
    ULONG CacheNode;
    ULONG CacheLevel;
    ULONG CacheSize;
    ULONG CacheLineSize;
    ULONG CacheType;
    ULONG CacheAttributes;
    ULONG CacheFlags;
    UCHAR Present;
    UCHAR Reserved[3];
} SYSTEM_MEMORY_NUMA_CACHE_ENTRY, *PSYSTEM_MEMORY_NUMA_CACHE_ENTRY;

// rev
/**
 * The SYSTEM_MEMORY_NUMA_CACHE_INFORMATION structure contains system memory NUMA cache information.
 */
typedef struct _SYSTEM_MEMORY_NUMA_CACHE_INFORMATION
{
    ULONG Version;        // always 1
    ULONG Size;           // total bytes written, aligned to 0x20
    ULONG EntryCount;     // number of cache entries
    ULONG Reserved;       // appears to stay zero
    SYSTEM_MEMORY_NUMA_CACHE_ENTRY Entries[1]; // Followed by EntryCount records, each 0x20 bytes
} SYSTEM_MEMORY_NUMA_CACHE_INFORMATION, *PSYSTEM_MEMORY_NUMA_CACHE_INFORMATION;

/**
 * The SYSTEM_REF_TRACE_INFORMATION_EX structure describes configuration
 * parameters for object reference tracing.
 */
typedef struct _SYSTEM_REF_TRACE_INFORMATION_EX
{
    ULONG Version;
    ULONGLONG MemoryLimits;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG TraceEnable        : 1;
            ULONG TracePermanent     : 1;
            ULONG UseTracePoolTags   : 1;
            ULONG TraceByStacksOnly  : 1;
            ULONG ReservedFlags      : 28;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    UNICODE_STRING TraceProcessName;
    UNICODE_STRING TracePoolTags;
    ULONG MaxObjectRefTraces;
    ULONG TracedObjectLimit;
} SYSTEM_REF_TRACE_INFORMATION_EX, *PSYSTEM_REF_TRACE_INFORMATION_EX;

/**
 * The SYSTEM_BASICPROCESS_INFORMATION structure describes basic process
 * information returned when enumerating processes.
 */
_Struct_size_bytes_(NextEntryOffset)
typedef struct _SYSTEM_BASICPROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG64 SequenceNumber;
    UNICODE_STRING ImageName;
} SYSTEM_BASICPROCESS_INFORMATION, *PSYSTEM_BASICPROCESS_INFORMATION;

/**
 * The SYSTEM_HANDLECOUNT_INFORMATION structure provides global counts of
 * processes, threads, and handles in the system.
 */
typedef struct _SYSTEM_HANDLECOUNT_INFORMATION
{
    ULONG ProcessCount;
    ULONG ThreadCount;
    ULONG HandleCount;
} SYSTEM_HANDLECOUNT_INFORMATION, *PSYSTEM_HANDLECOUNT_INFORMATION;

#define SYSTEM_RUNTIME_REPORT_INPUT_VERSION_1 1
#define SYSTEM_RUNTIME_REPORT_INPUT_PACKAGE_VERSION_1 1

/**
 * The SYSTEM_RUNTIME_REPORT_INPUT structure specifies the input parameters for a system runtime report query.
 */
typedef struct _SYSTEM_RUNTIME_REPORT_INPUT
{
    USHORT InputVersion;
    USHORT PackageVersion;
    ULONG Reserved;
    ULONG_PTR ReportTypesBitmap;
    UCHAR Nonce[32];
} SYSTEM_RUNTIME_REPORT_INPUT, *PSYSTEM_RUNTIME_REPORT_INPUT;

/**
 * The SYSTEM_POOLTAG2 structure describes allocation statistics for a single
 * pool tag, including paged and nonpaged usage.
 */
typedef struct _SYSTEM_POOLTAG2
{
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    } DUMMYUNIONNAME;
    SIZE_T PagedAllocs;
    SIZE_T PagedFrees;
    SIZE_T PagedUsed;
    SIZE_T NonPagedAllocs;
    SIZE_T NonPagedFrees;
    SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG2, *PSYSTEM_POOLTAG2;

/**
 * The SYSTEM_POOLTAG_INFORMATION2 structure describes a variable-length array
 * of SYSTEM_POOLTAG2 entries representing pool tag usage statistics.
 */
typedef struct _SYSTEM_POOLTAG_INFORMATION2
{
    ULONG Count;
    _Field_size_(Count) SYSTEM_POOLTAG2 TagInfo[ANYSIZE_ARRAY];
} SYSTEM_POOLTAG_INFORMATION2, *PSYSTEM_POOLTAG_INFORMATION2;

#pragma region Prefetch / Superfetch

/**
 * The PREFETCHER_INFORMATION_CLASS enumeration selects a Prefetcher query or control operation.
 */
typedef enum _PREFETCHER_INFORMATION_CLASS
{
    PrefetcherRetrieveTrace = 1,                // q: PF_RETRIEVE_TRACE
    PrefetcherSystemParameters,                 // q: PF_SYSTEM_PREFETCH_PARAMETERS
    PrefetcherBootPhase,                        // s: ULONG (0..4; user mode accepts only 2 on build 26100)
    PrefetcherSpare1, // Formerly PrefetcherRetrieveBootLoaderTrace; not implemented on build 26100
    PrefetcherOperationProcess,                 // s: PF_OPERATION_PROCESS
    PrefetcherCacheEntryUpdate,                 // s: PF_CACHE_ENTRY_UPDATE
    PrefetcherSpare2,                           // Reserved information class; not implemented on the verified build.
    PrefetcherAppLaunchScenarioControl,         // s: PF_APP_LAUNCH_SCENARIO_CONTROL
    PrefetcherInformationMax
} PREFETCHER_INFORMATION_CLASS;

#define PREFETCHER_INFORMATION_VERSION 1 // Current Prefetcher envelope version (1).
#define PREFETCHER_INFORMATION_VERSION_LEGACY 23 // Historical Prefetcher envelope version (23); rejected by the
// verified build.
#define PREFETCHER_INFORMATION_MAGIC ('kuhC') // Prefetcher envelope signature, 0x6b756843.

/**
 * The PREFETCHER_INFORMATION structure supplies the versioned envelope for Prefetcher system-information requests.
 */
typedef struct _PREFETCHER_INFORMATION
{
    _In_ ULONG Version;                         // Envelope version: PREFETCHER_INFORMATION_VERSION (1).
    _In_ ULONG Magic;                           // Envelope signature: PREFETCHER_INFORMATION_MAGIC.
    _In_ PREFETCHER_INFORMATION_CLASS PrefetcherInformationClass; // Operation and payload selector.
    _Inout_ PVOID PrefetcherInformation;        // Pointer to the class-specific input/output buffer.
    _Inout_ ULONG PrefetcherInformationLength;  // Size of the class-specific buffer, in bytes.
} PREFETCHER_INFORMATION, *PPREFETCHER_INFORMATION;

// rev
#define PF_RETRIEVE_TRACE_VERSION 31
#define PF_RETRIEVE_TRACE_MAGIC ('CCSA') // Trace signature, 0x43435341; stored as the bytes ASCC.

// rev
/**
 * The PF_RETRIEVE_TRACE_PAGE_ENTRY structure contains an opaque page record from a completed Prefetcher trace.
 */
typedef struct DECLSPEC_ALIGN(8) _PF_RETRIEVE_TRACE_PAGE_ENTRY
{
    UCHAR Data[16];                             // Opaque 16-byte page record.
} PF_RETRIEVE_TRACE_PAGE_ENTRY, *PPF_RETRIEVE_TRACE_PAGE_ENTRY;

// rev
/**
 * The PF_RETRIEVE_TRACE_SECTION_ENTRY structure contains an opaque section record from a completed Prefetcher trace.
 */
typedef struct DECLSPEC_ALIGN(8) _PF_RETRIEVE_TRACE_SECTION_ENTRY
{
    UCHAR Data[24];                             // Opaque 24-byte section record.
} PF_RETRIEVE_TRACE_SECTION_ENTRY, *PPF_RETRIEVE_TRACE_SECTION_ENTRY;

// rev
/**
 * The PF_RETRIEVE_TRACE structure describes the fixed header of a completed Prefetcher trace.
 */
typedef struct DECLSPEC_ALIGN(8) _PF_RETRIEVE_TRACE
{
    ULONG Version;                              // PF_RETRIEVE_TRACE_VERSION
    ULONG Magic;                                // PF_RETRIEVE_TRACE_MAGIC
    ULONG Size; // Total buffer size, including the variable payload that follows this header.
    ULONG Spare0;                               // Opaque trace state copied from the completed trace.
    UCHAR OpaqueHeader[0x40];                   // Opaque fixed fields copied from the completed trace.
    ULONG PageEntriesOffset; // Offset from the start of this structure to
    // PF_RETRIEVE_TRACE_PAGE_ENTRY[PageEntriesCount].
    ULONG PageEntriesCount;                     // Count of 16-byte PF_RETRIEVE_TRACE_PAGE_ENTRY records.
    ULONG TraceLimitsMaxNumPages;               // Page limit recorded for this trace.
    ULONG TraceLimitsMaxNumSections;            // Section limit recorded for this trace.
    ULONG SectionEntriesOffset; // Offset from the start of this structure to
    // PF_RETRIEVE_TRACE_SECTION_ENTRY[SectionEntriesCount].
    ULONG SectionEntriesCount;                  // Count of 24-byte PF_RETRIEVE_TRACE_SECTION_ENTRY records.
    UCHAR OpaqueTail[0x68]; // Fixed header size is 0xd0; page/section payloads follow at their offsets.
} PF_RETRIEVE_TRACE, *PPF_RETRIEVE_TRACE;

/**
 * The PF_ENABLE_STATUS enumeration specifies whether a Prefetcher scenario is enabled.
 */
typedef enum _PF_ENABLE_STATUS
{
    PfSvNotSpecified,                           // 0: No explicit enable setting.
    PfSvEnabled,                                // 1: Prefetching is enabled.
    PfSvDisabled,                               // 2: Prefetching is disabled.
    PfSvMaxEnableStatus                         // 3: Maximum sentinel; not an enable setting.
} PF_ENABLE_STATUS;

// rev
/**
 * The PF_TRACE_LIMITS structure specifies page, section and timer limits for a Prefetcher trace.
 */
typedef struct _PF_TRACE_LIMITS
{
    ULONG MaxNumPages;                          // Maximum number of pages recorded by the trace.
    ULONG MaxNumSections;                       // Maximum number of sections recorded by the trace.
    LONGLONG TimerPeriod;                       // Signed trace timer interval.
} PF_TRACE_LIMITS, *PPF_TRACE_LIMITS;

// rev
/**
 * The PF_SYSTEM_PREFETCH_PARAMETERS structure contains the parameters returned by PrefetcherSystemParameters.
 */
typedef struct _PF_SYSTEM_PREFETCH_PARAMETERS
{
    PF_ENABLE_STATUS EnableStatus[2];           // Enable settings for application-launch and activity scenarios.
    PF_TRACE_LIMITS TraceLimits[2];             // Trace limits for application-launch and activity scenarios.
    ULONG MaxNumActiveTraces;                   // Maximum number of simultaneously active traces.
    ULONG MaxNumSavedTraces;                    // Maximum number of saved traces.
    WCHAR RootDirPath[48];                      // Prefetch root directory, stored in a 48-WCHAR array.
    WCHAR HostingApplicationList[128];          // Hosting-application list, stored in a 128-WCHAR array.
    ULONG PrefetchFlags;                        // 0..31
    ULONG NumTracePeriods;                      // 1..10
} PF_SYSTEM_PREFETCH_PARAMETERS, *PPF_SYSTEM_PREFETCH_PARAMETERS;

// Legacy boot phase identifiers; not the 0..4 values accepted by the current PrefetcherBootPhase handler.
#define PF_SN_BOOT_PHASE_USER_SHELL_READY 2 // Current user-shell-ready phase (2); the only phase accepted from user
// mode on the verified build.
#define PF_SN_BOOT_PHASE_MAX 5 // Exclusive upper bound (5) for current Prefetcher boot phases.

/**
 * The PF_BOOT_PHASE_ID enumeration identifies historical Prefetcher boot milestones.
 */
typedef enum _PF_BOOT_PHASE_ID
{
    PfKernelInitPhase = 0,                      // Kernel initialization milestone (0).
    PfBootDriverInitPhase = 90,                 // Boot-driver initialization milestone (90).
    PfSystemDriverInitPhase = 120,              // System-driver initialization milestone (120).
    PfSessionManagerInitPhase = 150,            // Session Manager initialization milestone (150).
    PfSMRegistryInitPhase = 180,                // Session Manager registry milestone (180).
    PfVideoInitPhase = 210,                     // Video initialization milestone (210).
    PfPostVideoInitPhase = 240,                 // Post-video initialization milestone (240).
    PfBootAcceptedRegistryInitPhase = 270,      // Boot-accepted registry milestone (270).
    PfUserShellReadyPhase = 300,                // User-shell-ready milestone (300).
    PfMaxBootPhaseId = 900                      // Maximum legacy milestone identifier (900).
} PF_BOOT_PHASE_ID;

#define PF_SN_OPERATION_PROCESS_VERSION 1

/**
 * The PF_OPERATION_PROCESS_ACTION enumeration selects whether a process operation scenario begins or ends.
 */
typedef enum _PF_OPERATION_PROCESS_ACTION
{
    PfSnOpProcessBegin = 0,                     // 0: Begin an operation scenario.
    PfSnOpProcessEnd = 1,                       // 1: End an operation scenario.
    PfSnOpProcessMax = 2                        // 2: Maximum sentinel; not an operation.
} PF_OPERATION_PROCESS_ACTION;

/**
 * The PF_OPERATION_PROCESS structure starts or ends an operation scenario for the calling process.
 */
typedef struct _PF_OPERATION_PROCESS
{
    UCHAR Version;                              // Request version: PF_SN_OPERATION_PROCESS_VERSION (1).
    UCHAR Action;                               // PF_OPERATION_PROCESS_ACTION
    USHORT Reserved;                            // Must be zero.
    ULONG OpFlags;                              // Begin: 0..4 (bit 2 cannot be combined with bits 0..1); end: 0..1.
    ULONG Value;                                // Operation-specific value incorporated into the scenario identifier.
} PF_OPERATION_PROCESS, *PPF_OPERATION_PROCESS;

#define PF_BOOT_CONTROL_VERSION 1

/**
 * The PF_BOOT_CONTROL structure contains the legacy boot-prefetch control payload.
 */
typedef struct _PF_BOOT_CONTROL
{
    ULONG Version;                              // Legacy request version: PF_BOOT_CONTROL_VERSION (1).
    ULONG DisableBootPrefetching;               // Legacy boot-prefetch disable setting.
} PF_BOOT_CONTROL, *PPF_BOOT_CONTROL;

#define PF_CACHE_ENTRY_UPDATE_VERSION 2

/**
 * The PF_CACHE_ENTRY_UPDATE structure supplies an update to a Prefetcher cache entry.
 */
typedef struct _PF_CACHE_ENTRY_UPDATE
{
    ULONG Version;                              // Request version: PF_CACHE_ENTRY_UPDATE_VERSION (2).
    UCHAR Name[64];                             // Fixed 64-byte cache-entry identifier.
    ULONG NewValue;                             // Replacement value for the selected cache entry.
} PF_CACHE_ENTRY_UPDATE, *PPF_CACHE_ENTRY_UPDATE;

#define PF_APP_LAUNCH_SCENARIO_CONTROL_VERSION 1

/**
 * The PF_APP_LAUNCH_SCENARIO_CONTROL structure starts an application-launch scenario for a process.
 */
typedef struct _PF_APP_LAUNCH_SCENARIO_CONTROL
{
    ULONG Version;                              // Request version: PF_APP_LAUNCH_SCENARIO_CONTROL_VERSION (1).
    ULONG Enable;                               // Must be nonzero; zero does not disable the scenario.
    HANDLE ProcessHandle;                       // Handle to the process whose application-launch scenario is started.
} PF_APP_LAUNCH_SCENARIO_CONTROL, *PPF_APP_LAUNCH_SCENARIO_CONTROL;

//
// Superfetch
//

// rev
/**
 * The SUPERFETCH_INFORMATION_CLASS enumeration selects a Superfetch query or control operation.
 */
typedef enum _SUPERFETCH_INFORMATION_CLASS
{
    SuperfetchRetrieveTrace = 1,                // q: PF_SYSTEM_SUPERFETCH_RETRIEVE_TRACE // PfGetCompletedTrace
    SuperfetchSystemParameters,                 // q: PF_SYSTEM_SUPERFETCH_PARAMETERS
    SuperfetchLogEvent,                         // s: PF_LOG_EVENT_DATA
    SuperfetchGenerateTrace,                    // s: PF_GENERATE_TRACE_CONTROL
    SuperfetchPrefetch,                         // s: PF_PREFETCH_REQUEST
    SuperfetchPfnQuery,                         // q: PF_PFN_PRIO_REQUEST
    SuperfetchPfnSetPriority,                   // s: PF_PFN_PRIO_REQUEST // MmSetPfnListInfo
    SuperfetchPrivSourceQuery,                  // q: PF_PRIVSOURCE_QUERY_REQUEST
    SuperfetchSequenceNumberQuery,              // q: PF_SEQUENCENUMBER_QUERY_REQUEST
    SuperfetchScenarioPhase,                    // s: PF_SCENARIO_PHASE_INFO // 10
    SuperfetchWorkerPriority,                   // s: PF_WORKER_PRIORITY_CONTROL
    SuperfetchScenarioQuery,                    // q: PF_SCENARIO_QUERY_INFO
    SuperfetchScenarioPrefetch,                 // s: PF_SCENARIO_PREFETCH_INFO
    SuperfetchRobustnessControl,                // s: PF_ROBUSTNESS_CONTROL
    SuperfetchTimeControl,                      // s: PF_TIME_CONTROL
    SuperfetchMemoryListQuery,                  // q: PF_MEMORY_LIST_INFO
    SuperfetchMemoryRangesQuery,                // q: PF_PHYSICAL_MEMORY_RANGE_INFO_V2 (V1 on older systems)
    SuperfetchTracingControl,                   // s: PF_ACCESS_TRACING_CONTROL
    SuperfetchTrimWhileAgingControl,            // s: PF_TRIM_WHILE_AGING_CONTROL_3
    SuperfetchRepurposedByPrefetch,             // q: PF_REPURPOSED_BY_PREFETCH_INFO // 20
    SuperfetchChannelPowerRequest,              // q: not implemented
    SuperfetchMovePages,                        // s: PF_PFN_PRIO_REQUEST // MmRelocatePfnList
    SuperfetchVirtualQuery,                     // q: PF_VIRTUAL_QUERY
    SuperfetchCombineStatsQuery,                // q: PF_PAGECOMBINE_AGGREGATE_STAT
    SuperfetchSetMinWsAgeRate,                  // s: PF_MIN_WS_AGE_RATE_CONTROL
    SuperfetchDeprioritizeOldPagesInWs,         // s: PF_DEPRIORITIZE_OLD_PAGES
    SuperfetchFileExtentsQuery,                 // q: PF_FILE_EXTENTS_INFO_V2
    SuperfetchGpuUtilizationQuery,              // q: PF_GPU_UTILIZATION_INFO
    SuperfetchPfnSet,                           // s: PF_PFN_PRIO_REQUEST // since WIN11
    SuperfetchInformationMax
} SUPERFETCH_INFORMATION_CLASS;

#define SUPERFETCH_INFORMATION_VERSION 45
#define SUPERFETCH_INFORMATION_MAGIC ('kuhC')

/**
 * The SUPERFETCH_INFORMATION structure supplies the versioned envelope for Superfetch system-information requests.
 */
typedef struct _SUPERFETCH_INFORMATION
{
    _In_ ULONG Version;                         // Envelope version: SUPERFETCH_INFORMATION_VERSION (45).
    _In_ ULONG Magic;                           // Envelope signature: SUPERFETCH_INFORMATION_MAGIC.
    _In_ SUPERFETCH_INFORMATION_CLASS SuperfetchInformationClass; // Operation and payload selector.
    _Inout_ PVOID SuperfetchInformation;        // Pointer to the class-specific input/output buffer.
    _Inout_ ULONG SuperfetchInformationLength;  // Size of the class-specific buffer, in bytes.
} SUPERFETCH_INFORMATION, *PSUPERFETCH_INFORMATION;

#define PF_SYSTEM_SUPERFETCH_RETRIEVE_TRACE_VERSION 2

/**
 * The PF_SYSTEM_SUPERFETCH_RETRIEVE_TRACE structure provides the input and output envelope for a completed Superfetch
 * trace.
 */
typedef struct _PF_SYSTEM_SUPERFETCH_RETRIEVE_TRACE
{
    union
    {
        struct
        {
            ULONGLONG RequestType;              // Low USHORT is PF_SYSTEM_SUPERFETCH_RETRIEVE_TRACE_VERSION.
            ULONGLONG Reserved;                 // Ignored on input
            HANDLE PartitionHandle;             // Partition handle supplied on input and preserved on output.
        } Input;
        struct
        {
            ULONGLONG TypeFlags;                // 0x0000000000180002 on success
            ULONGLONG Timestamp;                // Scaled shared-user-data tick count.
            HANDLE PartitionHandle;             // Partition handle supplied on input and preserved on output.
        } Output;

        //
        // Raw view of the buffer for opaque access
        //
        UCHAR Buffer[ANYSIZE_ARRAY]; // Raw view of the envelope; additional storage is required for the trailing trace
        // dump.
    };
} PF_SYSTEM_SUPERFETCH_RETRIEVE_TRACE, *PPF_SYSTEM_SUPERFETCH_RETRIEVE_TRACE;

// rev
/**
 * The PF_SYSTEM_SUPERFETCH_PARAMETERS structure contains the parameters returned by SuperfetchSystemParameters.
 */
typedef struct _PF_SYSTEM_SUPERFETCH_PARAMETERS
{
    ULONG EnabledComponents;                    // Bitmask of enabled Superfetch components.
    ULONG BootID;                               // Boot identifier associated with the Superfetch state.
    ULONG SavedSectInfoTracesMax;               // Maximum number of saved section-information traces.
    ULONG SavedPageAccessTracesMax;             // Maximum number of saved page-access traces.
    ULONG ScenarioPrefetchTimeoutStandby;       // Configured standby-scenario prefetch timeout.
    ULONG ScenarioPrefetchTimeoutHibernate;     // Configured hibernation-scenario prefetch timeout.
    ULONG ScenarioPrefetchTimeoutHiberBoot;     // Configured hybrid-boot-scenario prefetch timeout.
} PF_SYSTEM_SUPERFETCH_PARAMETERS, *PPF_SYSTEM_SUPERFETCH_PARAMETERS;

#define PF_GENERATE_TRACE_CONTROL_VERSION 1

/**
 * The PF_GENERATE_TRACE_CONTROL structure requests trace generation for a Superfetch partition.
 */
typedef struct _PF_GENERATE_TRACE_CONTROL
{
    ULONG Version;                              // PF_GENERATE_TRACE_CONTROL_VERSION
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    HANDLE PartitionHandle;                     // Handle identifying the partition whose trace is generated.
} PF_GENERATE_TRACE_CONTROL, *PPF_GENERATE_TRACE_CONTROL;

// rev
/**
 * The PF_PREFETCH_RANGE structure describes a byte range to prefetch from a file or private-page source.
 */
typedef struct _PF_PREFETCH_RANGE
{
    ULONGLONG Offset;                           // File byte offset or virtual address, not a PFN.
    ULONG Length;                               // Nonzero byte count.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
} PF_PREFETCH_RANGE, *PPF_PREFETCH_RANGE;

// rev
/**
 * The PF_PREFETCH_RANGE_INFO structure locates a variable array of prefetch byte ranges.
 */
typedef struct _PF_PREFETCH_RANGE_INFO
{
    ULONG RangeCount;                           // Number of PF_PREFETCH_RANGE records.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    union
    {
        ULONGLONG RangesOffset;                 // Byte offset from PF_PREFETCH_REQUEST to the range array.
        PPF_PREFETCH_RANGE Ranges;              // Kernel-private patched view.
    };
} PF_PREFETCH_RANGE_INFO, *PPF_PREFETCH_RANGE_INFO;

// rev
/**
 * The PF_PREFETCH_PATH_INFO structure locates a NUL-terminated path within a prefetch request.
 */
typedef struct _PF_PREFETCH_PATH_INFO
{
    union
    {
        ULONGLONG PathOffset; // Byte offset from PF_PREFETCH_REQUEST to the NUL-terminated UTF-16 path.
        PWSTR Path;                             // Kernel-private patched view.
    };
    ULONG PathLength;                           // WCHAR count, excluding terminator; 1..0x7ffe when present.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
} PF_PREFETCH_PATH_INFO, *PPF_PREFETCH_PATH_INFO;

// rev
/**
 * The PF_PREFETCH_FILE_INFO structure describes a file and its ranges in a prefetch request.
 */
typedef struct _PF_PREFETCH_FILE_INFO
{
    ULONG Flags;                                // File-prefetch request/result flags.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    ULONGLONG FileIndexNumber;                  // File identifier used for metadata prefetch and file-ID opens.
    PF_PREFETCH_RANGE_INFO Ranges;              // Descriptor of the byte ranges to prefetch.
    union
    {
        ULONGLONG PathOffset;                   // Byte offset from PF_PREFETCH_REQUEST to the optional UTF-16 path.
        PWSTR Path;                             // Kernel-private patched view.
    };
    ULONG PathLength;                           // WCHAR count, excluding terminator; 1..0x7ffe when present.
    ULONG Reserved1;                            // Reserved field; initialize to zero and do not interpret on output.
} PF_PREFETCH_FILE_INFO, *PPF_PREFETCH_FILE_INFO;

// rev
/**
 * The PF_PREFETCH_VOLUME_INFO structure describes a volume and its file records in a prefetch request.
 */
typedef struct _PF_PREFETCH_VOLUME_INFO
{
    LARGE_INTEGER VolumeCreationTime;           // Volume creation time used to verify volume identity.
    ULONG VolumeSerialNumber;                   // Volume serial number used to verify volume identity.
    union
    {
        ULONG Flags;                            // Packed power-state flag (bit 0) and file count (bits 1..31).
        struct
        {
            ULONG CheckPowerState : 1;          // Requests a volume power-state check before prefetching.
            ULONG PrefetchFileCount : 31;       // Number of PF_PREFETCH_FILE_INFO records for the volume.
        };
    };
    union
    {
        ULONGLONG PrefetchFileInfoOffset;       // Byte offset from PF_PREFETCH_REQUEST to the file-record array.
        PPF_PREFETCH_FILE_INFO PrefetchFileInfo; // Kernel-private patched view.
    };
    ULONG VolumePathLength;                     // WCHAR count, excluding terminator; 1..0x7ffe.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    union
    {
        ULONGLONG VolumePathOffset;             // Byte offset from PF_PREFETCH_REQUEST to the UTF-16 volume path.
        PWSTR VolumePath;                       // Kernel-private patched view.
    };
} PF_PREFETCH_VOLUME_INFO, *PPF_PREFETCH_VOLUME_INFO;

// rev
/**
 * The PF_PREFETCH_SOURCE_INFO structure describes a kernel or process private-page prefetch source.
 */
typedef struct _PF_PREFETCH_SOURCE_INFO
{
    ULONG Type;                                 // PFS_PRIVATE_PAGE_SOURCE_TYPE: kernel (0) or process (2).
    ULONG ProcessId;                            // Process identifier when Type is PfsPrivateSourceProcess.
    ULONG ImagePathHash;                        // Image-path hash associated with the private-page source.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    ULONGLONG UniqueProcessHash;                // Zero or the process ID/create-time hash.
    PF_PREFETCH_RANGE_INFO RangeInfo;           // Descriptor of the source virtual-address byte ranges.
} PF_PREFETCH_SOURCE_INFO, *PPF_PREFETCH_SOURCE_INFO;

#define PF_PREFETCH_REQUEST_VERSION 13

/**
 * The PF_PREFETCH_REQUEST structure supplies a variable-length file and private-page prefetch request.
 */
typedef struct _PF_PREFETCH_REQUEST
{
    ULONG Version;                              // PF_PREFETCH_REQUEST_VERSION
    ULONG Size;                                 // Entire buffer size, including the 0x80-byte header (x64).
    ULONG VolumeCount;                          // Number of PF_PREFETCH_VOLUME_INFO records.
    ULONG PrefetchFileCount;                    // Total number of PF_PREFETCH_FILE_INFO records.
    ULONG RangeCount;                           // Number of PF_PREFETCH_RANGE records, not paths.
    ULONG SourceCount;                          // Number of PF_PREFETCH_SOURCE_INFO records.
    ULONG UnicodeTextSize;                      // Bytes.
    USHORT PrefetchPriority;                    // 0..7.
    USHORT VolumePrefetchPriority;              // 0..7.
    ULONG VolumeInfoOffset;                     // Byte offset to the volume records; zero when VolumeCount is zero.
    ULONG Reserved0;                            // Reserved field; initialize to zero and do not interpret on output.
    ULONG PrefetchFileInfoOffset;               // Byte offset to the file records; zero when PrefetchFileCount is zero.
    ULONG Reserved1;                            // Reserved field; initialize to zero and do not interpret on output.
    ULONG RangeInfoOffset; // Byte offset to PF_PREFETCH_RANGE records; zero when RangeCount is zero.
    ULONG Reserved2;                            // Reserved field; initialize to zero and do not interpret on output.
    ULONG SourceInfoOffset;                     // Byte offset to private-source records; zero when SourceCount is zero.
    ULONG Reserved3;                            // Reserved field; initialize to zero and do not interpret on output.
    ULONG UnicodeTextOffset; // Byte offset to the UTF-16 text area; zero when UnicodeTextSize is zero.
    ULONG Reserved4;                            // Reserved field; initialize to zero and do not interpret on output.
    HANDLE CompletionEvent; // Optional event handle; captured as an object in the kernel's private copy.
    union
    {
        ULONG Flags;                            // Packed request flags and scenario selector.
        struct
        {
            ULONG ContinueIO : 1;               // Bit 0: Continue-I/O flag retained from the reconstructed layout.
            ULONG LowPowerMode : 1;             // Bit 1: Low-power flag retained from the reconstructed layout.
            ULONG UseScenarioTimeouts : 1;      // Bit 2: Selects scenario-timeout and trickled-prefetch processing.
            ULONG OtherFlags : 3;               // Accepted bits whose semantics are not yet identified.
            ULONG ReservedFlags : 2;            // Must be zero.
            ULONG ScenarioType : 8;             // PF_PHASED_SCENARIO_TYPE, 0..5.
            ULONG Spare : 16;                   // Reserved field; initialize to zero and do not interpret on output.
        };
    };
    ULONG FilePrefetchCount;                    // Output count of files considered for prefetching.
    ULONG MetadataPrefetchCount;                // Output count of metadata prefetch operations.
    ULONG PrivatePrefetchCount;                 // Output count of private-source prefetch operations.
    ULONG FilePageCount;                        // Output page count for the first file-prefetch pass.
    ULONG FilePageCountSecondPass;              // Output page count for the second file-prefetch pass.
    ULONG PrivatePageCount;                     // Output count of private pages submitted for prefetching.
    ULONG MetadataPrefetchTime;                 // Milliseconds.
    ULONG FilePrefetchTime;                     // Milliseconds.
    ULONG FilePrefetchTimeSecondPass;           // Milliseconds.
    ULONG PrivatePrefetchTime;                  // Milliseconds.
    ULONG Reserved5;                            // Reserved field; initialize to zero and do not interpret on output.
} PF_PREFETCH_REQUEST, *PPF_PREFETCH_REQUEST;

// rev
/**
 * The PF_EVENT_TYPE enumeration identifies a Prefetcher or Superfetch event category.
 */
typedef enum _PF_EVENT_TYPE
{
    PfEventTypeImageLoad = 0,                   // 0: Image load.
    PfEventTypeAppLaunch = 1,                   // 1: Application launch.
    PfEventTypeStartTrace = 2,                  // 2: Trace start.
    PfEventTypeEndTrace = 3,                    // 3: Trace end.
    PfEventTypeTimestamp = 4,                   // 4: Timestamp.
    PfEventTypeOperation = 5,                   // 5: Operation.
    PfEventTypeRepurpose = 6,                   // 6: Page repurposing.
    PfEventTypeForegroundProcess = 7,           // 7: Foreground process.
    PfEventTypeTimeRange = 8,                   // 8: Time range.
    PfEventTypeUserInput = 9,                   // 9: User input.
    PfEventTypeFileAccess = 10,                 // 10: File access.
    PfEventTypeUnmap = 11,                      // 11: Unmap (legacy value).
    PfEventTypeUtilization = 11,                // 11: Utilization (shares the declared value 11).
    PfEventTypeMemInfo = 12,                    // 12: Memory information.
    PfEventTypeFileDelete = 13,                 // 13: File deletion.
    PfEventTypeAppExit = 14,                    // 14: Application exit.
    PfEventTypeSystemTime = 15,                 // 15: System time.
    PfEventTypePower = 16,                      // 16: Power.
    PfEventTypeSessionChange = 17,              // 17: Session change.
    PfEventTypeHardFaultTimeStamp = 18,         // 18: Hard-fault timestamp.
    PfEventTypeVirtualFree = 19,                // 19: Virtual memory free.
    PfEventTypePerfInfo = 20,                   // 20: Performance information.
    PfEventTypeProcessSnapshot = 21,            // 21: Process snapshot.
    PfEventTypeUserSnapshot = 22,               // 22: User snapshot.
    PfEventTypeStreamSequenceNumber = 23,       // 23: Stream sequence number.
    PfEventTypeFileTruncate = 24,               // 24: File truncation.
    PfEventTypeFileRename = 25,                 // 25: File rename.
    PfEventTypeFileCreate = 26,                 // 26: File creation.
    PfEventTypeAgCxContext = 27,                // 27: AgCx context.
    PfEventTypePowerAction = 28,                // 28: Power action.
    PfEventTypeHardFaultTS = 29,                // 29: Hard-fault TS.
    PfEventTypeRobustInfo = 30,                 // 30: Robustness information.
    PfEventTypeFileDefrag = 31,                 // 31: File defragmentation.
    PfEventTypeMax = 32                         // 32: Maximum sentinel; not an event.
} PF_EVENT_TYPE;

#define PF_LOG_EVENT_DATA_VERSION 1

/**
 * The PF_LOG_EVENT_DATA structure supplies an event payload for SuperfetchLogEvent.
 */
typedef struct _PF_LOG_EVENT_DATA
{
    ULONG Version;                              // PF_LOG_EVENT_DATA_VERSION
    union
    {
        ULONG Packed;                           // [31:7]=DataSize, [6:5]=Flags, [4:0]=EventType (PF_EVENT_TYPE)
        struct
        {
            ULONG EventType : 5;                // PF_EVENT_TYPE: 2, 3, 5 or 27.
            ULONG Flags : 2;                    // Two event-logging flag bits, packed at bits 5..6.
            ULONG DataSize : 25;                // Bytes; < 0xff0. Minimum: 36 for 2/3, 12 for 5, 16 for 27.
        };
    };
    HANDLE PartitionHandle;                     // Input partition handle at offset 8 on x64.
    PVOID EventData;                            // Pointer to the input event payload at offset 16 on x64.
} PF_LOG_EVENT_DATA, *PPF_LOG_EVENT_DATA;

/**
 * The PFN_TRIPLET structure contains a page-frame entry for a Superfetch PFN update or relocation.
 */
typedef struct _PFN_TRIPLET
{
    ULONGLONG MaskOrKey;                        // Compared against identity with 0x1FFFFFFFFFFFE00 mask
    ULONGLONG Pfn;                              // Page frame number
    ULONGLONG Flags;                            // Request/result flags
} PFN_TRIPLET, *PPFN_TRIPLET;

#define PF_PFN_PRIO_REQUEST_VERSION 1
#define PF_PFN_PRIO_REQUEST_QUERY_MEMORY_LIST 0x1 // Bit 0: Also request memory-list information with a PFN query.
#define PF_PFN_PRIO_REQUEST_VALID_FLAGS 0x1 // Valid request flag mask (0x1) for PFN query and priority classes 6 and 7.

/**
 * The PF_PFN_PRIO_REQUEST structure queries or updates a variable array of page-frame entries.
 */
typedef struct _PF_PFN_PRIO_REQUEST
{
    ULONG Version;                              // Request version: PF_PFN_PRIO_REQUEST_VERSION (1).
    ULONG RequestFlags; // Classes 6/7: bit 0 only; class 22 passes the low/high USHORTs to MmRelocatePfnList.
    SIZE_T PfnCount; // Nonzero; buffer size is FIELD_OFFSET(..., PageData) + PfnCount * sizeof(MMPFN_IDENTITY).
    SYSTEM_MEMORY_LIST_INFORMATION MemInfo;     // Memory-list statistics associated with the request.
    union
    {
        // Class 6: input PFNs, output identities. Class 16 uses PF_MEMORY_LIST_INFO instead.
        MMPFN_IDENTITY PageIdentities[256];     // Variable-length array with PfnCount entries.
        MMPFN_IDENTITY PageData[256];           // Compatibility name.
        // Classes 7, 22 and 29: caller-supplied entries; class 22 also copies results back.
        PFN_TRIPLET Entries[256]; // Variable array of PfnCount update or relocation entries; 256 is the declared
        // capacity, not a limit.
    };
} PF_PFN_PRIO_REQUEST, *PPF_PFN_PRIO_REQUEST;

/**
 * The PFS_PRIVATE_PAGE_SOURCE_TYPE enumeration identifies the kind of private-page source.
 */
typedef enum _PFS_PRIVATE_PAGE_SOURCE_TYPE
{
    PfsPrivateSourceKernel,                     // 0: Kernel private-page source.
    PfsPrivateSourceSession,                    // 1: Legacy session private-page source.
    PfsPrivateSourceProcess,                    // 2: Process private-page source.
    PfsPrivateSourceMax                         // 3: Maximum sentinel; not a source type.
} PFS_PRIVATE_PAGE_SOURCE_TYPE;

/**
 * The PFS_PRIVATE_PAGE_SOURCE structure identifies a private-page source and its process or session metadata.
 */
typedef struct _PFS_PRIVATE_PAGE_SOURCE
{
    PFS_PRIVATE_PAGE_SOURCE_TYPE Type;          // Source category selecting kernel, session or process interpretation.
    union
    {
        ULONG SessionId;                        // Session identifier for a session source.
        ULONG ProcessId;                        // Process identifier for a process source.
    };
    ULONG ImagePathHash;                        // Hash identifying the source image path.
    ULONG_PTR UniqueProcessHash;                // Hash derived from the process identifier and creation time.
} PFS_PRIVATE_PAGE_SOURCE, *PPFS_PRIVATE_PAGE_SOURCE;

/**
 * The PF_PRIVSOURCE_INFO structure contains identity and memory-use information for a private-page source.
 */
typedef struct _PF_PRIVSOURCE_INFO
{
    PFS_PRIVATE_PAGE_SOURCE DbInfo;             // Private-page source identity.
    union
    {
        PVOID EProcess;                         // Legacy name; NOT an EPROCESS address on build 26100.
        ULONG_PTR ProcessId;                    // Process ID, or 0xffffffff for the kernel entry.
    };
    SIZE_T WsPrivatePages;                      // Private pages resident in the source working set.
    SIZE_T TotalPrivatePages;                   // Total private-page count reported for the source.
    ULONG SessionID;                            // Session identifier associated with the source.
    UCHAR ImageName[16];                        // Short source image name in a 16-byte array.
    union
    {
        SIZE_T WsSwapPages; // Process working-set swap pages when PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_QUERYWSPAGES is
        // selected.
        SIZE_T SessionPagedPoolPages;           // Legacy session paged-pool page count.
        SIZE_T StoreSizePages; // Process store size, in pages, when
        // PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_QUERYCOMPRESSEDPAGES is selected.
    };
    SIZE_T WsTotalPages;                        // Total working-set page count for a process or legacy session source.
    ULONG DeepFreezeTimeMs;                     // Process freeze timestamp, in milliseconds, when DeepFrozen is set.
    ULONG ModernApp : 1;                        // Process has the application identity attribute checked by the kernel.
    ULONG DeepFrozen : 1; // Process only. If set, DeepFreezeTimeMs contains the time at which the freeze occurred.
    ULONG Foreground : 1;                       // Process is classified as foreground.
    ULONG PerProcessStore : 1;                  // Process has an associated memory store.
    ULONG HasVmContext : 1;                     // Process has a non-NULL VM context.
    ULONG Spare : 27;                           // Reserved field; initialize to zero and do not interpret on output.
} PF_PRIVSOURCE_INFO, *PPF_PRIVSOURCE_INFO;

// rev
#define PF_PRIVSOURCE_QUERY_REQUEST_VERSION 8
#define PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_QUERYWSPAGES 0x1 // Bit 0: Query process working-set swap-page counts.
#define PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_QUERYCOMPRESSEDPAGES 0x2 // Bit 1: Query process memory-store page counts.
#define PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_SKIPMINIMALPROCESSES 0x4 // Bit 2: Omit minimal processes from the
// enumeration.
#define PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_QUERYSKIPPAGES PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_SKIPMINIMALPROCESSES //
// Compatibility name for PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_SKIPMINIMALPROCESSES.
#define PF_PRIVSOURCE_QUERY_REQUEST_VALID_FLAGS 0x7 // Valid mask 0x7; QUERYWSPAGES and QUERYCOMPRESSEDPAGES are
// mutually exclusive.

// rev
/**
 * The PF_PRIVSOURCE_QUERY_REQUEST structure enumerates private-page sources and their memory-use information.
 */
typedef struct _PF_PRIVSOURCE_QUERY_REQUEST
{
    ULONG Version;                              // Request version: PF_PRIVSOURCE_QUERY_REQUEST_VERSION (8).
    ULONG Flags;                                // PF_PRIVSOURCE_QUERY_REQUEST_FLAGS_* options; valid mask 0x7.
    ULONG InfoCount;                            // Number of source records written to InfoArray.
    PF_PRIVSOURCE_INFO InfoArray[1]; // Variable array of returned source records; allocate using the required buffer
    // length.
} PF_PRIVSOURCE_QUERY_REQUEST, *PPF_PRIVSOURCE_QUERY_REQUEST;

// rev
/**
 * The PF_SEQUENCENUMBER_QUERY_REQUEST structure receives the Superfetch sequence number.
 */
typedef struct _PF_SEQUENCENUMBER_QUERY_REQUEST
{
    ULONG SequenceNumber;                       // Output sequence number.
} PF_SEQUENCENUMBER_QUERY_REQUEST, *PPF_SEQUENCENUMBER_QUERY_REQUEST;

// rev
/**
 * The PF_PHASED_SCENARIO_TYPE enumeration identifies a phased Superfetch scenario.
 */
typedef enum _PF_PHASED_SCENARIO_TYPE
{
    PfScenarioTypeNone,                         // 0: No active phased scenario.
    PfScenarioTypeStandby,                      // 1: Standby scenario.
    PfScenarioTypeHibernate,                    // 2: Hibernation scenario.
    PfScenarioTypeFUS,                          // 3: Fast user switching scenario.
    PfScenarioTypeBoot,                         // 4: Boot scenario.
    PfScenarioTypeHiberBoot,                    // 5: Hybrid boot scenario.
    PfScenarioTypeMax                           // 6: Maximum sentinel; not a scenario.
} PF_PHASED_SCENARIO_TYPE;

// rev
#define PF_SCENARIO_PHASE_INFO_VERSION 4

/**
 * The PF_SCENARIO_PHASE_INFO structure notifies Superfetch of a scenario phase transition.
 */
typedef struct _PF_SCENARIO_PHASE_INFO
{
    ULONG Version;                              // Request version: PF_SCENARIO_PHASE_INFO_VERSION (4).
    PF_PHASED_SCENARIO_TYPE ScenType;           // Scenario category, 1..5.
    ULONG PhaseId;                              // Scenario-specific phase identifier.
    ULONG SequenceNumber;                       // Scenario sequence-number field.
    ULONG Flags;                                // Scenario-specific phase flags.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    ULONGLONG FUSUserId;                        // Copied to/from the FUS scenario context at offset 0x18.
} PF_SCENARIO_PHASE_INFO, *PPF_SCENARIO_PHASE_INFO;

#define PF_WORKER_PRIORITY_CONTROL_VERSION 1

/**
 * The PF_WORKER_PRIORITY_CONTROL structure changes the trace worker priority for a Superfetch partition.
 */
typedef struct _PF_WORKER_PRIORITY_CONTROL
{
    ULONG Version;                              // Request version: PF_WORKER_PRIORITY_CONTROL_VERSION (1).
    KPRIORITY Priority; // 0..31; invalid priority or unavailable worker returns STATUS_TOO_LATE.
    HANDLE PartitionHandle;                     // Handle identifying the partition containing the trace worker.
} PF_WORKER_PRIORITY_CONTROL, *PPF_WORKER_PRIORITY_CONTROL;

// rev
#define PF_SCENARIO_QUERY_INFO_VERSION 4

/**
 * The PF_SCENARIO_QUERY_INFO structure receives the active Superfetch scenario and its sequence number.
 */
typedef struct _PF_SCENARIO_QUERY_INFO
{
    ULONG Version;                              // PF_SCENARIO_QUERY_INFO_VERSION
    PF_PHASED_SCENARIO_TYPE ScenType;           // Output active scenario category.
    ULONG Reserved0;                            // Reserved field; initialize to zero and do not interpret on output.
    ULONG SequenceNumber;                       // Output scenario sequence number.
    ULONG Reserved1;                            // Reserved field; initialize to zero and do not interpret on output.
    ULONG Reserved2;                            // Reserved field; initialize to zero and do not interpret on output.
    ULONGLONG FUSUserId;                        // Output only when ScenType == PfScenarioTypeFUS.
} PF_SCENARIO_QUERY_INFO, *PPF_SCENARIO_QUERY_INFO;

// rev
/**
 * The PF_MEMORY_LIST_NODE structure contains page counts for a memory-list node.
 */
typedef struct _PF_MEMORY_LIST_NODE
{
    ULONGLONG Node : 8;                         // Node identifier; the verified aggregate result uses 0.
    ULONGLONG Spare : 56;                       // Reserved field; initialize to zero and do not interpret on output.
    ULONGLONG StandbyLowPageCount;              // Pages on low-priority standby lists.
    ULONGLONG StandbyMediumPageCount;           // Pages on the medium-priority standby list.
    ULONGLONG StandbyHighPageCount;             // Pages on high-priority standby lists.
    ULONGLONG FreePageCount;                    // Combined zeroed and free-page count.
    ULONGLONG ModifiedPageCount;                // Combined modified-page count reported by the query.
} PF_MEMORY_LIST_NODE, *PPF_MEMORY_LIST_NODE;

// rev
/**
 * The PF_ROBUST_PROCESS_ENTRY structure identifies a process in a Superfetch robustness-control list.
 */
typedef struct _PF_ROBUST_PROCESS_ENTRY
{
    ULONG ImagePathHash;                        // Nonzero image-path hash.
    ULONG Pid;                                  // Process identifier associated with the hash.
} PF_ROBUST_PROCESS_ENTRY, *PPF_ROBUST_PROCESS_ENTRY;

// rev
/**
 * The PF_ROBUST_FILE_ENTRY structure identifies a file in a Superfetch robustness-control list.
 */
typedef struct _PF_ROBUST_FILE_ENTRY
{
    ULONGLONG FilePathHash;                     // Nonzero file-path hash.
} PF_ROBUST_FILE_ENTRY, *PPF_ROBUST_FILE_ENTRY;

// rev
/**
 * The PF_ROBUSTNESS_CONTROL_COMMAND enumeration selects a Superfetch robustness-control operation.
 */
typedef enum _PF_ROBUSTNESS_CONTROL_COMMAND
{
    PfRpControlUpdate = 0,                      // 0: Update the process and file lists.
    PfRpControlReset = 1,                       // 1: Reset the lists; all four entry counts must be zero.
    PfRpControlRobustAllStart = 2,              // 2: Start the robust-all mode.
    PfRpControlRobustAllStop = 3,               // 3: Stop the robust-all mode.
    PfRpControlCommandMax = 4                   // 4: Maximum sentinel; not a command.
} PF_ROBUSTNESS_CONTROL_COMMAND;

// rev
#define PF_ROBUSTNESS_CONTROL_VERSION 3

/**
 * The PF_ROBUSTNESS_CONTROL structure supplies process and file lists for Superfetch robustness control.
 */
typedef struct _PF_ROBUSTNESS_CONTROL
{
    union
    {
        ULONG VersionAndCommand;                // Packed version in bits 0..15 and command in bits 16..31.
        struct
        {
            USHORT Version;                     // PF_ROBUSTNESS_CONTROL_VERSION
            USHORT Command;                     // PF_ROBUSTNESS_CONTROL_COMMAND
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    ULONG DeprioProcessCount;                   // Number of deprioritized process entries.
    ULONG ExemptProcessCount;                   // Number of exempt process entries.
    ULONG DeprioFileCount;                      // Number of deprioritized file entries.
    ULONG ExemptFileCount;                      // Number of exempt file entries.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    //
    // Pass FIELD_OFFSET(PF_ROBUSTNESS_CONTROL, Buffer) + 8 * the sum of all four counts.
    // Variable-size payload:
    //   PF_ROBUST_PROCESS_ENTRY ProcessEntries[DeprioProcessCount + ExemptProcessCount];
    //   PF_ROBUST_FILE_ENTRY FileEntries[DeprioFileCount + ExemptFileCount];
    //
    UCHAR Buffer[ANYSIZE_ARRAY];                // Variable payload of process entries followed by file entries.
} PF_ROBUSTNESS_CONTROL, *PPF_ROBUSTNESS_CONTROL;

#define PF_SCENARIO_PREFETCH_INFO_VERSION 1

/**
 * The PF_SCENARIO_PREFETCH_INFO structure sets the prefetch state of the active Superfetch scenario.
 */
typedef struct _PF_SCENARIO_PREFETCH_INFO
{
    USHORT Version;                             // PF_SCENARIO_PREFETCH_INFO_VERSION
    USHORT Reserved;                            // Reserved field; initialize to zero and do not interpret on output.
    ULONG State;                                // 1..5.
} PF_SCENARIO_PREFETCH_INFO, *PPF_SCENARIO_PREFETCH_INFO;

// rev
#define PF_TRIM_WHILE_AGING_CONTROL_VERSION_1 1

/**
 * The PF_TRIM_WHILE_AGING_STATE enumeration selects a trim-while-aging policy.
 */
typedef enum _PF_TRIM_WHILE_AGING_STATE
{
    PfTrimWhileAgingOff = 0,                    // 0: Disable trim-while-aging.
    PfTrimWhileAgingLowPriority = 1,            // 1: Select the low-priority policy.
    PfTrimWhileAgingPassive = 2,                // 2: Select the passive policy.
    PfTrimWhileAgingNormal = 3,                 // 3: Select the normal policy.
    PfTrimWhileAgingAggressive = 4,             // 4: Select the aggressive policy.
    PfTrimWhileAgingCustom = 5,                 // 5: Use explicit high and low thresholds in the version-3 request.
    PfTrimWhileAgingMax = 6                     // 6: Maximum sentinel; not a policy.
} PF_TRIM_WHILE_AGING_STATE, *PPF_TRIM_WHILE_AGING_STATE;

// rev
/**
 * The PF_TRIM_WHILE_AGING_CONTROL_1 structure contains the legacy version-1 trim-while-aging request.
 */
typedef struct _PF_TRIM_WHILE_AGING_CONTROL_1
{
    ULONG Version;                              // Legacy version: PF_TRIM_WHILE_AGING_CONTROL_VERSION_1 (1).
    PF_TRIM_WHILE_AGING_STATE TrimWhileAgingState; // Legacy trim-while-aging policy selector.
    BOOLEAN PrivatePageTrimAge;                 // Private-page age field in the legacy layout.
    BOOLEAN SharedPageTrimAge;                  // Shared-page age field in the legacy layout.
    USHORT Spare;                               // Reserved field; initialize to zero and do not interpret on output.
} PF_TRIM_WHILE_AGING_CONTROL_1, *PPF_TRIM_WHILE_AGING_CONTROL_1;

#define PF_TRIM_WHILE_AGING_CONTROL_VERSION_2 2

/**
 * The PF_TRIM_WHILE_AGING_CONTROL_2 structure contains the legacy version-2 trim-while-aging request.
 */
typedef struct _PF_TRIM_WHILE_AGING_CONTROL_2
{
    ULONG Version;                              // Legacy version: PF_TRIM_WHILE_AGING_CONTROL_VERSION_2 (2).
    PF_TRIM_WHILE_AGING_STATE TrimWhileAgingState; // Legacy trim-while-aging policy selector.
    UCHAR PrivatePageTrimAge;                   // 0..7
    UCHAR SharedPageTrimAge;                    // 0..7
    USHORT Spare;                               // Must be 0
} PF_TRIM_WHILE_AGING_CONTROL_2, *PPF_TRIM_WHILE_AGING_CONTROL_2;

#define PF_TRIM_WHILE_AGING_CONTROL_VERSION_3 3

/**
 * The PF_TRIM_WHILE_AGING_CONTROL_3 structure sets trim-while-aging policy and optional custom thresholds.
 */
typedef struct _PF_TRIM_WHILE_AGING_CONTROL_3
{
    ULONG Version;                              // PF_TRIM_WHILE_AGING_CONTROL_VERSION_3
    PF_TRIM_WHILE_AGING_STATE TrimWhileAgingState; // Policy selector, 0..5; custom thresholds apply only to state 5.
    UCHAR PrivatePageTrimAge;                   // 0..7.
    UCHAR SharedPageTrimAge;                    // 0..7.
    USHORT Spare;                               // Must be zero.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    SIZE_T CustomHighThreshold;                 // Custom: nonzero and greater than CustomLowThreshold.
    SIZE_T CustomLowThreshold;                  // Both thresholds must be zero for states 0..4.
} PF_TRIM_WHILE_AGING_CONTROL_3, *PPF_TRIM_WHILE_AGING_CONTROL_3;

// rev
/**
 * The PF_TIME_CONTROL structure adjusts the Superfetch base-time value.
 */
typedef struct _PF_TIME_CONTROL
{
    LONG TimeAdjustment;                        // Signed adjustment added to the Superfetch base-time value.
} PF_TIME_CONTROL, *PPF_TIME_CONTROL;

#define PF_MEMORY_LIST_INFO_VERSION 1

/**
 * The PF_MEMORY_LIST_INFO structure receives a variable array of memory-list node statistics.
 */
typedef struct _PF_MEMORY_LIST_INFO
{
    ULONG Version;                              // Output format version: PF_MEMORY_LIST_INFO_VERSION (1).
    ULONG Size;                                 // Output size in bytes; 64 on the verified x64 build.
    ULONG NodeCount;                            // Number of returned node records; 1 on the verified build.
    PF_MEMORY_LIST_NODE Nodes[1];               // Variable array of NodeCount memory-list records.
} PF_MEMORY_LIST_INFO, *PPF_MEMORY_LIST_INFO;

/**
 * The PF_PHYSICAL_MEMORY_RANGE structure describes a contiguous physical-memory range in page-frame units.
 */
typedef struct _PF_PHYSICAL_MEMORY_RANGE
{
    ULONG_PTR BasePfn;                          // First page-frame number in the physical range.
    ULONG_PTR PageCount;                        // Number of consecutive pages in the range.
} PF_PHYSICAL_MEMORY_RANGE, *PPF_PHYSICAL_MEMORY_RANGE;

#define PF_PHYSICAL_MEMORY_RANGE_INFO_V1_VERSION 1

/**
 * The PF_PHYSICAL_MEMORY_RANGE_INFO_V1 structure contains the legacy version-1 physical-memory range query.
 */
typedef struct _PF_PHYSICAL_MEMORY_RANGE_INFO_V1
{
    ULONG Version;                              // Legacy version: PF_PHYSICAL_MEMORY_RANGE_INFO_V1_VERSION (1).
    ULONG RangeCount;                           // Number of physical-memory range records.
    PF_PHYSICAL_MEMORY_RANGE Ranges[1];         // Variable array containing RangeCount physical-memory ranges.
} PF_PHYSICAL_MEMORY_RANGE_INFO_V1, *PPF_PHYSICAL_MEMORY_RANGE_INFO_V1;

#define PF_PHYSICAL_MEMORY_RANGE_INFO_V2_VERSION 2
#define PF_PHYSICAL_MEMORY_RANGE_INFO_V2_VALID_FLAGS 0x1 // Valid physical-range query flag mask (0x1).

/**
 * The PF_PHYSICAL_MEMORY_RANGE_INFO_V2 structure receives physical-memory ranges from SuperfetchMemoryRangesQuery.
 */
typedef struct _PF_PHYSICAL_MEMORY_RANGE_INFO_V2
{
    ULONG Version;                              // Request version: PF_PHYSICAL_MEMORY_RANGE_INFO_V2_VERSION (2).
    ULONG Flags;                                // Query flags; only bit 0 is accepted.
    ULONG RangeCount;                           // The kernel writes only 32 bits.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    PF_PHYSICAL_MEMORY_RANGE Ranges[1];         // Variable array containing RangeCount returned physical-memory ranges.
} PF_PHYSICAL_MEMORY_RANGE_INFO_V2, *PPF_PHYSICAL_MEMORY_RANGE_INFO_V2;

// rev
/**
 * The PF_START_TRACE_CONTROL structure contains the version-3 access-tracing control layout.
 */
typedef struct _PF_START_TRACE_CONTROL
{
    ULONG Version;                              // Request version: PF_ACCESS_TRACING_CONTROL_VERSION (3).
    ULONG Type;                                 // Operation: 0 enables selected tracing flags; 1 removes them.
    ULONG Flags;                                // Selected tracing flags; valid mask 0x3.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    HANDLE PartitionHandle;                     // Input handle identifying the tracing partition.
    HANDLE TraceHandle; // Must be NULL on input for Type 0; receives the trace handle on success.
} PF_START_TRACE_CONTROL, *PPF_START_TRACE_CONTROL;

// rev
#define PF_ACCESS_TRACING_CONTROL_VERSION 3

/**
 * The PF_ACCESS_TRACING_CONTROL structure controls access tracing for a Superfetch partition.
 */
typedef struct _PF_ACCESS_TRACING_CONTROL
{
    ULONG Version;                              // Request version: PF_ACCESS_TRACING_CONTROL_VERSION (3).
    ULONG Type;                                 // Operation: 0 enables selected tracing flags; 1 removes them.
    ULONG Flags;                                // Selected tracing flags; valid mask 0x3.
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    HANDLE PartitionHandle;                     // Input handle identifying the tracing partition.
    HANDLE TraceHandle; // Must be NULL on input for Type 0; receives the trace handle on success.
} PF_ACCESS_TRACING_CONTROL, *PPF_ACCESS_TRACING_CONTROL;

// rev
#define PF_REPURPOSED_BY_PREFETCH_INFO_VERSION 1

/**
 * The PF_REPURPOSED_BY_PREFETCH_INFO structure receives the count of pages repurposed by prefetching.
 */
typedef struct _PF_REPURPOSED_BY_PREFETCH_INFO
{
    ULONG Version;                              // PF_REPURPOSED_BY_PREFETCH_INFO_VERSION
    ULONG Reserved;                             // Reserved field; initialize to zero and do not interpret on output.
    SIZE_T RepurposedByPrefetch;                // Output count of pages repurposed by prefetching.
} PF_REPURPOSED_BY_PREFETCH_INFO, *PPF_REPURPOSED_BY_PREFETCH_INFO;

// rev
#define PF_VIRTUAL_QUERY_VERSION 1

/**
 * The PF_VIRTUAL_QUERY structure queries extended working-set information for a process.
 */
typedef struct _PF_VIRTUAL_QUERY
{
    ULONG Version;                              // Request version: PF_VIRTUAL_QUERY_VERSION (1).
    union
    {
        ULONG Flags;                            // Mutually exclusive page-table options; valid mask 0x3.
        struct
        {
            ULONG FaultInPageTables : 1;        // Fault page-table state in for the queried user VAs.
            ULONG ReportPageTables : 1; // Report page-table-related state for the queried user VAs in the returned
            // MEMORY_WORKING_SET_EX_INFORMATION entries.
            ULONG Spare : 30;                   // Reserved field; initialize to zero and do not interpret on output.
        };
    };
    PVOID QueryBuffer; // MEMORY_WORKING_SET_EX_INFORMATION[NumberOfPages] (input: VirtualAddress[], output:
    // VirtualAttributes[])
    SIZE_T QueryBufferSize;                     // NumberOfPages * sizeof(MEMORY_WORKING_SET_EX_INFORMATION)
    HANDLE ProcessHandle;                       // Handle identifying the process whose working set is queried.
} PF_VIRTUAL_QUERY, *PPF_VIRTUAL_QUERY;

// rev
#define PF_PAGECOMBINE_AGGREGATE_STAT_VERSION 1

/**
 * The PF_PAGECOMBINE_AGGREGATE_STAT structure receives aggregate page-combining statistics.
 */
typedef struct _PF_PAGECOMBINE_AGGREGATE_STAT
{
    ULONG Version;                              // Request version: PF_PAGECOMBINE_AGGREGATE_STAT_VERSION (1).
    ULONG CombineScanCount;                     // Number of page-combining scans.
    ULONG CombinedBlocksInUse;                  // Number of combined blocks currently in use.
    ULONG SumCombinedBlocksReferenceCount;      // Sum of the reference counts of combined blocks.
} PF_PAGECOMBINE_AGGREGATE_STAT, *PPF_PAGECOMBINE_AGGREGATE_STAT;

// rev
#define PF_MIN_WS_AGE_RATE_CONTROL_VERSION 1

/**
 * The PF_MIN_WS_AGE_RATE_CONTROL structure sets the minimum working-set page-aging rate.
 */
typedef struct _PF_MIN_WS_AGE_RATE_CONTROL
{
    ULONG Version;                              // Request version: PF_MIN_WS_AGE_RATE_CONTROL_VERSION (1).
    ULONG SecondsToOldestAgeRate;               // Requested aging interval to the oldest age, in seconds.
} PF_MIN_WS_AGE_RATE_CONTROL, *PPF_MIN_WS_AGE_RATE_CONTROL;

// rev
#define PF_DEPRIORITIZE_OLD_PAGES_VERSION_3 3
#define PF_DEPRIORITIZE_OLD_PAGES_VERSION 4

/**
 * The PF_DEPRIORITIZE_OLD_PAGES_V3 structure contains the legacy version-3 working-set deprioritization request.
 */
typedef struct _PF_DEPRIORITIZE_OLD_PAGES_V3
{
    ULONG Version;                              // Legacy version: PF_DEPRIORITIZE_OLD_PAGES_VERSION_3 (3).
    HANDLE ProcessHandle;                       // Handle to the target process.
    union
    {
        ULONG Flags;                            // Legacy packed priority and trim options.
        struct
        {
            ULONG TargetPriority : 4;           // Legacy target page-priority field.
            ULONG TrimPages : 2;                // Legacy trim-control field.
            ULONG Spare : 26;                   // Reserved field; initialize to zero and do not interpret on output.
        };
    };
} PF_DEPRIORITIZE_OLD_PAGES_V3, *PPF_DEPRIORITIZE_OLD_PAGES_V3;

/**
 * The PF_DEPRIORITIZE_OLD_PAGES structure deprioritizes or trims old pages in a process working set.
 */
typedef struct _PF_DEPRIORITIZE_OLD_PAGES
{
    ULONG Version;                              // PF_DEPRIORITIZE_OLD_PAGES_VERSION
    HANDLE ProcessHandle;                       // Requires PROCESS_SET_LIMITED_INFORMATION.
    union
    {
        ULONG Flags;                            // Packed priority, trim and age controls; valid mask 0x1ff.
        struct
        {
            ULONG TargetPriority : 4;           // 0..8; 8 requires nonzero TrimPages.
            ULONG TrimPages : 2;                // 0..2.
            ULONG Age : 3;                      // 0..7.
            ULONG Spare : 23;                   // Must be zero.
        };
    };
    SIZE_T NumberOfPages;                       // In: maximum pages (0 = unlimited); out: pages processed.
} PF_DEPRIORITIZE_OLD_PAGES, *PPF_DEPRIORITIZE_OLD_PAGES;

// rev
#define PF_FILE_EXTENTS_INFO_VERSION 1

/**
 * The PF_FILE_EXTENTS_INFO structure contains the legacy version-1 file-extents declaration.
 */
typedef struct _PF_FILE_EXTENTS_INFO
{
    ULONG Version;                              // Legacy version: PF_FILE_EXTENTS_INFO_VERSION (1).
    PWSTR FilePath;                             // Path pointer in the legacy declaration.
    ULONG FilePathSize;                         // File-path size field in the legacy declaration.
    ULONG VolumePathSize;                       // Volume-path size field in the legacy declaration.
    LARGE_INTEGER FileIndexNumber;              // File identifier in the legacy declaration.
    ULONG VolumeSerialNumber;                   // Volume serial number in the legacy declaration.
    RETRIEVAL_POINTERS_BUFFER ExtentsBuffer; // Inline retrieval-pointer buffer in the legacy declaration; not the
    // version-2 pointer field.
    ULONGLONG ExtentsBufferSize;                // Extent-buffer size field in the legacy declaration.
} PF_FILE_EXTENTS_INFO, *PPF_FILE_EXTENTS_INFO;

// rev
#define PF_FILE_EXTENTS_INFO_VERSION2 2

/**
 * The PF_FILE_EXTENTS_INFO_V2 structure queries file retrieval extents and volume identity.
 */
typedef struct _PF_FILE_EXTENTS_INFO_V2
{
    ULONG Version;                              // PF_FILE_EXTENTS_INFO_VERSION2
    ULONG Reserved0;                            // Reserved field; initialize to zero and do not interpret on output.
    PWSTR FilePath;                             // NUL-terminated native path.
    ULONG FilePathSize;                         // Bytes including NUL; even, 2..0x100000.
    ULONG VolumePathSize; // Even, nonzero byte offset of the backslash after the volume path; < FilePathSize.
    LARGE_INTEGER FileIndexNumber;              // Output for a file with no retrieval extents (STATUS_END_OF_FILE).
    ULONG VolumeSerialNumber;                   // Output.
    ULONG Reserved1;                            // Reserved field; initialize to zero and do not interpret on output.
    PRETRIEVAL_POINTERS_BUFFER ExtentsBuffer;   // Caller-owned output buffer, not an inline structure.
    ULONG ExtentsBufferSize; // In: capacity; out: required/returned bytes. Maximum allocation 0xa00000.
    ULONG Reserved2;                            // Reserved field; initialize to zero and do not interpret on output.
} PF_FILE_EXTENTS_INFO_V2, *PPF_FILE_EXTENTS_INFO_V2;

// rev
#define PF_GPU_UTILIZATION_INFO_VERSION 1

/**
 * The PF_GPU_UTILIZATION_INFO structure queries GPU time for a session.
 */
typedef struct _PF_GPU_UTILIZATION_INFO
{
    ULONG Version;                              // Request version: PF_GPU_UTILIZATION_INFO_VERSION (1).
    ULONG SessionId;                            // 0xffffffff selects the current process session.
    ULONGLONG GpuTime;                          // Output GPU-time value returned by the selected session callout.
} PF_GPU_UTILIZATION_INFO, *PPF_GPU_UTILIZATION_INFO;

#pragma endregion

#if !defined(_KERNEL_MODE)

_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

/**
 * The NtQuerySystemInformationEx routine queries information about the system.
 *
 * @param SystemInformationClass The type of information to be retrieved.
 * @param InputBuffer Pointer to a caller-allocated input buffer that contains class-specific information.
 * @param InputBufferLength The size of the buffer pointed to by InputBuffer.
 * @param SystemInformation A pointer to a buffer that receives the requested information.
 * @param SystemInformationLength The size of the buffer pointed to by SystemInformation.
 * @param ReturnLength A pointer to a variable that receives the size of the data returned in the buffer.
 * @return NTSTATUS Successful or errant status.
 * @see https://learn.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformationEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);
#endif

/**
 * The NtSetSystemInformation routine sets information about the system.
 *
 * @param SystemInformationClass The type of information to be set.
 * @param SystemInformation A pointer to a buffer that receives the requested information.
 * @param SystemInformationLength The size of the buffer pointed to by SystemInformation.
 * @return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetSystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _In_reads_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength
);

/**
 * The NtQueryLicenseValue routine retrieves a licensing-related value from the
 * system licensing database.
 *
 * \param ValueName A pointer to a UNICODE_STRING structure that contains the name of the license value to query.
 * \param Type An optional pointer that receives the type of the returned data.
 * \param Data An optional buffer that receives the value data.
 * \param DataSize The size, in bytes, of the buffer pointed to by Data.
 * \param ResultDataSize A pointer that receives the number of bytes required to store the complete value data.
 * \return NTSTATUS Successful or errant status.
 * \see https://learn.microsoft.com/en-us/windows/win32/api/slpublic/nf-slpublic-slquerylicensevaluefromapp
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryLicenseValue(
    _In_ PUNICODE_STRING ValueName,
    _Out_opt_ PULONG Type,
    _Out_writes_bytes_to_opt_(DataSize, *ResultDataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PULONG ResultDataSize);

EXTERN_C_END
