#pragma once

#include "../../MinDef.h"
#include "../Sync.h"
#include "../DataStructures/Bitmap.h"
#include "Process.h"
#include "../../Ps/JobInfo.h"

EXTERN_C_START

/* phnt & PDB & KNSoft.NDK */

typedef struct _LEAP_SECOND_DATA
{
    UCHAR Enabled;
    UCHAR Padding[3];
    ULONG Count;
    _Field_size_(Count) LARGE_INTEGER Data[ANYSIZE_ARRAY];
} LEAP_SECOND_DATA, *PLEAP_SECOND_DATA;

/**
 * The PEB_LDR_DATA structure contains information about the loaded modules for the process.
 * @sa https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
 */

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB_LDR_DATA64
{
    ULONG Length;
    BOOL Initialized;
    VOID* POINTER_64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    VOID* POINTER_64 EntryInProgress;
    BOOLEAN ShutdownInProgress;
    VOID* POINTER_64 ShutdownThreadId;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    BOOL Initialized;
    VOID* POINTER_32 SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    VOID* POINTER_32 EntryInProgress;
    BOOLEAN ShutdownInProgress;
    VOID* POINTER_32 ShutdownThreadId;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

// PEB->AppCompatFlags
#define KACF_OLDGETSHORTPATHNAME 0x00000001
#define KACF_VERSIONLIE_NOT_USED 0x00000002
#define KACF_GETTEMPPATH_NOT_USED 0x00000004
#define KACF_GETDISKFREESPACE 0x00000008
#define KACF_FTMFROMCURRENTAPT 0x00000020
#define KACF_DISALLOWORBINDINGCHANGES 0x00000040
#define KACF_OLE32VALIDATEPTRS 0x00000080
#define KACF_DISABLECICERO 0x00000100
#define KACF_OLE32ENABLEASYNCDOCFILE 0x00000200
#define KACF_OLE32ENABLELEGACYEXCEPTIONHANDLING 0x00000400
#define KACF_RPCDISABLENDRCLIENTHARDENING 0x00000800
#define KACF_RPCDISABLENDRMAYBENULL_SIZEIS 0x00001000
#define KACF_DISABLEALLDDEHACK_NOT_USED 0x00002000
#define KACF_RPCDISABLENDR61_RANGE 0x00004000
#define KACF_RPC32ENABLELEGACYEXCEPTIONHANDLING 0x00008000
#define KACF_OLE32DOCFILEUSELEGACYNTFSFLAGS 0x00010000
#define KACF_RPCDISABLENDRCONSTIIDCHECK 0x00020000
#define KACF_USERDISABLEFORWARDERPATCH 0x00040000
#define KACF_OLE32DISABLENEW_WMPAINT_DISPATCH 0x00100000
#define KACF_ADDRESTRICTEDSIDINCOINITIALIZESECURITY 0x00200000
#define KACF_ALLOCDEBUGINFOFORCRITSECTIONS 0x00400000
#define KACF_OLEAUT32ENABLEUNSAFELOADTYPELIBRELATIVE 0x00800000
#define KACF_ALLOWMAXIMIZEDWINDOWGAMMA 0x01000000
#define KACF_DONOTADDTOCACHE 0x80000000

// PEB->ApiSetMap
typedef struct _API_SET_NAMESPACE
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _API_SET_HASH_ENTRY
{
    ULONG Hash;
    ULONG Index;
} API_SET_HASH_ENTRY, *PAPI_SET_HASH_ENTRY;

typedef struct _API_SET_NAMESPACE_ENTRY
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_VALUE_ENTRY
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;

// PEB->TelemetryCoverageHeader
typedef struct _TELEMETRY_COVERAGE_HEADER
{
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    struct
    {
        USHORT TracingEnabled : 1;
        USHORT Reserved1 : 15;
    };
    ULONG HashTableEntries;
    ULONG HashIndexMask;
    ULONG TableUpdateVersion;
    ULONG TableSizeInBytes;
    ULONG LastResetTick;
    ULONG ResetRound;
    ULONG Reserved2;
    ULONG RecordedCount;
    ULONG Reserved3[4];
    ULONG HashTable[ANYSIZE_ARRAY];
} TELEMETRY_COVERAGE_HEADER, *PTELEMETRY_COVERAGE_HEADER;

typedef struct _WER_RECOVERY_INFO
{
    ULONG Length;
    PVOID Callback;
    PVOID Parameter;
    HANDLE Started;
    HANDLE Finished;
    HANDLE InProgress;
    LONG LastError;
    BOOL Successful;
    ULONG PingInterval;
    ULONG Flags;
} WER_RECOVERY_INFO, *PWER_RECOVERY_INFO;

typedef struct _WER_FILE
{
    USHORT Flags;
    WCHAR Path[MAX_PATH];
} WER_FILE, *PWER_FILE;

typedef struct _WER_MEMORY
{
    PVOID Address;
    ULONG Size;
} WER_MEMORY, *PWER_MEMORY;

typedef struct _WER_GATHER
{
    PVOID Next;
    USHORT Flags;
    union
    {
        WER_FILE File;
        WER_MEMORY Memory;
    } v;
} WER_GATHER, *PWER_GATHER;

typedef struct _WER_METADATA
{
    PVOID Next;
    WCHAR Key[64];
    WCHAR Value[128];
} WER_METADATA, *PWER_METADATA;

typedef struct _WER_RUNTIME_DLL
{
    PVOID Next;
    ULONG Length;
    PVOID Context;
    WCHAR CallbackDllPath[MAX_PATH];
} WER_RUNTIME_DLL, *PWER_RUNTIME_DLL;

typedef struct _WER_DUMP_COLLECTION
{
    PVOID Next;
    ULONG ProcessId;
    ULONG ThreadId;
} WER_DUMP_COLLECTION, *PWER_DUMP_COLLECTION;

typedef struct _WER_HEAP_MAIN_HEADER
{
    WCHAR Signature[16];
    LIST_ENTRY Links;
    HANDLE Mutex;
    PVOID FreeHeap;
    ULONG FreeCount;
} WER_HEAP_MAIN_HEADER, *PWER_HEAP_MAIN_HEADER;

#ifndef RESTART_MAX_CMD_LINE
#define RESTART_MAX_CMD_LINE 1024
#endif

typedef struct _WER_PEB_HEADER_BLOCK
{
    LONG Length;
    WCHAR Signature[16];
    WCHAR AppDataRelativePath[64];
    WCHAR RestartCommandLine[RESTART_MAX_CMD_LINE];
    WER_RECOVERY_INFO RecoveryInfo;
    PWER_GATHER Gather;
    PWER_METADATA MetaData;
    PWER_RUNTIME_DLL RuntimeDll;
    PWER_DUMP_COLLECTION DumpCollection;
    LONG GatherCount;
    LONG MetaDataCount;
    LONG DumpCount;
    LONG Flags;
    WER_HEAP_MAIN_HEADER MainHeader;
    PVOID Reserved;
} WER_PEB_HEADER_BLOCK, *PWER_PEB_HEADER_BLOCK;

typedef _Function_class_(PS_POST_PROCESS_INIT_ROUTINE)
VOID NTAPI PS_POST_PROCESS_INIT_ROUTINE(
    VOID
    );
typedef PS_POST_PROCESS_INIT_ROUTINE* PPS_POST_PROCESS_INIT_ROUTINE;

/**
 * Process Environment Block (PEB) structure.
 *
 * @remarks https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
 */
typedef struct _PEB
{
    //
    // The process was cloned with an inherited address space.
    //
    BOOLEAN InheritedAddressSpace;

    //
    // The process has image file execution options (IFEO).
    //
    BOOLEAN ReadImageFileExecOptions;

    //
    // The process has a debugger attached.
    //
    BOOLEAN BeingDebugged;

    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;            // The process uses large image regions (4 MB).  
            BOOLEAN IsProtectedProcess : 1;             // The process is a protected process.
            BOOLEAN IsImageDynamicallyRelocated : 1;    // The process image base address was relocated.         
            BOOLEAN SkipPatchingUser32Forwarders : 1;   // The process skipped forwarders for User32.dll functions. 1 for 64-bit, 0 for 32-bit.            
            BOOLEAN IsPackagedProcess : 1;              // The process is a packaged store process (APPX/MSIX).
            BOOLEAN IsAppContainer : 1;                 // The process has an AppContainer token.      
            BOOLEAN IsProtectedProcessLight : 1;        // The process is a protected process (light).            
            BOOLEAN IsLongPathAwareProcess : 1;         // The process is long path aware.
        };
    };

    //
    // Handle to a mutex for synchronization.
    //
    HANDLE Mutant;

    //
    // Pointer to the base address of the process image.
    //
    PVOID ImageBaseAddress;

    //
    // Pointer to the process loader data.
    //
    PPEB_LDR_DATA Ldr;

    //
    // Pointer to the process parameters.
    //
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;

    //
    // Reserved.
    //
    PVOID SubSystemData;

    //
    // Pointer to the process default heap.
    //
    PVOID ProcessHeap;

    //
    // Pointer to a critical section used to synchronize access to the PEB.
    //
    PRTL_CRITICAL_SECTION FastPebLock;

    //
    // Pointer to a singly linked list used by ATL.
    //
    PSLIST_HEADER AtlThunkSListPtr;

    //
    // Pointer to the Image File Execution Options key.
    //
    PVOID IFEOKey;

    //
    // Cross process flags.
    //
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;                 // The process is part of a job.
            ULONG ProcessInitializing : 1;          // The process is initializing. 
            ULONG ProcessUsingVEH : 1;              // The process is using VEH.
            ULONG ProcessUsingVCH : 1;              // The process is using VCH.
            ULONG ProcessUsingFTH : 1;              // The process is using FTH.
            ULONG ProcessPreviouslyThrottled : 1;   // The process was previously throttled.
            ULONG ProcessCurrentlyThrottled : 1;    // The process is currently throttled.
            ULONG ProcessImagesHotPatched : 1;      // The process images are hot patched. // RS5
            ULONG ReservedBits0 : 24;
        };
    };

    //
    // User32 KERNEL_CALLBACK_TABLE (ntuser.h)
    //
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };

    //
    // Reserved.
    //
    ULONG SystemReserved;

    //
    // Pointer to the Active Template Library (ATL) singly linked list (32-bit)
    //
    ULONG AtlThunkSListPtr32;

    //
    // Pointer to the API Set Schema.
    //
    PAPI_SET_NAMESPACE ApiSetMap;

    //
    // Counter for TLS expansion.
    //
    ULONG TlsExpansionCounter;

    //
    // Pointer to the TLS bitmap.
    //
    PRTL_BITMAP TlsBitmap;

    //
    // Bits for the TLS bitmap.
    //
    ULONG TlsBitmapBits[2];

    //
    // Reserved for CSRSS.
    //
    PVOID ReadOnlySharedMemoryBase;

    //
    // Pointer to the USER_SHARED_DATA for the current SILO.
    //
    PSILO_USER_SHARED_DATA SharedData;

    //
    // Reserved for CSRSS.
    //
    PVOID* ReadOnlyStaticServerData;

    //
    // Pointer to the ANSI code page data. (PCPTABLEINFO)
    //
    PVOID AnsiCodePageData;

    //
    // Pointer to the OEM code page data. (PCPTABLEINFO)
    //
    PVOID OemCodePageData;

    //
    // Pointer to the Unicode case table data. (PNLSTABLEINFO)
    //
    PVOID UnicodeCaseTableData;

    //
    // The total number of system processors.
    //
    ULONG NumberOfProcessors;

    //
    // Global flags for the system.
    //
    ULONG NtGlobalFlag;

    //
    // Timeout for critical sections.
    //
    LARGE_INTEGER CriticalSectionTimeout;

    //
    // Reserved size for heap segments.
    //
    SIZE_T HeapSegmentReserve;

    //
    // Committed size for heap segments.
    //
    SIZE_T HeapSegmentCommit;

    //
    // Threshold for decommitting total free heap.
    //
    SIZE_T HeapDeCommitTotalFreeThreshold;

    //
    // Threshold for decommitting free heap blocks.
    //
    SIZE_T HeapDeCommitFreeBlockThreshold;

    //
    // Number of process heaps.
    //
    ULONG NumberOfHeaps;

    //
    // Maximum number of process heaps.
    //
    ULONG MaximumNumberOfHeaps;

    //
    // Pointer to an array of process heaps. ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //
    PVOID* ProcessHeaps;

    //
    // Pointer to the system GDI shared handle table.
    //
    PVOID GdiSharedHandleTable;

    //
    // Pointer to the process starter helper.
    //
    PVOID ProcessStarterHelper;

    //
    // The maximum number of GDI function calls during batch operations (GdiSetBatchLimit)
    //
    ULONG GdiDCAttributeList;

    //
    // Pointer to the loader lock critical section.
    //
    PRTL_CRITICAL_SECTION LoaderLock;

    //
    // Major version of the operating system.
    //
    ULONG OSMajorVersion;

    //
    // Minor version of the operating system.
    //
    ULONG OSMinorVersion;

    //
    // Build number of the operating system.
    //
    USHORT OSBuildNumber;

    //
    // CSD version of the operating system.
    //
    USHORT OSCSDVersion;

    //
    // Platform ID of the operating system.
    //
    ULONG OSPlatformId;

    //
    // Subsystem version of the current process image (PE Headers).
    //
    ULONG ImageSubsystem;

    //
    // Major version of the current process image subsystem (PE Headers).
    //
    ULONG ImageSubsystemMajorVersion;

    //
    // Minor version of the current process image subsystem (PE Headers).
    //
    ULONG ImageSubsystemMinorVersion;

    //
    // Affinity mask for the current process.
    //
    KAFFINITY ActiveProcessAffinityMask;

    //
    // Temporary buffer for GDI handles accumulated in the current batch.
    //
#ifdef _WIN64
    ULONG GdiHandleBuffer[60];
#else
    ULONG GdiHandleBuffer[34];
#endif

    //
    // Pointer to the post-process initialization routine available for use by the application.
    //
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;

    //
    // Pointer to the TLS expansion bitmap.
    //
    PRTL_BITMAP TlsExpansionBitmap;

    //
    // Bits for the TLS expansion bitmap. TLS_EXPANSION_SLOTS
    //
    ULONG TlsExpansionBitmapBits[32];

    //
    // Session ID of the current process.
    //
    ULONG SessionId;

    //
    // Application compatibility flags. KACF_*
    //
    ULARGE_INTEGER AppCompatFlags;

    //
    // Application compatibility flags. KACF_*
    //
    ULARGE_INTEGER AppCompatFlagsUser;

    //
    // Pointer to the Application SwitchBack Compatibility Engine.
    //
    PVOID pShimData;

    //
    // Pointer to the Application Compatibility Engine. // APPCOMPAT_EXE_DATA
    //
    PVOID AppCompatInfo;

    //
    // CSD version string of the operating system.
    //
    UNICODE_STRING CSDVersion;

    //
    // Pointer to the process activation context.
    //
    PACTIVATION_CONTEXT_DATA ActivationContextData;

    //
    // Pointer to the process assembly storage map.
    //
    PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;

    //
    // Pointer to the system default activation context.
    //
    PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;

    //
    // Pointer to the system assembly storage map.
    //
    PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

    //
    // Minimum stack commit size.
    //
    SIZE_T MinimumStackCommit;

    //
    // since 19H1 (previously FlsCallback to FlsHighIndex)
    //
    PVOID SparePointers[2];

    //
    // Pointer to the patch loader data.
    //
    PVOID PatchLoaderData;

    //
    // Pointer to the CHPE V2 process information. CHPEV2_PROCESS_INFO
    //
    PVOID ChpeV2ProcessInfo;

    //
    // Packaged process feature state.
    //
    union
    {
        ULONG AppModelFeatureState;
        struct
        {
            ULONG ForegroundBoostProcesses : 1;
            ULONG AppModelFeatureStateReserved : 31;
        };
    };

    //
    // SpareUlongs
    // 
    ULONG SpareUlongs[2];

    //
    // Active code page.
    //
    USHORT ActiveCodePage;

    //
    // OEM code page.
    //
    USHORT OemCodePage;

    //
    // Code page case mapping.
    //
    USHORT UseCaseMapping;

    //
    // Unused NLS field.
    //
    USHORT UnusedNlsField;

    //
    // Pointer to the application WER registration data.
    //
    PWER_PEB_HEADER_BLOCK WerRegistrationData;

    //
    // Pointer to the application WER assert pointer.
    //
    PVOID WerShipAssertPtr;

    //
    // Pointer to the EC bitmap on ARM64. (Windows 11 and above)
    //
    union
    {
        PVOID pContextData; // Pointer to the switchback compatibility engine (Windows 7 and below)
        PVOID EcCodeBitMap; // Pointer to the EC bitmap on ARM64 (Windows 11 and above) // since WIN11
    };

    //
    // Reserved.
    //
    PVOID pImageHeaderHash;

    //
    // ETW tracing flags.
    //
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;       // ETW heap tracing enabled.
            ULONG CritSecTracingEnabled : 1;    // ETW lock tracing enabled.
            ULONG LibLoaderTracingEnabled : 1;  // ETW loader tracing enabled.
            ULONG SpareTracingBits : 29;
        };
    };

    //
    // Reserved for CSRSS.
    //
    ULONGLONG CsrServerReadOnlySharedMemoryBase;

    //
    // Pointer to the thread pool worker list lock.
    //
    PRTL_CRITICAL_SECTION TppWorkerpListLock;

    //
    // Pointer to the thread pool worker list.
    //
    LIST_ENTRY TppWorkerpList;

    //
    // Wait on address hash table. (RtlWaitOnAddress)
    //
    PVOID WaitOnAddressHashTable[128];

    //
    // Pointer to the telemetry coverage header. // since RS3
    //
    PTELEMETRY_COVERAGE_HEADER TelemetryCoverageHeader;

    //
    // Cloud file flags. (ProjFs and Cloud Files) // since RS4
    //
    ULONG CloudFileFlags;

    //
    // Cloud file diagnostic flags.
    //
    ULONG CloudFileDiagFlags;

    //
    // Placeholder compatibility mode. (ProjFs and Cloud Files)
    //
    CHAR PlaceholderCompatibilityMode;

    //
    // Reserved for placeholder compatibility mode.
    //
    CHAR PlaceholderCompatibilityModeReserved[7];

    //
    // Pointer to leap second data. // since RS5
    //
    PLEAP_SECOND_DATA LeapSecondData;

    //
    // Leap second flags.
    //
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1; // Leap seconds enabled.
            ULONG Reserved : 31;
        };
    };

    //
    // Global flags for the process.
    //
    ULONG NtGlobalFlag2;

    //
    // Extended feature disable mask (AVX). // since WIN11
    //
    ULONGLONG ExtendedFeatureDisableMask;
} PEB, *PPEB;

typedef struct _PEB64
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        UCHAR BitField;
        struct
        {
            UCHAR ImageUsesLargePages : 1;
            UCHAR IsProtectedProcess : 1;
            UCHAR IsImageDynamicallyRelocated : 1;
            UCHAR SkipPatchingUser32Forwarders : 1;
            UCHAR IsPackagedProcess : 1;
            UCHAR IsAppContainer : 1;
            UCHAR IsProtectedProcessLight : 1;
            UCHAR IsLongPathAwareProcess : 1;
        };
    };
#if _WIN64
    UCHAR Padding0[4];
#endif
    VOID* POINTER_64 Mutant;
    VOID* POINTER_64 ImageBaseAddress;
    PEB_LDR_DATA64* POINTER_64 Ldr;
    RTL_USER_PROCESS_PARAMETERS64* POINTER_64 ProcessParameters;
    VOID* POINTER_64 SubSystemData;
    VOID* POINTER_64 ProcessHeap;
    RTL_CRITICAL_SECTION64* POINTER_64 FastPebLock;
    struct SLIST_HEADER* POINTER_64 AtlThunkSListPtr; // FIXME: SLIST_HEADER is depends on platform
    VOID* POINTER_64 IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1;
            ULONG ReservedBits0 : 24;
        };
    };
    UCHAR Padding1[4];
    union
    {
        VOID* POINTER_64 KernelCallbackTable;
        VOID* POINTER_64 UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    VOID* POINTER_64 ApiSetMap;
    ULONG TlsExpansionCounter;
    UCHAR Padding2[4];
    RTL_BITMAP64* POINTER_64 TlsBitmap;
    ULONG TlsBitmapBits[2];
    VOID* POINTER_64 ReadOnlySharedMemoryBase;
    VOID* POINTER_64 SharedData;
    VOID* POINTER_64* POINTER_64 ReadOnlyStaticServerData;
    VOID* POINTER_64 AnsiCodePageData;
    VOID* POINTER_64 OemCodePageData;
    VOID* POINTER_64 UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONGLONG HeapSegmentReserve;
    ULONGLONG HeapSegmentCommit;
    ULONGLONG HeapDeCommitTotalFreeThreshold;
    ULONGLONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    VOID* POINTER_64* POINTER_64 ProcessHeaps;
    VOID* POINTER_64 GdiSharedHandleTable;
    VOID* POINTER_64 ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    UCHAR Padding3[4];
    RTL_CRITICAL_SECTION64* POINTER_64 LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    UCHAR Padding4[4];
    ULONGLONG ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[60];
    VOID* POINTER_64 PostProcessInitRoutine;
    RTL_BITMAP64* POINTER_64 TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    UCHAR Padding5[4];
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    VOID* POINTER_64 pShimData;
    VOID* POINTER_64 AppCompatInfo;
    UNICODE_STRING64 CSDVersion;
    ACTIVATION_CONTEXT_DATA* POINTER_64 ActivationContextData;
    ASSEMBLY_STORAGE_MAP64* POINTER_64 ProcessAssemblyStorageMap;
    ACTIVATION_CONTEXT_DATA* POINTER_64 SystemDefaultActivationContextData;
    ASSEMBLY_STORAGE_MAP64* POINTER_64 SystemAssemblyStorageMap;
    ULONGLONG MinimumStackCommit;
    VOID* POINTER_64 SparePointers[2];
    VOID* POINTER_64 PatchLoaderData;
    struct CHPEV2_PROCESS_INFO* POINTER_64 ChpeV2ProcessInfo;
    ULONG AppModelFeatureState;
    ULONG SpareUlongs[2];
    USHORT ActiveCodePage;
    USHORT OemCodePage;
    USHORT UseCaseMapping;
    USHORT UnusedNlsField;
    VOID* POINTER_64 WerRegistrationData; // TODO: WER_PEB_HEADER_BLOCK64*
    VOID* POINTER_64 WerShipAssertPtr;
    VOID* POINTER_64 EcCodeBitMap;
    VOID* POINTER_64 pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    UCHAR Padding6[4];
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    RTL_CRITICAL_SECTION64* POINTER_64 TppWorkerpListLock;
    LIST_ENTRY64 TppWorkerpList;
    VOID* POINTER_64 WaitOnAddressHashTable[128];
    TELEMETRY_COVERAGE_HEADER* POINTER_64 TelemetryCoverageHeader;
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags;
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    LEAP_SECOND_DATA* POINTER_64 LeapSecondData;
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
    ULONGLONG ExtendedFeatureDisableMask;
} PEB64, *PPEB64;

typedef struct _PEB32
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        UCHAR BitField;
        struct
        {
            UCHAR ImageUsesLargePages : 1;
            UCHAR IsProtectedProcess : 1;
            UCHAR IsImageDynamicallyRelocated : 1;
            UCHAR SkipPatchingUser32Forwarders : 1;
            UCHAR IsPackagedProcess : 1;
            UCHAR IsAppContainer : 1;
            UCHAR IsProtectedProcessLight : 1;
            UCHAR IsLongPathAwareProcess : 1;
        };
    };
    VOID* POINTER_32 Mutant;
    VOID* POINTER_32 ImageBaseAddress;
    PEB_LDR_DATA32* POINTER_32 Ldr;
    RTL_USER_PROCESS_PARAMETERS32* POINTER_32 ProcessParameters;
    VOID* POINTER_32 SubSystemData;
    VOID* POINTER_32 ProcessHeap;
    RTL_CRITICAL_SECTION32* POINTER_32 FastPebLock;
    struct SLIST_HEADER* POINTER_32 AtlThunkSListPtr; // FIXME: SLIST_HEADER is depends on platform
    VOID* POINTER_32 IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1;
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        VOID* POINTER_32 KernelCallbackTable;
        VOID* POINTER_32 UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    VOID* POINTER_32 ApiSetMap;
    ULONG TlsExpansionCounter;
    RTL_BITMAP32* POINTER_32 TlsBitmap;
    ULONG TlsBitmapBits[2];
    VOID* POINTER_32 ReadOnlySharedMemoryBase;
    VOID* POINTER_32 SharedData;
    VOID* POINTER_32* POINTER_32 ReadOnlyStaticServerData;
    VOID* POINTER_32 AnsiCodePageData;
    VOID* POINTER_32 OemCodePageData;
    VOID* POINTER_32 UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    VOID* POINTER_32* POINTER_32 ProcessHeaps;
    VOID* POINTER_32 GdiSharedHandleTable;
    VOID* POINTER_32 ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    RTL_CRITICAL_SECTION32* POINTER_32 LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[34];
    VOID* POINTER_32 PostProcessInitRoutine;
    RTL_BITMAP32* POINTER_32 TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    VOID* POINTER_32 pShimData;
    VOID* POINTER_32 AppCompatInfo;
    UNICODE_STRING32 CSDVersion;
    ACTIVATION_CONTEXT_DATA* POINTER_32 ActivationContextData;
    ASSEMBLY_STORAGE_MAP32* POINTER_32 ProcessAssemblyStorageMap;
    ACTIVATION_CONTEXT_DATA* POINTER_32 SystemDefaultActivationContextData;
    ASSEMBLY_STORAGE_MAP32* POINTER_32 SystemAssemblyStorageMap;
    ULONG MinimumStackCommit;
    VOID* POINTER_32 SparePointers[2];
    VOID* POINTER_32 PatchLoaderData;
    struct CHPEV2_PROCESS_INFO* POINTER_32 ChpeV2ProcessInfo;
    ULONG AppModelFeatureState;
    ULONG SpareUlongs[2];
    USHORT ActiveCodePage;
    USHORT OemCodePage;
    USHORT UseCaseMapping;
    USHORT UnusedNlsField;
    VOID* POINTER_32 WerRegistrationData;  // TODO: WER_PEB_HEADER_BLOCK32*
    VOID* POINTER_32 WerShipAssertPtr;
    VOID* POINTER_32 Spare;
    VOID* POINTER_32 pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    RTL_CRITICAL_SECTION32* POINTER_32 TppWorkerpListLock;
    LIST_ENTRY32 TppWorkerpList;
    VOID* POINTER_32 WaitOnAddressHashTable[128];
    TELEMETRY_COVERAGE_HEADER* POINTER_32 TelemetryCoverageHeader;
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags;
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    LEAP_SECOND_DATA* POINTER_32 LeapSecondData;
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
    ULONGLONG ExtendedFeatureDisableMask;
} PEB32, *PPEB32;

/**
 * The GDI_TEB_BATCH structure is used to store information about GDI batch operations.
 */
typedef struct _GDI_TEB_BATCH
{
    struct
    {
        ULONG Offset : 31;
        ULONG HasRenderingCommand : 1;
    };
    ULONG_PTR HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _GDI_TEB_BATCH64
{
    struct
    {
        ULONG Offset : 31;
        ULONG HasRenderingCommand : 1;
    };
    ULONGLONG HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH64, *PGDI_TEB_BATCH64;

typedef struct _GDI_TEB_BATCH32
{
    struct
    {
        ULONG Offset : 31;
        ULONG HasRenderingCommand : 1;
    };
    ULONG HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH32, *PGDI_TEB_BATCH32;

#define TEB_ACTIVE_FRAME_CONTEXT_FLAG_EXTENDED (0x00000001)

/**
 * The TEB_ACTIVE_FRAME_CONTEXT structure is used to store information about an active frame context.
 */
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

/**
 * The TEB_ACTIVE_FRAME_CONTEXT_EX structure extends TEB_ACTIVE_FRAME_CONTEXT with additional information.
 */
typedef struct _TEB_ACTIVE_FRAME_CONTEXT_EX
{
    TEB_ACTIVE_FRAME_CONTEXT BasicContext;
    PCSTR SourceLocation;
} TEB_ACTIVE_FRAME_CONTEXT_EX, *PTEB_ACTIVE_FRAME_CONTEXT_EX;

#define TEB_ACTIVE_FRAME_FLAG_EXTENDED (0x00000001)

/**
 * The TEB_ACTIVE_FRAME structure is used to store information about an active frame.
 */
typedef struct _TEB_ACTIVE_FRAME TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;
struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    PTEB_ACTIVE_FRAME Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
};

/**
 * The TEB_ACTIVE_FRAME_EX structure extends TEB_ACTIVE_FRAME with additional information.
 */
typedef struct _TEB_ACTIVE_FRAME_EX
{
    TEB_ACTIVE_FRAME BasicFrame;
    PVOID ExtensionIdentifier;
} TEB_ACTIVE_FRAME_EX, *PTEB_ACTIVE_FRAME_EX;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT64
{
    ULONG Flags;
    UCHAR Padding[4];
    CONST CHAR* POINTER_64 FrameName;
} TEB_ACTIVE_FRAME_CONTEXT64, *PTEB_ACTIVE_FRAME_CONTEXT64;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT32
{
    ULONG Flags;
    UCHAR Padding[4];
    CONST CHAR* POINTER_32 FrameName;
} TEB_ACTIVE_FRAME_CONTEXT32, *PTEB_ACTIVE_FRAME_CONTEXT32;

typedef struct _TEB_ACTIVE_FRAME64 TEB_ACTIVE_FRAME64, *PTEB_ACTIVE_FRAME64;
typedef struct _TEB_ACTIVE_FRAME32 TEB_ACTIVE_FRAME32, *PTEB_ACTIVE_FRAME32;

struct _TEB_ACTIVE_FRAME64
{
    DWORD Flags;
    UCHAR Padding[4];
    TEB_ACTIVE_FRAME64* POINTER_64 Previous;
    TEB_ACTIVE_FRAME_CONTEXT64* POINTER_64 Context;
};

struct _TEB_ACTIVE_FRAME32
{
    DWORD Flags;
    TEB_ACTIVE_FRAME32* POINTER_32 Previous;
    TEB_ACTIVE_FRAME_CONTEXT32* POINTER_32 Context;
};

/**
 * Thread Environment Block (TEB) structure.
 *
 * @remarks https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb
 */
typedef struct _TEB
{
    // Thread Information Block (TIB) contains the thread's stack, base and limit addresses, the current stack pointer, and the exception list.
    NT_TIB NtTib;

    // Reserved.
    PVOID EnvironmentPointer;

    // Client ID for this thread.
    CLIENT_ID ClientId;

    // A handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation.
    PVOID ActiveRpcHandle;

    // A pointer to the __declspec(thread) local storage array.
    PVOID ThreadLocalStoragePointer;

    // A pointer to the Process Environment Block (PEB), which contains information about the process.
    PPEB ProcessEnvironmentBlock;

    // The previous Win32 error value for this thread.
    ULONG LastErrorValue;

    // The number of critical sections currently owned by this thread.
    ULONG CountOfOwnedCriticalSections;

    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;

    // The LCID of the current thread. (Kernel32!GetThreadLocale)
    LCID CurrentLocale;

    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
    PVOID SystemReserved1[25];

    // Per-thread fiber local storage. (Teb->HasFiberData)
    PVOID HeapFlsData;

    ULONG_PTR RngState[4];
#else
    PVOID SystemReserved1[26];
#endif

    // Placeholder compatibility mode. (ProjFs and Cloud Files)
    CHAR PlaceholderCompatibilityMode;

    BOOLEAN PlaceholderHydrationAlwaysExplicit;
    CHAR PlaceholderReserved[10];

    // The process ID (PID) that the current COM server thread is acting on behalf of.
    ULONG ProxiedProcessId;

    ACTIVATION_CONTEXT_STACK ActivationStack;

    // Opaque operation on behalf of another user or process.
    UCHAR WorkingOnBehalfTicket[8];

    // The last exception status for the current thread.
    NTSTATUS ExceptionCode;

    // Pointer to the activation context stack for the current thread.
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;

    // The stack pointer (SP) of the current system call or exception during instrumentation.
    ULONG_PTR InstrumentationCallbackSp;

    // The program counter (PC) of the previous system call or exception during instrumentation.
    ULONG_PTR InstrumentationCallbackPreviousPc;

    // The stack pointer (SP) of the previous system call or exception during instrumentation.
    ULONG_PTR InstrumentationCallbackPreviousSp;

#ifdef _WIN64
    // The miniversion ID of the current transacted file operation.
    ULONG TxFsContext;
#endif

    // Indicates the state of the system call or exception instrumentation callback.
    BOOLEAN InstrumentationCallbackDisabled;

#ifdef _WIN64
    // Indicates the state of alignment exceptions for unaligned load/store operations.
    BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifndef _WIN64
    UCHAR SpareBytes[23];

    // The miniversion ID of the current transacted file operation.
    ULONG TxFsContext;
#endif
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];

    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    // The previous status value for this thread.
    NTSTATUS LastStatusValue;

    // A static string for use by the application.
    UNICODE_STRING StaticUnicodeString;

    // A static buffer for use by the application.
    WCHAR StaticUnicodeBuffer[261];

    // The maximum stack size and indicates the base of the stack.
    PVOID DeallocationStack;

    // Data for Thread Local Storage. (TlsGetValue)
    PVOID TlsSlots[64];

    LIST_ENTRY TlsLinks;

    // Reserved for NTVDM.
    PVOID Vdm;

    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    // The error mode for the current thread. (GetThreadErrorMode)
    ULONG HardErrorMode;

#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    // The service creating the thread (svchost).
    PVOID SubProcessTag;

    PVOID PerflibData;
    PVOID EtwTraceData;

    // The address of a socket handle during a blocking socket operation. (WSAStartup)
    PVOID WinSockData;

    // The number of function calls accumulated in the current GDI batch. (GdiSetBatchLimit)
    ULONG GdiBatchCount;

    // The preferred processor for the curremt thread. (SetThreadIdealProcessor/SetThreadIdealProcessorEx)
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    // The minimum size of the stack available during any stack overflow exceptions. (SetThreadStackGuarantee)
    ULONG GuaranteedStackBytes;

    PVOID ReservedForPerf;

    // tagSOleTlsData
    PVOID ReservedForOle;

    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PVOID *TlsExpansionSlots;
#ifdef _WIN64
    struct CHPEV2_CPUAREA_INFO* ChpeV2CpuAreaInfo; // previously DeallocationBStore
    PVOID Unused; // previously BStoreLimit
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapData;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
    ULONGLONG LastSleepCounter; // Win11
    ULONG SpinCallCount;
    ULONGLONG ExtendedFeatureDisableMask;
    PVOID SchedulerSharedDataSlot; // 24H2
    PVOID HeapWalkContext;
    GROUP_AFFINITY PrimaryGroupAffinity;
    ULONG Rcu[2];
} TEB, *PTEB;

typedef struct _TEB64
{
    NT_TIB64 NtTib;
    VOID* POINTER_64 EnvironmentPointer;
    CLIENT_ID64 ClientId;
    VOID* POINTER_64 ActiveRpcHandle;
    VOID* POINTER_64 ThreadLocalStoragePointer;
    PEB64* POINTER_64 ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    VOID* POINTER_64 CsrClientThread;
    VOID* POINTER_64 Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    VOID* POINTER_64 WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    VOID* POINTER_64 ReservedForDebuggerInstrumentation[16];
    VOID* POINTER_64 SystemReserved1[30];
    CHAR PlaceholderCompatibilityMode;
    BOOLEAN PlaceholderHydrationAlwaysExplicit;
    CHAR PlaceholderReserved[10];
    ULONG ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK64 _ActivationStack;
    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode;
    UCHAR Padding0[4];
    ACTIVATION_CONTEXT_STACK64* POINTER_64 ActivationContextStackPointer;
    ULONGLONG InstrumentationCallbackSp;
    ULONGLONG InstrumentationCallbackPreviousPc;
    ULONGLONG InstrumentationCallbackPreviousSp;
    ULONG TxFsContext;
    BOOLEAN InstrumentationCallbackDisabled;
    BOOLEAN UnalignedLoadStoreExceptions;
    UCHAR Padding1[2];
    GDI_TEB_BATCH64 GdiTebBatch;
    CLIENT_ID64 RealClientId;
    VOID* POINTER_64 GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    VOID* POINTER_64 GdiThreadLocalInfo;
    ULONGLONG Win32ClientInfo[62];
    VOID* POINTER_64 glDispatchTable[233];
    ULONGLONG glReserved1[29];
    VOID* POINTER_64 glReserved2;
    VOID* POINTER_64 glSectionInfo;
    VOID* POINTER_64 glSection;
    VOID* POINTER_64 glTable;
    VOID* POINTER_64 glCurrentRC;
    VOID* POINTER_64 glContext;
    NTSTATUS LastStatusValue;
    UCHAR Padding2[4];
    UNICODE_STRING64 StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    UCHAR Padding3[6];
    VOID* POINTER_64 DeallocationStack;
    VOID* POINTER_64 TlsSlots[64];
    LIST_ENTRY64 TlsLinks;
    VOID* POINTER_64 Vdm;
    VOID* POINTER_64 ReservedForNtRpc;
    VOID* POINTER_64 DbgSsReserved[2];
    ULONG HardErrorMode;
    UCHAR Padding4[4];
    VOID* POINTER_64 Instrumentation[11];
    GUID ActivityId;
    VOID* POINTER_64 SubProcessTag;
    VOID* POINTER_64 PerflibData;
    VOID* POINTER_64 EtwTraceData;
    VOID* POINTER_64 WinSockData;
    ULONG GdiBatchCount;
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        union
        {
            ULONG IdealProcessorValue;
            struct
            {
                UCHAR ReservedPad0;
                UCHAR ReservedPad1;
                UCHAR ReservedPad2;
                UCHAR IdealProcessor;
            };
        };
    };
    ULONG GuaranteedStackBytes;
    UCHAR Padding5[4];
    VOID* POINTER_64 ReservedForPerf;
    VOID* POINTER_64 ReservedForOle;
    ULONG WaitingOnLoaderLock;
    UCHAR Padding6[4];
    VOID* POINTER_64 SavedPriorityState;
    ULONGLONG ReservedForCodeCoverage;
    VOID* POINTER_64 ThreadPoolData;
    VOID* POINTER_64* POINTER_64 TlsExpansionSlots;
    struct CHPEV2_CPUAREA_INFO* POINTER_64 ChpeV2CpuAreaInfo;
    VOID* POINTER_64 Unused;
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    VOID* POINTER_64 NlsCache;
    VOID* POINTER_64 pShimData;
    ULONG HeapData;
    UCHAR Padding7[4];
    VOID* POINTER_64 CurrentTransactionHandle;
    TEB_ACTIVE_FRAME64* POINTER_64 ActiveFrame;
    VOID* POINTER_64 FlsData;
    VOID* POINTER_64 PreferredLanguages;
    VOID* POINTER_64 UserPrefLanguages;
    VOID* POINTER_64 MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        USHORT CrossTebFlags;
        struct
        {
            USHORT SpareCrossTebBits : 16;
        };
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };
    VOID* POINTER_64 TxnScopeEnterCallback;
    VOID* POINTER_64 TxnScopeExitCallback;
    VOID* POINTER_64 TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    VOID* POINTER_64 ResourceRetValue;
    VOID* POINTER_64 ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
    ULONGLONG LastSleepCounter;
    ULONG SpinCallCount;
    UCHAR Padding8[4];
    ULONGLONG ExtendedFeatureDisableMask;
} TEB64, *PTEB64;

typedef struct _TEB32
{
    NT_TIB32 NtTib;
    VOID* POINTER_32 EnvironmentPointer;
    CLIENT_ID32 ClientId;
    VOID* POINTER_32 ActiveRpcHandle;
    VOID* POINTER_32 ThreadLocalStoragePointer;
    PEB32* POINTER_32 ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    VOID* POINTER_32 CsrClientThread;
    VOID* POINTER_32 Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    VOID* POINTER_32 WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    VOID* POINTER_32 ReservedForDebuggerInstrumentation[16];
    VOID* POINTER_32 SystemReserved1[26];
    CHAR PlaceholderCompatibilityMode;
    BOOLEAN PlaceholderHydrationAlwaysExplicit;
    CHAR PlaceholderReserved[10];
    ULONG ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK32 _ActivationStack;
    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode;
    ACTIVATION_CONTEXT_STACK32* POINTER_32 ActivationContextStackPointer;
    ULONG InstrumentationCallbackSp;
    ULONG InstrumentationCallbackPreviousPc;
    ULONG InstrumentationCallbackPreviousSp;
    UCHAR InstrumentationCallbackDisabled;
    UCHAR SpareBytes[23];
    ULONG TxFsContext;
    GDI_TEB_BATCH32 GdiTebBatch;
    CLIENT_ID32 RealClientId;
    VOID* POINTER_32 GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    VOID* POINTER_32 GdiThreadLocalInfo;
    ULONG Win32ClientInfo[62];
    VOID* POINTER_32 glDispatchTable[233];
    ULONG glReserved1[29];
    VOID* POINTER_32 glReserved2;
    VOID* POINTER_32 glSectionInfo;
    VOID* POINTER_32 glSection;
    VOID* POINTER_32 glTable;
    VOID* POINTER_32 glCurrentRC;
    VOID* POINTER_32 glContext;
    NTSTATUS LastStatusValue;
    UNICODE_STRING32 StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    VOID* POINTER_32 DeallocationStack;
    VOID* POINTER_32 TlsSlots[64];
    LIST_ENTRY32 TlsLinks;
    VOID* POINTER_32 Vdm;
    VOID* POINTER_32 ReservedForNtRpc;
    VOID* POINTER_32 DbgSsReserved[2];
    ULONG HardErrorMode;
    VOID* POINTER_32 Instrumentation[9];
    GUID ActivityId;
    VOID* POINTER_32 SubProcessTag;
    VOID* POINTER_32 PerflibData;
    VOID* POINTER_32 EtwTraceData;
    VOID* POINTER_32 WinSockData;
    ULONG GdiBatchCount;
    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        union
        {
            ULONG IdealProcessorValue;
            struct
            {
                UCHAR ReservedPad0;
                UCHAR ReservedPad1;
                UCHAR ReservedPad2;
                UCHAR IdealProcessor;
            };
        };
    };
    ULONG GuaranteedStackBytes;
    VOID* POINTER_32 ReservedForPerf;
    VOID* POINTER_32 ReservedForOle;
    ULONG WaitingOnLoaderLock;
    VOID* POINTER_32 SavedPriorityState;
    ULONG ReservedForCodeCoverage;
    VOID* POINTER_32 ThreadPoolData;
    VOID* POINTER_32 TlsExpansionSlots;
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    VOID* POINTER_32 NlsCache;
    VOID* POINTER_32 pShimData;
    ULONG HeapData;
    VOID* POINTER_32 CurrentTransactionHandle;
    TEB_ACTIVE_FRAME32* POINTER_32 ActiveFrame;
    VOID* POINTER_32 FlsData;
    VOID* POINTER_32 PreferredLanguages;
    VOID* POINTER_32 UserPrefLanguages;
    VOID* POINTER_32 MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        USHORT CrossTebFlags;
        struct
        {
            USHORT SpareCrossTebBits : 16;
        };
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };
    VOID* POINTER_32 TxnScopeEnterCallback;
    VOID* POINTER_32 TxnScopeExitCallback;
    VOID* POINTER_32 TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    VOID* POINTER_32 ResourceRetValue;
    VOID* POINTER_32 ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
    ULONGLONG LastSleepCounter;
    ULONG SpinCallCount;
    ULONGLONG ExtendedFeatureDisableMask;
} TEB32, *PTEB32;

NTSYSAPI
PPEB
NTAPI
RtlGetCurrentPeb(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlAcquirePebLock(VOID);

NTSYSAPI
NTSTATUS
NTAPI
RtlReleasePebLock(VOID);

NTSYSAPI
LOGICAL
NTAPI
RtlTryAcquirePebLock(VOID);

EXTERN_C_END
