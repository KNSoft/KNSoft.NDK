#pragma once

#include "MinDef.h"

EXTERN_C_START

/* ntimage.h & phnt */

#if !defined(_KERNEL_MODE)

#define IMAGE_FILE_MACHINE_CHPE_X86          0x3A64
#define IMAGE_FILE_MACHINE_ARM64EC           0xA641
#define IMAGE_FILE_MACHINE_ARM64X            0xA64E

#define IMAGE_LOADER_FLAGS_COMPLUS             0x00000001   // COM+ image
#define IMAGE_LOADER_FLAGS_SYSTEM_GLOBAL       0x01000000   // Global subsections apply across TS sessions.

#endif

/**
 * The IMAGE_CHPE_METADATA_X86 structure represents CHPE metadata for x86.
 */
typedef struct _IMAGE_CHPE_METADATA_X86
{
    ULONG  Version;
    ULONG  CHPECodeAddressRangeOffset;
    ULONG  CHPECodeAddressRangeCount;
    ULONG  WowA64ExceptionHandlerFunctionPointer;
    ULONG  WowA64DispatchCallFunctionPointer;
    ULONG  WowA64DispatchIndirectCallFunctionPointer;
    ULONG  WowA64DispatchIndirectCallCfgFunctionPointer;
    ULONG  WowA64DispatchRetFunctionPointer;
    ULONG  WowA64DispatchRetLeafFunctionPointer;
    ULONG  WowA64DispatchJumpFunctionPointer;
    ULONG  CompilerIATPointer;         // Present if Version >= 2
    ULONG  WowA64RdtscFunctionPointer; // Present if Version >= 3
} IMAGE_CHPE_METADATA_X86, *PIMAGE_CHPE_METADATA_X86;

/**
 * The IMAGE_CHPE_RANGE_ENTRY structure represents a CHPE range entry.
 */
typedef struct _IMAGE_CHPE_RANGE_ENTRY
{
    union
    {
        ULONG StartOffset;
        struct
        {
            ULONG NativeCode : 1;
            ULONG AddressBits : 31;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    ULONG Length;
} IMAGE_CHPE_RANGE_ENTRY, *PIMAGE_CHPE_RANGE_ENTRY;

/**
 * The IMAGE_ARM64EC_METADATA structure represents ARM64EC metadata.
 */
typedef struct _IMAGE_ARM64EC_METADATA
{
    ULONG  Version;
    ULONG  CodeMap;
    ULONG  CodeMapCount;
    ULONG  CodeRangesToEntryPoints;
    ULONG  RedirectionMetadata;
    ULONG  tbd__os_arm64x_dispatch_call_no_redirect;
    ULONG  tbd__os_arm64x_dispatch_ret;
    ULONG  tbd__os_arm64x_dispatch_call;
    ULONG  tbd__os_arm64x_dispatch_icall;
    ULONG  tbd__os_arm64x_dispatch_icall_cfg;
    ULONG  AlternateEntryPoint;
    ULONG  AuxiliaryIAT;
    ULONG  CodeRangesToEntryPointsCount;
    ULONG  RedirectionMetadataCount;
    ULONG  GetX64InformationFunctionPointer;
    ULONG  SetX64InformationFunctionPointer;
    ULONG  ExtraRFETable;
    ULONG  ExtraRFETableSize;
    ULONG  __os_arm64x_dispatch_fptr;
    ULONG  AuxiliaryIATCopy;
} IMAGE_ARM64EC_METADATA;

typedef struct _IMAGE_ARM64EC_METADATA_V2
{
    ULONG  Version;
    ULONG  CodeMap;
    ULONG  CodeMapCount;
    ULONG  CodeRangesToEntryPoints;
    ULONG  RedirectionMetadata;
    ULONG  tbd__os_arm64x_dispatch_call_no_redirect;
    ULONG  tbd__os_arm64x_dispatch_ret;
    ULONG  tbd__os_arm64x_dispatch_call;
    ULONG  tbd__os_arm64x_dispatch_icall;
    ULONG  tbd__os_arm64x_dispatch_icall_cfg;
    ULONG  AlternateEntryPoint;
    ULONG  AuxiliaryIAT;
    ULONG  CodeRangesToEntryPointsCount;
    ULONG  RedirectionMetadataCount;
    ULONG  GetX64InformationFunctionPointer;
    ULONG  SetX64InformationFunctionPointer;
    ULONG  ExtraRFETable;
    ULONG  ExtraRFETableSize;
    ULONG  __os_arm64x_dispatch_fptr;
    ULONG  AuxiliaryIATCopy;

    //
    // Below are V2-specific
    //
    ULONG  AuxDelayloadIAT;
    ULONG  AuxDelayloadIATCopy;
    ULONG  ReservedBitField;    // reserved and unused by the linker
} IMAGE_ARM64EC_METADATA_V2;

/**
 * The IMAGE_ARM64EC_REDIRECTION_ENTRY structure represents an ARM64EC redirection entry.
 */
typedef struct _IMAGE_ARM64EC_REDIRECTION_ENTRY
{
    ULONG Source;
    ULONG Destination;
} IMAGE_ARM64EC_REDIRECTION_ENTRY, *PIMAGE_ARM64EC_REDIRECTION_ENTRY;

/**
 * The IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT structure represents an ARM64EC code range entry point.
 */
typedef struct _IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT
{
    ULONG StartRva;
    ULONG EndRva;
    ULONG EntryPoint;
} IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT, *PIMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT;

#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL   0
#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE      1
#define IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA      2

#define IMAGE_DVRT_ARM64X_FIXUP_SIZE_2BYTES     1
#define IMAGE_DVRT_ARM64X_FIXUP_SIZE_4BYTES     2
#define IMAGE_DVRT_ARM64X_FIXUP_SIZE_8BYTES     3

/**
 * The IMAGE_DVRT_ARM64X_FIXUP_RECORD structure represents an ARM64X fixup record.
 */
typedef struct _IMAGE_DVRT_ARM64X_FIXUP_RECORD
{
    USHORT Offset : 12;
    USHORT Type : 2;
    USHORT Size : 2;
    // Value of variable Size when IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE
} IMAGE_DVRT_ARM64X_FIXUP_RECORD, *PIMAGE_DVRT_ARM64X_FIXUP_RECORD;

/**
 * The IMAGE_DVRT_ARM64X_DELTA_FIXUP_RECORD structure represents an ARM64X delta fixup record.
 */
typedef struct _IMAGE_DVRT_ARM64X_DELTA_FIXUP_RECORD
{
    USHORT Offset : 12;
    USHORT Type : 2; // IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA
    USHORT Sign : 1; // 1 = -, 0 = +
    USHORT Scale : 1; // 1 = 8, 0 = 4
    // USHORT Value; // Delta = Value * Scale * Sign
} IMAGE_DVRT_ARM64X_DELTA_FIXUP_RECORD, *PIMAGE_DVRT_ARM64X_DELTA_FIXUP_RECORD;

/* phnt */

/**
 * The IMAGE_DEBUG_POGO_ENTRY structure represents a POGO (Profile Guided Optimization) entry.
 */
typedef struct _IMAGE_DEBUG_POGO_ENTRY
{
    ULONG Rva;
    ULONG Size;
    CHAR Name[1];
} IMAGE_DEBUG_POGO_ENTRY, *PIMAGE_DEBUG_POGO_ENTRY;

/**
 * The IMAGE_DEBUG_POGO_SIGNATURE structure represents a POGO signature.
 */
typedef struct _IMAGE_DEBUG_POGO_SIGNATURE
{
    ULONG Signature;
} IMAGE_DEBUG_POGO_SIGNATURE, *PIMAGE_DEBUG_POGO_SIGNATURE;

#define IMAGE_DEBUG_POGO_SIGNATURE_LTCG 'LTCG' // coffgrp LTCG (0x4C544347)
#define IMAGE_DEBUG_POGO_SIGNATURE_PGI 'PGI\0' // coffgrp PGI (0x50474900)
#define IMAGE_DEBUG_POGO_SIGNATURE_PGO 'PGO\0' // coffgrp PGO (0x50474F00)
#define IMAGE_DEBUG_POGO_SIGNATURE_PGU 'PGU\0' // coffgrp PGU (0x50475500)
#define IMAGE_DEBUG_POGO_SIGNATURE_SPGO 'SPGO' // coffgrp SPGO (0x5350474F)

/**
 * The IMAGE_RELOCATION_RECORD structure represents a relocation record.
 */
typedef struct _IMAGE_RELOCATION_RECORD
{
    USHORT Offset : 12;
    USHORT Type : 4;
} IMAGE_RELOCATION_RECORD, *PIMAGE_RELOCATION_RECORD;

// rev
#define IMAGE_ARM64EC_CODE_MAP_TYPE_ARM64   0
#define IMAGE_ARM64EC_CODE_MAP_TYPE_ARM64EC 1
#define IMAGE_ARM64EC_CODE_MAP_TYPE_AMD64   2

/**
 * The IMAGE_ARM64EC_CODE_MAP_ENTRY structure represents an ARM64EC code map entry.
 */
typedef struct _IMAGE_ARM64EC_CODE_MAP_ENTRY
{
    union
    {
        ULONG StartOffset;
        struct
        {
            ULONG Type : 2;
            ULONG AddressBits : 30;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    ULONG Length;
} IMAGE_ARM64EC_CODE_MAP_ENTRY, *PIMAGE_ARM64EC_CODE_MAP_ENTRY;

/**
 * The IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION structure represents an ARM64 import control transfer relocation.
 *
 * \remarks On ARM64, optimized imported functions use this structure for import control transfer relocations.
 * This is used with IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER.
 */
//typedef struct _IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION
//{
//    ULONG PageRelativeOffset : 10;
//    ULONG IndirectCall : 1;
//    ULONG RegisterIndex : 5;
//    ULONG ImportType : 1;
//    ULONG IATIndex : 15;
//} IMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION, *PIMAGE_IMPORT_CONTROL_TRANSFER_ARM64_RELOCATION;
//
/**
 * The IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER structure represents a prologue dynamic relocation header.
 *
 * \remarks This structure is followed by PrologueByteCount bytes containing the prologue code.
 * Used with IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE.
 */
//#include <pshpack1.h>
//typedef struct _IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER
//{
//    UCHAR PrologueByteCount;
//    // UCHAR PrologueBytes[PrologueByteCount];
//} IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER, UNALIGNED *PIMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER;
//#include <poppack.h>
//
/**
 * The IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER structure represents an epilogue dynamic relocation header.
 *
 * \remarks This structure is followed by variable-length branch descriptor data.
 * Used with IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE.
 */
//#include <pshpack1.h>
//typedef struct _IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER
//{
//    ULONG EpilogueCount;
//    UCHAR EpilogueByteCount;
//    UCHAR BranchDescriptorElementSize;
//    USHORT BranchDescriptorCount;
//    // UCHAR BranchDescriptors[...];
//    // UCHAR BranchDescriptorBitMap[...];
//} IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER, UNALIGNED *PIMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER;
//#include <poppack.h>

#define IMAGE_DYNAMIC_RELOCATION_ARM64X                         0x00000006
#define IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER 0x00000008
#define IMAGE_DYNAMIC_RELOCATION_MM_SHARED_USER_DATA_VA         0x7FFE0000
#define IMAGE_DYNAMIC_RELOCATION_KI_USER_SHARED_DATA64          0xFFFFF78000000000UI64

// Note: The Windows SDK defines UNALIGNED for PIMAGE_IMPORT_DESCRIPTOR but
// doesn't include UNALIGNED for PIMAGE_THUNK_DATA (See GH#1694) (dmex)
typedef struct _IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA32;
typedef struct _IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA32 UNALIGNED* UNALIGNED_PIMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA64 UNALIGNED* UNALIGNED_PIMAGE_THUNK_DATA64;

// Note: Required for legacy SDK support (dmex)
#if !defined(NTDDI_WIN10_NI) || (NTDDI_VERSION < NTDDI_WIN10_NI)
#define IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE   0x00000001
#define IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE   0x00000002
#define IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER  0x00000003
#define IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER   0x00000004
#define IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH       0x00000005
#define IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE              0x00000007

typedef struct _IMAGE_FUNCTION_OVERRIDE_HEADER
{
    ULONG FuncOverrideSize;
    // IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION  FuncOverrideInfo[ANYSIZE_ARRAY]; // FuncOverrideSize bytes in size
    // IMAGE_BDD_INFO BDDInfo; // BDD region, size in bytes: DVRTEntrySize - sizeof(IMAGE_FUNCTION_OVERRIDE_HEADER) - FuncOverrideSize
} IMAGE_FUNCTION_OVERRIDE_HEADER;
typedef IMAGE_FUNCTION_OVERRIDE_HEADER UNALIGNED *PIMAGE_FUNCTION_OVERRIDE_HEADER;

typedef struct _IMAGE_BDD_INFO
{
    ULONG Version; // decides the semantics of serialized BDD
    ULONG BDDSize;
    // IMAGE_BDD_DYNAMIC_RELOCATION BDDNodes[ANYSIZE_ARRAY]; // BDDSize size in bytes.
} IMAGE_BDD_INFO, *PIMAGE_BDD_INFO;

typedef struct _IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION
{
    ULONG OriginalRva;          // RVA of original function
    ULONG BDDOffset;            // Offset into the BDD region
    ULONG RvaSize;              // Size in bytes taken by RVAs. Must be multiple of sizeof(ULONG).
    ULONG BaseRelocSize;        // Size in bytes taken by BaseRelocs
    // ULONG RVAs[RvaSize / sizeof(ULONG)];     // Array containing overriding func RVAs.
    // IMAGE_BASE_RELOCATION  BaseRelocs[ANYSIZE_ARRAY];
    // ^Base relocations (RVA + Size + TO)
    // ^Padded with extra TOs for 4B alignment
    // ^BaseRelocSize size in bytes
} IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION, *PIMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION;

typedef struct _IMAGE_BDD_DYNAMIC_RELOCATION
{
    USHORT Left;  // Index of FALSE edge in BDD array
    USHORT Right; // Index of TRUE edge in BDD array
    ULONG  Value; // Either FeatureNumber or Index into RVAs array
} IMAGE_BDD_DYNAMIC_RELOCATION, *PIMAGE_BDD_DYNAMIC_RELOCATION;

// Function override relocation types in DVRT records.
#define IMAGE_FUNCTION_OVERRIDE_INVALID         0
#define IMAGE_FUNCTION_OVERRIDE_X64_REL32       1  // 32-bit relative address from byte following reloc
#define IMAGE_FUNCTION_OVERRIDE_ARM64_BRANCH26  2  // 26 bit offset << 2 & sign ext. for B & BL
#define IMAGE_FUNCTION_OVERRIDE_ARM64_THUNK     3
#endif

#if !defined(NTDDI_WIN11_GE) || (NTDDI_VERSION < NTDDI_WIN11_GE)
#define IMAGE_DLLCHARACTERISTICS_EX_FORWARD_CFI_COMPAT                          0x40
#define IMAGE_DLLCHARACTERISTICS_EX_HOTPATCH_COMPATIBLE                         0x80
#endif

EXTERN_C_END
