#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

typedef enum _HOT_PATCH_INFORMATION_CLASS
{
    ManageHotPatchLoadPatch = 0, // MANAGE_HOT_PATCH_LOAD_PATCH
    ManageHotPatchUnloadPatch = 1, // MANAGE_HOT_PATCH_UNLOAD_PATCH
    ManageHotPatchQueryPatches = 2, // MANAGE_HOT_PATCH_QUERY_PATCHES
    ManageHotPatchLoadPatchForUser = 3, // MANAGE_HOT_PATCH_LOAD_PATCH
    ManageHotPatchUnloadPatchForUser = 4, // MANAGE_HOT_PATCH_UNLOAD_PATCH
    ManageHotPatchQueryPatchesForUser = 5, // MANAGE_HOT_PATCH_QUERY_PATCHES
    ManageHotPatchQueryActivePatches = 6, // MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES
    ManageHotPatchApplyImagePatch = 7, // MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH
    ManageHotPatchQuerySinglePatch = 8, // MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH
    ManageHotPatchCheckEnabled = 9, // MANAGE_HOT_PATCH_CHECK_ENABLED
    ManageHotPatchCreatePatchSection = 10, // MANAGE_HOT_PATCH_CREATE_PATCH_SECTION
    ManageHotPatchMax
} HOT_PATCH_INFORMATION_CLASS;

/**
 * The HOT_PATCH_IMAGE_INFO structure contains identifying information about a hot patch image.
 */
typedef struct _HOT_PATCH_IMAGE_INFO
{
    ULONG CheckSum;             // The checksum of the hot patch image.
    ULONG TimeDateStamp;        // The time/date stamp of the hot patch image.
} HOT_PATCH_IMAGE_INFO, *PHOT_PATCH_IMAGE_INFO;

#define MANAGE_HOT_PATCH_LOAD_PATCH_VERSION 1

/**
 * The MANAGE_HOT_PATCH_LOAD_PATCH structure describes parameters for loading a hot patch.
 */
typedef struct _MANAGE_HOT_PATCH_LOAD_PATCH
{
    ULONG Version;                              // Structure version. Must be MANAGE_HOT_PATCH_LOAD_PATCH_VERSION.
    UNICODE_STRING PatchPath;                   // The path to the hot patch file.
    union
    {
        SID Sid;                                // The SID of the user for whom the patch is being loaded.
        UCHAR Buffer[SECURITY_MAX_SID_SIZE];    // Buffer for the SID.
    } UserSid;
    HOT_PATCH_IMAGE_INFO BaseInfo;              // Identifying information about the base image to patch.
} MANAGE_HOT_PATCH_LOAD_PATCH, *PMANAGE_HOT_PATCH_LOAD_PATCH;

#define MANAGE_HOT_PATCH_UNLOAD_PATCH_VERSION 1

/**
 * The MANAGE_HOT_PATCH_UNLOAD_PATCH structure describes parameters for unloading a hot patch.
 */
typedef struct _MANAGE_HOT_PATCH_UNLOAD_PATCH
{
    ULONG Version;                  // Structure version. Must be MANAGE_HOT_PATCH_UNLOAD_PATCH_VERSION.
    HOT_PATCH_IMAGE_INFO BaseInfo;  // Identifying information about the base image to unpatch.
    union
    {
        SID Sid;                    // The SID of the user for whom the patch is being unloaded.
        UCHAR Buffer[SECURITY_MAX_SID_SIZE]; // Buffer for the SID.
    } UserSid;
} MANAGE_HOT_PATCH_UNLOAD_PATCH, *PMANAGE_HOT_PATCH_UNLOAD_PATCH;

#define MANAGE_HOT_PATCH_QUERY_PATCHES_VERSION 1

/**
 * The MANAGE_HOT_PATCH_QUERY_PATCHES structure is used to query information about loaded hot patches.
 */
typedef struct _MANAGE_HOT_PATCH_QUERY_PATCHES
{
    ULONG Version;                           // Structure version. Must be MANAGE_HOT_PATCH_QUERY_PATCHES_VERSION.
    union
    {
        SID Sid;                             // The SID of the user whose patches are being queried.
        UCHAR Buffer[SECURITY_MAX_SID_SIZE]; // Buffer for the SID.
    } UserSid;
    ULONG PatchCount;                        // The number of patches found.
    PUNICODE_STRING PatchPathStrings;        // Pointer to an array of patch path strings.
    PHOT_PATCH_IMAGE_INFO BaseInfos;         // Pointer to an array of patch image info structures.
} MANAGE_HOT_PATCH_QUERY_PATCHES, *PMANAGE_HOT_PATCH_QUERY_PATCHES;

#define MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES_VERSION 1

/**
 * The MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES structure is used to query active hot patches for a process.
 */
typedef struct _MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES
{
    ULONG Version;                      // Structure version. Must be MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES_VERSION.
    HANDLE ProcessHandle;               // Handle to the process being queried.
    ULONG PatchCount;                   // The number of active patches.
    PUNICODE_STRING PatchPathStrings;   // Pointer to an array of patch path strings.
    PHOT_PATCH_IMAGE_INFO BaseInfos;    // Pointer to an array of patch image info structures.
    PULONG PatchSequenceNumbers;        // Pointer to an array of patch sequence numbers.
} MANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES, *PMANAGE_HOT_PATCH_QUERY_ACTIVE_PATCHES;

#define MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH_VERSION 1

/**
 * The MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH structure describes parameters for applying a hot patch to an image.
 */
typedef struct _MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH
{
    ULONG Version;                              // Structure version. Must be MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH_VERSION.
    union
    {
        ULONG AllFlags;                         // All flags as a ULONG.
        struct
        {
            ULONG ApplyReversePatches : 1;      // If set, apply reverse patches.
            ULONG ApplyForwardPatches : 1;      // If set, apply forward patches.
            ULONG Spare : 29;
        };
    };
    HANDLE ProcessHandle;                       // Handle to the process to patch.
    PVOID BaseImageAddress;                     // Base address of the image to patch.
    PVOID PatchImageAddress;                    // Address of the patch image.
} MANAGE_HOT_PATCH_APPLY_IMAGE_PATCH, *PMANAGE_HOT_PATCH_APPLY_IMAGE_PATCH;

#define MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH_VERSION 1

/**
 * The MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH structure is used to query a single hot patch.
 */
typedef struct _MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH
{
    ULONG Version;                  // Structure version. Must be MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH_VERSION.
    HANDLE ProcessHandle;           // Handle to the process being queried.
    PVOID BaseAddress;              // Base address of the image being queried.
    ULONG Flags;                    // Query flags.
    UNICODE_STRING PatchPathString; // The path to the patch being queried.
} MANAGE_HOT_PATCH_QUERY_SINGLE_PATCH, *PMANAGE_HOT_PATCH_QUERY_SINGLE_PATCH;

#define MANAGE_HOT_PATCH_CHECK_ENABLED_VERSION 1

/**
 * The MANAGE_HOT_PATCH_CHECK_ENABLED structure is used to check if hot patching is enabled.
 */
typedef struct _MANAGE_HOT_PATCH_CHECK_ENABLED
{
    ULONG Version;          // Structure version. Must be MANAGE_HOT_PATCH_CHECK_ENABLED_VERSION.
    ULONG Flags;            // Flags for the check operation.
} MANAGE_HOT_PATCH_CHECK_ENABLED, *PMANAGE_HOT_PATCH_CHECK_ENABLED;

#define MANAGE_HOT_PATCH_CREATE_PATCH_SECTION_VERSION 1

/**
 * The MANAGE_HOT_PATCH_CREATE_PATCH_SECTION structure describes parameters for creating a hot patch section.
 */
typedef struct _MANAGE_HOT_PATCH_CREATE_PATCH_SECTION
{
    ULONG Version;                  // Structure version. Must be MANAGE_HOT_PATCH_CREATE_PATCH_SECTION_VERSION.
    ULONG Flags;                    // Creation flags.
    ACCESS_MASK DesiredAccess;      // Desired access mask for the section.
    ULONG PageProtection;           // Page protection flags.
    ULONG AllocationAttributes;     // Allocation attributes.
    PVOID BaseImageAddress;         // Base address of the image for the patch section.
    HANDLE SectionHandle;           // Handle to the created section.
} MANAGE_HOT_PATCH_CREATE_PATCH_SECTION, *PMANAGE_HOT_PATCH_CREATE_PATCH_SECTION;

#if (NTDDI_VERSION >= NTDDI_WIN11_ZN)
// rev
/**
 * The NtManageHotPatch routine manages hot patching operations in the system.
 *
 * \param[in] HotPatchInformationClass Specifies the type of hot patch information being queried or set.
 * \param[out] HotPatchInformation A pointer to a buffer that receives or contains the hot patch information, depending on the operation.
 * \param[in] HotPatchInformationLength The size, in bytes, of the HotPatchInformation buffer.
 * \param[out] ReturnLength Optional pointer to a variable that receives the number of bytes written to the HotPatchInformation buffer.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSCALLAPI
NTSTATUS
NTAPI
NtManageHotPatch(
    _In_ HOT_PATCH_INFORMATION_CLASS HotPatchInformationClass,
    _Out_writes_bytes_opt_(HotPatchInformationLength) PVOID HotPatchInformation,
    _In_ ULONG HotPatchInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
#endif

EXTERN_C_END
