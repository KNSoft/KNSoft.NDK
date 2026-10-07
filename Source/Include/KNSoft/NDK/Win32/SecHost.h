#pragma once

#include "../NT/MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Specifies the subprocess-tag information to query.
 */
typedef enum _TAG_INFO_LEVEL
{
    /** Resolves a service tag in a process to its service name. */
    eTagInfoLevelNameFromTag = 1, // TAG_INFO_NAME_FROM_TAG
    /** Returns the service names that reference a module in a process. */
    eTagInfoLevelNamesReferencingModule, // TAG_INFO_NAMES_REFERENCING_MODULE
    /** Returns every service-tag mapping for a process. */
    eTagInfoLevelNameTagMapping, // TAG_INFO_NAME_TAG_MAPPING
    /** Marks the upper bound of valid information levels. */
    eTagInfoLevelMax
} TAG_INFO_LEVEL;

/**
 * Specifies the type of a subprocess tag.
 */
typedef enum _TAG_TYPE
{
    /** The tag identifies a Windows service. */
    eTagTypeService = 1,
    /** Marks the upper bound of valid tag types. */
    eTagTypeMax
} TAG_TYPE;

/**
 * Contains the input parameters for a service-name query by tag.
 */
typedef struct _TAG_INFO_NAME_FROM_TAG_IN_PARAMS
{
    /** The identifier of the process that owns the tag. */
    ULONG dwPid;
    /** The service tag to resolve. */
    ULONG dwTag;
} TAG_INFO_NAME_FROM_TAG_IN_PARAMS, *PTAG_INFO_NAME_FROM_TAG_IN_PARAMS;

/**
 * Receives the result of a service-name query by tag.
 */
typedef struct _TAG_INFO_NAME_FROM_TAG_OUT_PARAMS
{
    /** The type of the resolved tag. */
    TAG_TYPE eTagType;
    /**
     * The null-terminated service name. Free this buffer with LocalFree when it
     * is no longer required.
     */
    PWSTR pszName;
} TAG_INFO_NAME_FROM_TAG_OUT_PARAMS, *PTAG_INFO_NAME_FROM_TAG_OUT_PARAMS;

/**
 * Contains the input and output parameters for eTagInfoLevelNameFromTag.
 */
typedef struct _TAG_INFO_NAME_FROM_TAG
{
    /** The query input. dwPid and dwTag must be nonzero. */
    TAG_INFO_NAME_FROM_TAG_IN_PARAMS InParams;
    /** The query result. pszName must be NULL on input. */
    TAG_INFO_NAME_FROM_TAG_OUT_PARAMS OutParams;
} TAG_INFO_NAME_FROM_TAG, *PTAG_INFO_NAME_FROM_TAG;

/**
 * Contains the input parameters for a module-reference query.
 */
typedef struct _TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS
{
    /** The identifier of the process to inspect. This value must be nonzero. */
    ULONG dwPid;
    /** The null-terminated module name to query. This pointer must not be NULL. */
    PCWSTR pszModule;
} TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS, *PTAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS;

/**
 * Receives the result of a module-reference query.
 */
typedef struct _TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS
{
    /** The type of the returned tags. */
    TAG_TYPE eTagType;
    /**
     * A sequence of null-terminated service names terminated by an additional
     * null character. Free this buffer with LocalFree when it is no longer
     * required.
     */
    PCWSTR pmszNames;
} TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS, *PTAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS;

/**
 * Contains the input and output parameters for
 * eTagInfoLevelNamesReferencingModule.
 */
typedef struct _TAG_INFO_NAMES_REFERENCING_MODULE
{
    /** The query input. */
    TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS InParams;
    /** The query result. pmszNames must be NULL on input. */
    TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS OutParams;
} TAG_INFO_NAMES_REFERENCING_MODULE, *PTAG_INFO_NAMES_REFERENCING_MODULE;

/**
 * Contains the input parameters for a process service-tag mapping query.
 */
typedef struct _TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS
{
    /** The identifier of the process to inspect. */
    ULONG dwPid;
} TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS, *PTAG_INFO_NAME_TAG_MAPPING_IN_PARAMS;

/**
 * Describes one subprocess-tag mapping.
 */
typedef struct _TAG_INFO_NAME_TAG_MAPPING_ELEMENT
{
    /** The type of the tag. */
    TAG_TYPE eTagType;
    /** The subprocess tag value. */
    ULONG dwTag;
    /** The null-terminated service name associated with the tag. */
    PWSTR pszName;
    /** The null-terminated service group name, if one is present. */
    PWSTR pszGroupName;
} TAG_INFO_NAME_TAG_MAPPING_ELEMENT, *PTAG_INFO_NAME_TAG_MAPPING_ELEMENT;

/**
 * Contains the mappings returned for a process.
 */
typedef struct _TAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS
{
    /** The number of entries in pNameTagMappingElements. */
    ULONG cElements;
    /** An array of cElements tag-mapping entries. */
    PTAG_INFO_NAME_TAG_MAPPING_ELEMENT pNameTagMappingElements;
} TAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS, *PTAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS;

/**
 * Contains the input and output parameters for eTagInfoLevelNameTagMapping.
 */
typedef struct _TAG_INFO_NAME_TAG_MAPPING
{
    /** The query input. */
    TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS InParams;
    /**
     * The returned mapping information. This pointer must be NULL on input.
     * Free the returned allocation with LocalFree when it is no longer required.
     */
    PTAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS pOutParams;
} TAG_INFO_NAME_TAG_MAPPING, *PTAG_INFO_NAME_TAG_MAPPING;

/**
 * Queries subprocess-tag information from the Service Control Manager.
 *
 * @param MachineName Reserved. This parameter is not used.
 * @param InfoLevel The kind of information to query. This determines the
 * structure supplied in TagInfo:
 * - eTagInfoLevelNameFromTag: PTAG_INFO_NAME_FROM_TAG.
 * - eTagInfoLevelNamesReferencingModule: PTAG_INFO_NAMES_REFERENCING_MODULE.
 * - eTagInfoLevelNameTagMapping: PTAG_INFO_NAME_TAG_MAPPING.
 * @param TagInfo A pointer to the information-level-specific input/output
 * structure.
 * @return A Win32 error code. ERROR_SUCCESS is returned on success.
 */
_Must_inspect_result_
ULONG
WINAPI
I_QueryTagInformation(
    _In_opt_ PCWSTR MachineName,
    _In_ TAG_INFO_LEVEL InfoLevel,
    _Inout_ PVOID TagInfo);

/**
 * Defines a callback compatible with I_QueryTagInformation.
 *
 * @param MachineName Reserved. This parameter is not used.
 * @param InfoLevel The kind of subprocess-tag information to query.
 * @param TagInfo A pointer to the information-level-specific input/output
 * structure.
 * @return A Win32 error code. ERROR_SUCCESS is returned on success.
 */
typedef _Function_class_(QUERY_TAG_INFORMATION)
_Must_inspect_result_
ULONG
NTAPI
QUERY_TAG_INFORMATION(
    _In_opt_ PCWSTR MachineName,
    _In_ TAG_INFO_LEVEL InfoLevel,
    _Inout_ PVOID TagInfo
);
typedef QUERY_TAG_INFORMATION* PQUERY_TAG_INFORMATION;

EXTERN_C_END
