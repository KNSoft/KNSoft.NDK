#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

//
// Virtualization // since REDSTONE
//

// rev
#define VR_DEVICE_NAME L"\\Device\\VRegDriver"

// rev
#define IOCTL_VR_INITIALIZE_JOB_FOR_VREG            CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_INITIALIZE_JOB_FOR_VREG
#define IOCTL_VR_LOAD_DIFFERENCING_HIVE             CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_LOAD_DIFFERENCING_HIVE
#define IOCTL_VR_CREATE_NAMESPACE_NODE              CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_CREATE_NAMESPACE_NODE
#define IOCTL_VR_MODIFY_FLAGS                       CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_MODIFY_FLAGS
#define IOCTL_VR_CREATE_MULTIPLE_NAMESPACE_NODES    CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_CREATE_MULTIPLE_NAMESPACE_NODES
#define IOCTL_VR_UNLOAD_DYNAMICALLY_LOADED_HIVES    CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_UNLOAD_DYNAMICALLY_LOADED_HIVES
#define IOCTL_VR_GET_VIRTUAL_ROOT_KEY               CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_GET_VIRTUAL_ROOT; out: VR_GET_VIRTUAL_ROOT_RESULT
#define IOCTL_VR_LOAD_DIFFERENCING_HIVE_FOR_HOST    CTL_CODE(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_LOAD_DIFFERENCING_HIVE_FOR_HOST
#define IOCTL_VR_UNLOAD_DIFFERENCING_HIVE_FOR_HOST  CTL_CODE(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS) // in: VR_UNLOAD_DIFFERENCING_HIVE_FOR_HOST

// private
/**
 * VR_INITIALIZE_JOB_FOR_VREG is used with the VReg driver to associate a job object
 * with the virtualization driver instance.
 */
typedef struct _VR_INITIALIZE_JOB_FOR_VREG
{
    HANDLE Job;
} VR_INITIALIZE_JOB_FOR_VREG, *PVR_INITIALIZE_JOB_FOR_VREG;

// rev
#define VR_FLAG_INHERIT_TRUST_CLASS 0x00000001
#define VR_FLAG_WRITE_THROUGH_HIVE 0x00000002 // since REDSTONE2
#define VR_FLAG_LOCAL_MACHINE_TRUST_CLASS 0x00000004 // since 21H1

// rev + private
/**
 * VR_LOAD_DIFFERENCING_HIVE describes parameters for loading a differencing hive
 * for the virtualization driver.
 *
 * The structure contains job handle, path length fields, flags and an inline
 * buffer with wide-character strings for the paths.
 */
typedef struct _VR_LOAD_DIFFERENCING_HIVE
{
    HANDLE Job;
    ULONG NextLayerIsHost;
    ULONG Flags; // VR_FLAG_*
    ULONG LoadFlags; // NtLoadKeyEx flags
    USHORT KeyPathLength;
    USHORT HivePathLength;
    USHORT NextLayerKeyPathLength;
    HANDLE FileAccessToken; // since 20H1
    WCHAR Strings[ANYSIZE_ARRAY];
    // ...
    // WCHAR KeyPath[1];
    // WCHAR HivePath[1];
    // WCHAR NextLayerKeyPath[1];
} VR_LOAD_DIFFERENCING_HIVE, *PVR_LOAD_DIFFERENCING_HIVE;

// rev + private
/**
 * VR_CREATE_NAMESPACE_NODE contains parameters for creating a namespace node
 * that maps a container path to a host path for virtualized registry access.
 */
typedef struct _VR_CREATE_NAMESPACE_NODE
{
    HANDLE Job;
    USHORT ContainerPathLength;
    USHORT HostPathLength;
    ULONG Flags;
    ACCESS_MASK AccessMask; // since 20H1
    WCHAR Strings[ANYSIZE_ARRAY];
    // ...
    // WCHAR ContainerPath[1];
    // WCHAR HostPath[1];
} VR_CREATE_NAMESPACE_NODE, *PVR_CREATE_NAMESPACE_NODE;

// private
/**
 * VR_MODIFY_FLAGS specifies flags to add or remove for a given job in the
 * virtualization driver.
 */
typedef struct _VR_MODIFY_FLAGS
{
    HANDLE Job;
    ULONG AddFlags;
    ULONG RemoveFlags;
} VR_MODIFY_FLAGS, *PVR_MODIFY_FLAGS;

// private
/**
 * NAMESPACE_NODE_DATA describes a single namespace node entry containing access
 * mask, path lengths, flags and inline strings for paths.
 */
typedef struct _NAMESPACE_NODE_DATA
{
    ACCESS_MASK AccessMask;
    USHORT ContainerPathLength;
    USHORT HostPathLength;
    ULONG Flags;
    WCHAR Strings[ANYSIZE_ARRAY];
    // ...
    // WCHAR ContainerPath[1];
    // WCHAR HostPath[1];
} NAMESPACE_NODE_DATA, *PNAMESPACE_NODE_DATA;

// private
/**
 * VR_CREATE_MULTIPLE_NAMESPACE_NODES is used to create multiple namespace nodes
 * in a single operation. It contains the job handle, number of keys and an
 * inline array of NAMESPACE_NODE_DATA items.
 */
typedef struct _VR_CREATE_MULTIPLE_NAMESPACE_NODES
{
    HANDLE Job;
    ULONG NumNewKeys;
    NAMESPACE_NODE_DATA Keys[1];
} VR_CREATE_MULTIPLE_NAMESPACE_NODES, *PVR_CREATE_MULTIPLE_NAMESPACE_NODES;

// private
/**
 * VR_UNLOAD_DYNAMICALLY_LOADED_HIVES requests unloading of dynamically loaded
 * differencing hives for a job.
 */
typedef struct _VR_UNLOAD_DYNAMICALLY_LOADED_HIVES
{
    HANDLE Job;
} VR_UNLOAD_DYNAMICALLY_LOADED_HIVES, *PVR_UNLOAD_DYNAMICALLY_LOADED_HIVES;

// rev
#define VR_KEY_COMROOT 0          // \Registry\ComRoot\Classes
#define VR_KEY_MACHINE_SOFTWARE 1 // \Registry\Machine\Software // since REDSTONE2
#define VR_KEY_CONTROL_SET 2      // \Registry\Machine\System\ControlSet001 // since REDSTONE2

// rev
/**
 * VR_GET_VIRTUAL_ROOT is used to request a virtual root key for a given job
 * and index (VR_KEY_*).
 */
typedef struct _VR_GET_VIRTUAL_ROOT
{
    HANDLE Job;
    ULONG Index; // VR_KEY_* // since REDSTONE2
} VR_GET_VIRTUAL_ROOT, *PVR_GET_VIRTUAL_ROOT;

// rev
/**
 * VR_GET_VIRTUAL_ROOT_RESULT contains the resulting key handle returned by
 * a VR_GET_VIRTUAL_ROOT request.
 */
typedef struct _VR_GET_VIRTUAL_ROOT_RESULT
{
    HANDLE Key;
} VR_GET_VIRTUAL_ROOT_RESULT, *PVR_GET_VIRTUAL_ROOT_RESULT;

// rev
/**
 * VR_LOAD_DIFFERENCING_HIVE_FOR_HOST describes parameters to load a differencing
 * hive on behalf of a host. It contains flags, path lengths and inline string
 * buffers for the key and hive paths.
 */
typedef struct _VR_LOAD_DIFFERENCING_HIVE_FOR_HOST
{
    ULONG LoadFlags; // NtLoadKeyEx flags
    ULONG Flags; // VR_FLAG_* // since REDSTONE2
    USHORT KeyPathLength;
    USHORT HivePathLength;
    USHORT NextLayerKeyPathLength;
    HANDLE FileAccessToken; // since 20H1
    WCHAR Strings[ANYSIZE_ARRAY];
    // ...
    // WCHAR KeyPath[1];
    // WCHAR HivePath[1];
    // WCHAR NextLayerKeyPath[1];
} VR_LOAD_DIFFERENCING_HIVE_FOR_HOST, *PVR_LOAD_DIFFERENCING_HIVE_FOR_HOST;

// rev
/**
 * VR_UNLOAD_DIFFERENCING_HIVE_FOR_HOST is used to request unloading of a
 * differencing hive for the host. It contains the target key path length and
 * path buffer.
 */
typedef struct _VR_UNLOAD_DIFFERENCING_HIVE_FOR_HOST
{
    ULONG Reserved;
    USHORT TargetKeyPathLength;
    WCHAR TargetKeyPath[ANYSIZE_ARRAY];
} VR_UNLOAD_DIFFERENCING_HIVE_FOR_HOST, *PVR_UNLOAD_DIFFERENCING_HIVE_FOR_HOST;

EXTERN_C_END
