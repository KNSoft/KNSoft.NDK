#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

// CURDIR Handle | Flags
#define RTL_USER_PROC_CURDIR_CLOSE      0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT    0x00000003

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _CURDIR64
{
    UNICODE_STRING64 DosPath;
    VOID* POINTER_64 Handle;
} CURDIR64, *PCURDIR64;

typedef struct _CURDIR32
{
    UNICODE_STRING32 DosPath;
    VOID* POINTER_32 Handle;
} CURDIR32, *PCURDIR32;

// RTL_DRIVE_LETTER_CURDIR Flags
#define RTL_MAX_DRIVE_LETTERS   32
#define RTL_DRIVE_LETTER_VALID  ((USHORT)0x0001)

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR64
{
    USHORT Flags;
    USHORT Length;
    UINT TimeStamp;
    STRING64 DosPath;
} RTL_DRIVE_LETTER_CURDIR64, *PRTL_DRIVE_LETTER_CURDIR64;

typedef struct _RTL_DRIVE_LETTER_CURDIR32
{
    USHORT Flags;
    USHORT Length;
    UINT TimeStamp;
    STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, *PRTL_DRIVE_LETTER_CURDIR32;

#define RTL_USER_PROC_DETACHED_PROCESS      ((HANDLE)(LONG_PTR)-1)
#define RTL_USER_PROC_CREATE_NEW_CONSOLE    ((HANDLE)(LONG_PTR)-2)
#define RTL_USER_PROC_CREATE_NO_WINDOW      ((HANDLE)(LONG_PTR)-3)

typedef enum RTL_USER_PROC_FLAGS
{
    RTL_USER_PROC_PARAMS_NORMALIZED = 0x1,
    RTL_USER_PROC_FLAG_INHERITED    = 0x100,
    RTL_USER_PROC_SECURE_PROCESS    = 0x2000000,
    RTL_USER_PROC_APPX_CONTEXT      = 0x8000000,
    RTL_USER_PROC_PROTECTED_PROCESS = 0x80000000,
} RTL_USER_PROC_FLAGS;

typedef enum RTL_USER_DEBUG_FLAGS
{
    RTL_USER_PROC_DEBUG_PROCESS = 0x1,
    RTL_USER_PROC_DEBUG_ONLY_THIS_PROCESS = 0x2,
} RTL_USER_DEBUG_FLAGS;

typedef enum _RTL_USER_PROC_CONSOLE_FLAGS
{
    RTL_USER_PROC_CONSOLE_FLAG_IGNORE_CTRL_C  = 0x1,
    RTL_USER_PROC_CONSOLE_FLAG_SANITIZE_STDIO = 0x2,
    RTL_USER_PROC_CONSOLE_FLAG_CLOSE_STDIO    = 0x4,
} RTL_USER_PROC_CONSOLE_FLAGS;

typedef enum _RTL_USER_PROC_WINDOW_FLAGS
{
    RTL_USER_PROC_WINDOW_FLAG_USESHOWWINDOW       = 0x001,
    RTL_USER_PROC_WINDOW_FLAG_USESIZE             = 0x002,
    RTL_USER_PROC_WINDOW_FLAG_USEPOSITION         = 0x004,
    RTL_USER_PROC_WINDOW_FLAG_USECOUNTCHARS       = 0x008,
    RTL_USER_PROC_WINDOW_FLAG_USEFILLATTRIBUTE    = 0x010,
    RTL_USER_PROC_WINDOW_FLAG_USESTDHANDLES       = 0x100,
    RTL_USER_PROC_WINDOW_FLAG_HASSHELLDATA_STDIN  = 0x200,
    RTL_USER_PROC_WINDOW_FLAG_HASSHELLDATA_STDOUT = 0x400,
} _RTL_USER_PROC_WINDOW_FLAGS;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags; // RTL_USER_PROC_FLAGS
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags; // RTL_USER_PROC_CONSOLE_FLAGS
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags; // RTL_USER_PROC_WINDOW_FLAGS
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads; // THRESHOLD

    UNICODE_STRING RedirectionDllName; // REDSTONE5
    UNICODE_STRING HeapPartitionName; // 19H1
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum; // 20H1
    ULONG HeapMemoryTypeMask; // WIN11 22H2
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    VOID* POINTER_64 ConsoleHandle;
    ULONG ConsoleFlags;
    VOID* POINTER_64 StandardInput;
    VOID* POINTER_64 StandardOutput;
    VOID* POINTER_64 StandardError;
    CURDIR64 CurrentDirectory;
    UNICODE_STRING64 DllPath;
    UNICODE_STRING64 ImagePathName;
    UNICODE_STRING64 CommandLine;
    WCHAR* POINTER_64 Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING64 WindowTitle;
    UNICODE_STRING64 DesktopInfo;
    UNICODE_STRING64 ShellInfo;
    UNICODE_STRING64 RuntimeData;
    RTL_DRIVE_LETTER_CURDIR64 CurrentDirectores[32];
    ULONGLONG EnvironmentSize;
    ULONGLONG EnvironmentVersion;
    VOID* POINTER_64 PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING64 RedirectionDllName;
    UNICODE_STRING64 HeapPartitionName;
    ULONGLONG* POINTER_64 DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask;
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    VOID* POINTER_32 ConsoleHandle;
    ULONG ConsoleFlags;
    VOID* POINTER_32 StandardInput;
    VOID* POINTER_32 StandardOutput;
    VOID* POINTER_32 StandardError;
    CURDIR32 CurrentDirectory;
    UNICODE_STRING32 DllPath;
    UNICODE_STRING32 ImagePathName;
    UNICODE_STRING32 CommandLine;
    WCHAR* POINTER_32 Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING32 WindowTitle;
    UNICODE_STRING32 DesktopInfo;
    UNICODE_STRING32 ShellInfo;
    UNICODE_STRING32 RuntimeData;
    RTL_DRIVE_LETTER_CURDIR32 CurrentDirectores[32];
    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    VOID* POINTER_32 PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING32 RedirectionDllName;
    UNICODE_STRING32 HeapPartitionName;
    ULONGLONG* POINTER_32 DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

/**
 * A pointer to a user-defined function that serves as the starting routine for a new thread.
 *
 * \param ThreadParameter A pointer to a variable that is passed to the thread.
 * \return NTSTATUS Successful or errant status.
 */
typedef
_Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS
NTAPI
USER_THREAD_START_ROUTINE(
    _In_ PVOID ThreadParameter);
typedef USER_THREAD_START_ROUTINE *PUSER_THREAD_START_ROUTINE;

/**
 * The INITIAL_TEB structure contains information about the initial stack for a thread.
 * This structure is used when creating a new thread to specify the stack boundaries and allocation base.
 * It also contains information about the previous stack if the thread is being recreated.
 */
typedef struct _INITIAL_TEB
{
    struct
    {
        PVOID OldStackBase;     // Pointer to the base address of the previous stack.
        PVOID OldStackLimit;    // Pointer to the limit address of the previous stack.
    } OldInitialTeb;
    PVOID StackBase;            // Pointer to the base address of the new stack.
    PVOID StackLimit;           // Pointer to the limit address of the new stack.
    PVOID StackAllocationBase;  // Pointer to the base address where the stack was allocated.
} INITIAL_TEB, *PINITIAL_TEB;

/**
 * The PS_PROTECTION structure is used to define the protection level of a process.
 */
typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;

EXTERN_C_END
