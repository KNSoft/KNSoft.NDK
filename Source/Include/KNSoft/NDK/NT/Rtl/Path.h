#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * Represents a reference-counted current directory handle.
 */
typedef struct _RTLP_CURDIR_REF
{
    LONG ReferenceCount;
    HANDLE DirectoryHandle;
} RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

/**
 * Describes a path expressed relative to a containing directory, as produced by path parsing routines.
 */
typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

/**
 * Identifies the syntactic type of a DOS path.
 */
typedef enum _RTL_PATH_TYPE
{
    RtlPathTypeUnknown,
    RtlPathTypeUncAbsolute,
    RtlPathTypeDriveAbsolute,
    RtlPathTypeDriveRelative,
    RtlPathTypeRooted,
    RtlPathTypeRelative,
    RtlPathTypeLocalDevice,
    RtlPathTypeRootLocalDevice
} RTL_PATH_TYPE;

// Data exports (ntdll.lib/ntdllp.lib)

/**
 * Well-known module name and path-separator string constants.
 */
NTSYSAPI PCWSTR RtlNtdllName;
NTSYSAPI UNICODE_STRING RtlDosPathSeperatorsString;
NTSYSAPI UNICODE_STRING RtlAlternateDosPathSeperatorString;
NTSYSAPI UNICODE_STRING RtlNtPathSeperatorString;

/**
 * The RtlDetermineDosPathNameType_U routine determines the type of Dos or Win32 path type for the specified filename.
 *
 * \param DosFileName A pointer to the buffer that contains the Dos or Win32 filename.
 * \return The return value specifies the path type for the specified file.
 */
NTSYSAPI
RTL_PATH_TYPE
NTAPI
RtlDetermineDosPathNameType_U(
    _In_ PCWSTR DosFileName
);

/**
 * The RtlIsDosDeviceName_U routine examines the Dos format file name and determines if it is a Dos device name.
 *
 * \param DosFileName A pointer to the buffer that contains the DOS or Win32 filename.
 * \return A nonzero value when the Dos file name is the name of a Dos device. The high order 16 bits is the offset
 * in the input buffer where the dos device name beings and the low order 16 bits is the length of the device name (excluding any optional trailing colon).
 * Otherwise, A zero value when the Dos file name is not the name of a Dos device.
 * \sa https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlisdosdevicename_u
 */
NTSYSAPI
ULONG
NTAPI
RtlIsDosDeviceName_U(
    _In_ PCWSTR DosFileName
);

/**
 * The RtlGetFullPathName_U routine retrieves the full path and file name of the specified file.
 *
 * \param FileName A pointer to the buffer that contains the relative filename.
 * \param BufferLength The length of the buffer for the file path string, in WCHARs. The buffer length must include room for a terminating null character.
 * \param Buffer A pointer to the buffer that receives the file path string.
 * \param FilePart A pointer to a buffer that receives the address (within Buffer) of the final file name component in the path.
 * \return If the function succeeds, the return value specifies the number of characters that are written to the buffer, not including the terminating null character.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfullpathnamea
 */
NTSYSAPI
ULONG
NTAPI
RtlGetFullPathName_U(
    _In_ PCWSTR FileName,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _Out_opt_ PWSTR *FilePart
);

// rev
/**
 * The RtlGetFullPathName_UEx routine retrieves the full path and file name of the specified file.
 *
 * \param FileName A pointer to the buffer that contains the relative filename.
 * \param BufferLength The length of the buffer for the file path string, in WCHARs. The buffer length must include room for a terminating null character.
 * \param Buffer A pointer to the buffer that receives the file path string.
 * \param FilePart A pointer to a buffer that receives the address (within Buffer) of the final file name component in the path.
 * \param BytesRequired If the function succeeds, the return value specifies the number of characters that are written to the buffer, not including the terminating null character.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfullpathnamea
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetFullPathName_UEx(
    _In_ PCWSTR FileName,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ ULONG *BytesRequired
);

/**
 * The RtlGetFullPathName_UstrEx routine retrieves the full path and file name of the specified file as a counted
 * Unicode string.
 *
 * \param FileName A pointer to the file name to resolve.
 * \param StaticString A caller-supplied buffer that receives the full path if it is large enough.
 * \param DynamicString An optional buffer that receives an allocated string when the static buffer is too small.
 * \param StringUsed An optional pointer to a variable that receives which of the static or dynamic strings holds the
 * result.
 * \param FilePartPrefixCch An optional pointer to a variable that receives the length, in characters, of the path
 * preceding the file name.
 * \param NameInvalid An optional pointer to a variable that receives whether the name is invalid.
 * \param InputPathType A pointer to a variable that receives the RTL_PATH_TYPE of the input path.
 * \param BytesRequired An optional pointer to a variable that receives the number of bytes required for the full path.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetFullPathName_UstrEx(
    _In_ PUNICODE_STRING FileName,
    _Inout_ PUNICODE_STRING StaticString,
    _Out_opt_ PUNICODE_STRING DynamicString,
    _Out_opt_ PUNICODE_STRING *StringUsed,
    _Out_opt_ SIZE_T *FilePartPrefixCch,
    _Out_opt_ PBOOLEAN NameInvalid,
    _Out_ RTL_PATH_TYPE *InputPathType,
    _Out_opt_ SIZE_T *BytesRequired
);

/**
 * The RtlGetCurrentDirectory_U routine retrieves the current directory for the current process.
 *
 * \param BufferLength The length of the buffer for the current directory string, in WCHARs. The buffer length must include room for a terminating null character.
 * \param Buffer A pointer to the buffer that receives the current directory string.
 * \return If the function succeeds, the return value specifies the number of characters that are written to the buffer, not including the terminating null character.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcurrentdirectory
 */
NTSYSAPI
ULONG
NTAPI
RtlGetCurrentDirectory_U(
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer
);

/**
 * The RtlSetCurrentDirectory_U routine changes the current directory for the current process.
 *
 * \param PathName The path to the new current directory.
 * This parameter may specify a relative path or a full path. In either case, the full path of the specified directory is calculated and stored as the current directory.
 * \return If the function succeeds, the return value specifies the number of characters that are written to the buffer, not including the terminating null character.
 * \sa https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcurrentdirectory
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetCurrentDirectory_U(
    _In_ PUNICODE_STRING PathName
);

/**
 * The RtlGetLongestNtPathLength routine returns the length, in characters, of the longest possible NT path name.
 *
 * \return ULONG The maximum NT path length, in characters.
 */
NTSYSAPI
ULONG
NTAPI
RtlGetLongestNtPathLength(
    VOID
);

/**
 * Represents a growable memory buffer with a fixed-size static portion.
 */
typedef struct _RTL_BUFFER
{
    PUCHAR Buffer;
    PUCHAR StaticBuffer;
    SIZE_T Size;
    SIZE_T StaticSize;
} RTL_BUFFER, *PRTL_BUFFER;

/**
 * Represents a Unicode string backed by a growable RTL_BUFFER.
 */
typedef struct _RTL_UNICODE_STRING_BUFFER
{
    UNICODE_STRING String;
    RTL_BUFFER ByteBuffer;
    UCHAR MinimumStaticBufferForTerminalNul[2];
} RTL_UNICODE_STRING_BUFFER, *PRTL_UNICODE_STRING_BUFFER;

// rev
/**
 * The RtlNtPathNameToDosPathName routine converts an NT path name to its equivalent DOS path name.
 *
 * \param Flags Reserved. This parameter must be zero.
 * \param Path A pointer to a path buffer that contains the NT path on input and receives the DOS path on output.
 * \param Disposition An optional pointer to a variable that receives the DOS path type (as returned by
 * RtlDetermineDosPathNameType_U).
 * \param FilePart An optional pointer to a variable that receives a pointer to the file-name portion of the resulting
 * path.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlNtPathNameToDosPathName(
    _Reserved_ ULONG Flags,
    _Inout_ PRTL_UNICODE_STRING_BUFFER Path,
    _Out_opt_ PULONG Disposition, // RtlDetermineDosPathNameType_U
    _Inout_opt_ PWSTR* FilePart
);

/**
 * The RtlDosPathNameToNtPathName_U routine converts a DOS path name to its equivalent NT path name.
 *
 * \param DosFileName A pointer to the DOS path name to convert.
 * \param NtFileName A pointer to a UNICODE_STRING that receives the equivalent NT path name.
 * \param FilePart An optional pointer to a variable that receives a pointer to the file-name portion of the NT path.
 * \param RelativeName An optional pointer to a structure that receives relative-name information.
 * \return `TRUE` if the conversion succeeded, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlDosPathNameToNtPathName_U(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
);

/**
 * The RtlDosPathNameToNtPathName_U_WithStatus routine converts a DOS path name to its equivalent NT path name and
 * returns a status code.
 *
 * \param DosFileName A pointer to the DOS path name to convert.
 * \param NtFileName A pointer to a UNICODE_STRING that receives the equivalent NT path name.
 * \param FilePart An optional pointer to a variable that receives a pointer to the file-name portion of the NT path.
 * \param RelativeName An optional pointer to a structure that receives relative-name information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDosPathNameToNtPathName_U_WithStatus(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)
// rev
/**
 * The RtlDosLongPathNameToNtPathName_U_WithStatus routine converts a DOS long path name to its equivalent NT path name
 * and returns a status code.
 *
 * \param DosFileName A pointer to the DOS long path name to convert.
 * \param NtFileName A pointer to a UNICODE_STRING that receives the equivalent NT path name.
 * \param FilePart An optional pointer to a variable that receives a pointer to the file-name portion of the NT path.
 * \param RelativeName An optional pointer to a structure that receives relative-name information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDosLongPathNameToNtPathName_U_WithStatus(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
);
#endif

/**
 * The RtlDosPathNameToRelativeNtPathName_U routine converts a DOS path name to its equivalent NT path name, including
 * relative-name information.
 *
 * \param DosFileName A pointer to the DOS path name to convert.
 * \param NtFileName A pointer to a UNICODE_STRING that receives the equivalent NT path name.
 * \param FilePart An optional pointer to a variable that receives a pointer to the file-name portion of the NT path.
 * \param RelativeName An optional pointer to a structure that receives relative-name information.
 * \return `TRUE` if the conversion succeeded, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlDosPathNameToRelativeNtPathName_U(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
);

/**
 * The RtlDosPathNameToRelativeNtPathName_U_WithStatus routine converts a DOS path name to its equivalent NT path name,
 * including relative-name information, and returns a status code.
 *
 * \param DosFileName A pointer to the DOS path name to convert.
 * \param NtFileName A pointer to a UNICODE_STRING that receives the equivalent NT path name.
 * \param FilePart An optional pointer to a variable that receives a pointer to the file-name portion of the NT path.
 * \param RelativeName An optional pointer to a structure that receives relative-name information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDosPathNameToRelativeNtPathName_U_WithStatus(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3)
// rev
/**
 * The RtlDosLongPathNameToRelativeNtPathName_U_WithStatus routine converts a DOS long path name to its equivalent NT
 * path name, including relative-name information, and returns a status code.
 *
 * \param DosFileName A pointer to the DOS long path name to convert.
 * \param NtFileName A pointer to a UNICODE_STRING that receives the equivalent NT path name.
 * \param FilePart An optional pointer to a variable that receives a pointer to the file-name portion of the NT path.
 * \param RelativeName An optional pointer to a structure that receives relative-name information.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDosLongPathNameToRelativeNtPathName_U_WithStatus(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NtFileName,
    _Out_opt_ PWSTR *FilePart,
    _Out_opt_ PRTL_RELATIVE_NAME_U RelativeName
);
#endif

/**
 * The RtlReleaseRelativeName routine releases the resources associated with a relative-name structure previously
 * returned by one of the RtlDosPathNameToRelativeNtPathName routines.
 *
 * \param RelativeName A pointer to the relative-name structure to release.
 */
NTSYSAPI
VOID
NTAPI
RtlReleaseRelativeName(
    _Inout_ PRTL_RELATIVE_NAME_U RelativeName
);

/**
 * The RtlDosSearchPath_U routine searches a set of directories for the specified file.
 *
 * \param Path A pointer to the search path, consisting of one or more directories separated by semicolons.
 * \param FileName A pointer to the name of the file to locate.
 * \param Extension An optional default extension to append when the file name has none.
 * \param BufferLength The size, in bytes, of the output buffer.
 * \param Buffer A buffer that receives the full path of the located file.
 * \param FilePart An optional pointer to a variable that receives a pointer to the file-name portion of the result.
 * \return ULONG The length, in bytes, of the string copied to Buffer, or the required size if the buffer is too small.
 */
NTSYSAPI
ULONG
NTAPI
RtlDosSearchPath_U(
    _In_ PCWSTR Path,
    _In_ PCWSTR FileName,
    _In_opt_ PCWSTR Extension,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _Out_opt_ PWSTR *FilePart
);

/**
 * Flags for the RTL DOS path search routines.
 */
#define RTL_DOS_SEARCH_PATH_FLAG_APPLY_ISOLATION_REDIRECTION 0x00000001
#define RTL_DOS_SEARCH_PATH_FLAG_DISALLOW_DOT_RELATIVE_PATH_SEARCH 0x00000002
#define RTL_DOS_SEARCH_PATH_FLAG_APPLY_DEFAULT_EXTENSION_WHEN_NOT_RELATIVE_PATH_EVEN_IF_FILE_HAS_EXTENSION 0x00000004

/**
 * The RtlDosSearchPath_Ustr routine searches a set of directories for the specified file and returns the result as a
 * counted Unicode string.
 *
 * \param Flags Flags that control the search behavior.
 * \param Path A pointer to the search path, consisting of one or more directories separated by semicolons.
 * \param FileName A pointer to the name of the file to locate.
 * \param DefaultExtension An optional default extension to append when the file name has none.
 * \param StaticString A caller-supplied buffer that receives the result if it is large enough.
 * \param DynamicString An optional buffer that receives an allocated string when the static buffer is too small.
 * \param FullFileNameOut An optional pointer to a variable that receives a pointer to the full file name.
 * \param FilePartPrefixCch An optional pointer to a variable that receives the length, in characters, of the path
 * preceding the file name.
 * \param BytesRequired An optional pointer to a variable that receives the number of bytes required for the full path.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDosSearchPath_Ustr(
    _In_ ULONG Flags,
    _In_ PUNICODE_STRING Path,
    _In_ PUNICODE_STRING FileName,
    _In_opt_ PUNICODE_STRING DefaultExtension,
    _Out_opt_ PUNICODE_STRING StaticString,
    _Out_opt_ PUNICODE_STRING DynamicString,
    _Out_opt_ PCUNICODE_STRING *FullFileNameOut,
    _Out_opt_ SIZE_T *FilePartPrefixCch,
    _Out_opt_ SIZE_T *BytesRequired
);

/**
 * The RtlDoesFileExists_U routine determines whether the specified file exists.
 *
 * \param FileName A pointer to the name of the file to test.
 * \return `TRUE` if the file exists, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlDoesFileExists_U(
    _In_ PCWSTR FileName
);

// ros
/**
 * The RtlDosApplyFileIsolationRedirection_Ustr routine applies side-by-side (SxS) isolation redirection to the
 * specified file name.
 *
 * \param Flags Flags that control the redirection behavior.
 * \param OriginalName A pointer to the original file name to redirect.
 * \param Extension A pointer to the default extension to apply when the name has none.
 * \param StaticString An optional caller-supplied buffer that receives the redirected name if it is large enough.
 * \param DynamicString An optional buffer that receives an allocated string when the static buffer is too small.
 * \param NewName An optional pointer to a variable that receives a pointer to the redirected name.
 * \param NewFlags A pointer to a variable that receives flags describing the redirection result.
 * \param FileNameSize A pointer to a variable that receives the size, in bytes, of the redirected name.
 * \param RequiredLength A pointer to a variable that receives the number of bytes required for the redirected name.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlDosApplyFileIsolationRedirection_Ustr(
    _In_ ULONG Flags,
    _In_ PCUNICODE_STRING OriginalName,
    _In_ PCUNICODE_STRING Extension,
    _In_opt_ PCUNICODE_STRING StaticString,
    _In_opt_ PCUNICODE_STRING DynamicString,
    _In_opt_ PCUNICODE_STRING* NewName,
    _In_ PULONG NewFlags,
    _In_ PSIZE_T FileNameSize,
    _In_ PSIZE_T RequiredLength
);

/**
 * The RtlGetLengthWithoutLastFullDosOrNtPathElement routine computes the length of a path string excluding its last
 * full DOS or NT path element.
 *
 * \param Flags Reserved. This parameter must be zero.
 * \param PathString A pointer to the path string to examine.
 * \param Length A pointer to a variable that receives the length, in characters, of the path without its last element.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetLengthWithoutLastFullDosOrNtPathElement(
    _Reserved_ ULONG Flags,
    _In_ PUNICODE_STRING PathString,
    _Out_ PULONG Length
);

/**
 * The RtlGetLengthWithoutTrailingPathSeperators routine computes the length of a path string excluding any trailing
 * path separators.
 *
 * \param Flags Reserved. This parameter must be zero.
 * \param PathString A pointer to the path string to examine.
 * \param Length A pointer to a variable that receives the length, in characters, of the path without trailing
 * separators.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetLengthWithoutTrailingPathSeperators(
    _Reserved_ ULONG Flags,
    _In_ PUNICODE_STRING PathString,
    _Out_ PULONG Length
);

/**
 * Maintains state used when generating short (8.3) file names from long names.
 */
typedef struct _GENERATE_NAME_CONTEXT
{
    USHORT Checksum;
    BOOLEAN CheckSumInserted;
    UCHAR NameLength;
    WCHAR NameBuffer[8];
    ULONG ExtensionLength;
    WCHAR ExtensionBuffer[4];
    ULONG LastIndexValue;
} GENERATE_NAME_CONTEXT, *PGENERATE_NAME_CONTEXT;

// private
/**
 * The RtlGenerate8dot3Name routine generates a short (8.3) file name from the specified long file name.
 *
 * \param Name A pointer to the long file name from which the short name is generated.
 * \param AllowExtendedCharacters A boolean that specifies whether extended characters are permitted in the generated
 * name.
 * \param Context A pointer to a context structure that maintains state across successive generation attempts.
 * \param Name8dot3 A pointer to a UNICODE_STRING that receives the generated 8.3 name.
 * \return NTSTATUS Successful or errant status.
 * \sa https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgenerate8dot3name
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGenerate8dot3Name(
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN AllowExtendedCharacters,
    _Inout_ PGENERATE_NAME_CONTEXT Context,
    _Inout_ PUNICODE_STRING Name8dot3
);

#if (NTDDI_VERSION >= NTDDI_WIN8)

// private
/**
 * The RtlComputePrivatizedDllName_U routine computes the privatized (side-by-side) DLL file names for the specified
 * DLL.
 *
 * \param DllName A pointer to the name of the DLL to privatize.
 * \param RealName A pointer to a UNICODE_STRING that receives the fully qualified real DLL name.
 * \param LocalName A pointer to a UNICODE_STRING that receives the local (privatized) DLL name.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlComputePrivatizedDllName_U(
    _In_ PUNICODE_STRING DllName,
    _Out_ PUNICODE_STRING RealName,
    _Out_ PUNICODE_STRING LocalName
);

// rev
/**
 * The RtlGetSearchPath routine retrieves the search path used to locate images and files for the current process.
 *
 * \param SearchPath A pointer to a variable that receives an allocated null-terminated search path string. The caller
 * frees the string with RtlReleasePath.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetSearchPath(
    _Out_ PWSTR* SearchPath
);

// rev
/**
 * The RtlSetSearchPathMode routine sets the search path mode used when locating images and files for the current
 * process.
 *
 * \param Flags Flags that specify the search path mode.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlSetSearchPathMode(
    _In_ ULONG Flags
);

// rev
/**
 * The RtlGetExePath routine retrieves the executable search path for the specified application.
 *
 * \param DosPathName A pointer to the DOS path name of the application.
 * \param SearchPath A pointer to a variable that receives an allocated null-terminated search path string. The caller
 * frees the string with RtlReleasePath.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlGetExePath(
    _In_ PCWSTR DosPathName,
    _Out_ PWSTR* SearchPath
);

// rev
/**
 * The RtlReleasePath routine frees a path buffer previously allocated by the RtlGetSearchPath or RtlGetExePath
 * routines.
 *
 * \param Path A pointer to the path buffer to free.
 */
NTSYSAPI
VOID
NTAPI
RtlReleasePath(
    _In_ PCWSTR Path
);

#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
/**
 * The RtlReplaceSystemDirectoryInPath routine replaces the system directory in a path with the directory appropriate
 * for the specified machine architecture.
 *
 * \param Destination A pointer to a UNICODE_STRING that contains the path on input and receives the modified path on
 * output.
 * \param Machine The source machine architecture (an IMAGE_FILE_MACHINE_* value).
 * \param TargetMachine The target machine architecture (an IMAGE_FILE_MACHINE_* value).
 * \param IncludePathSeperator A boolean that specifies whether a trailing path separator is included.
 * \return ULONG The length, in bytes, of the resulting path.
 */
NTSYSAPI
ULONG
NTAPI
RtlReplaceSystemDirectoryInPath(
    _Inout_ PUNICODE_STRING Destination,
    _In_ USHORT Machine, // IMAGE_FILE_MACHINE_I386
    _In_ USHORT TargetMachine, // IMAGE_FILE_MACHINE_TARGET_HOST
    _In_ BOOLEAN IncludePathSeperator
);
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
/**
 * The RtlGetNtSystemRoot routine returns the path of the Windows system root directory.
 *
 * \return PWSTR A pointer to a null-terminated string containing the system root path.
 */
NTSYSAPI
PWSTR
NTAPI
RtlGetNtSystemRoot(
    VOID
);
#endif

/**
 * The RtlAreLongPathsEnabled routine determines whether long path support is enabled for the current process.
 *
 * \return `TRUE` if long paths are enabled, otherwise `FALSE`.
 */
NTSYSAPI
BOOLEAN
NTAPI
RtlAreLongPathsEnabled(
    VOID
);


// RtlCanonicalizeDomainName
/**
 * The RtlCanonicalizeDomainName routine produces the canonical form of a domain name.
 *
 * \param DestinationName A pointer to a UNICODE_STRING that receives the canonicalized name.
 * \param SourceName A pointer to the Unicode string that specifies the domain name to canonicalize.
 * \param AllowInvalidLabels If `TRUE`, labels that are otherwise invalid are permitted.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCanonicalizeDomainName(
    _Out_ PUNICODE_STRING DestinationName,
    _In_ PCUNICODE_STRING SourceName,
    _In_ BOOLEAN AllowInvalidLabels
    );

// RtlConstructCrossVmEventPath
/**
 * The RtlConstructCrossVmEventPath routine constructs the object path for a cross-VM event identified by two GUIDs.
 *
 * \param ObjectPath A pointer to a UNICODE_STRING that receives the constructed event path.
 * \param Guid1 A pointer to the first GUID that identifies the cross-VM channel.
 * \param Guid2 A pointer to the second GUID that identifies the cross-VM channel.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlConstructCrossVmEventPath(
    _In_ PCUNICODE_STRING ObjectPath,
    _In_ const GUID *Guid1,
    _In_ const GUID *Guid2
    );

// RtlConstructCrossVmMutexPath
/**
 * The RtlConstructCrossVmMutexPath routine constructs the object path for a cross-VM mutex identified by two GUIDs.
 *
 * \param ObjectPath A pointer to a UNICODE_STRING that receives the constructed mutex path.
 * \param Guid1 A pointer to the first GUID that identifies the cross-VM channel.
 * \param Guid2 A pointer to the second GUID that identifies the cross-VM channel.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlConstructCrossVmMutexPath(
    _In_ PCUNICODE_STRING ObjectPath,
    _In_ const GUID *Guid1,
    _In_ const GUID *Guid2
    );

// RtlCreateSystemVolumeInformationFolder
/**
 * The RtlCreateSystemVolumeInformationFolder routine creates the System Volume Information folder on the volume at the
 * specified root path.
 *
 * \param RootPath A pointer to the Unicode string that specifies the volume root path.
 * \return NTSTATUS Successful or errant status.
 */
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSystemVolumeInformationFolder(
    _In_ PCUNICODE_STRING RootPath
    );

// RtlIsNameLegalDOS8Dot3
NTSYSAPI
BOOLEAN
NTAPI
RtlIsNameLegalDOS8Dot3(
    _In_ PCUNICODE_STRING Name,
    _Out_opt_ POEM_STRING OemName,
    _Out_opt_ PBOOLEAN NameContainsSpaces
    );
EXTERN_C_END
