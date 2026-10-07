#pragma once

#include "../NT/MinDef.h"

#include <WinBase.h>

EXTERN_C_START

#pragma region Appx/Msix Packages

/* phnt */

// private
/**
 * The PACKAGE_CONTEXT_REFERENCE structure represents an opaque reference to an application package context.
 */
typedef struct _PACKAGE_CONTEXT_REFERENCE
{
    PVOID reserved;
} *PACKAGE_CONTEXT_REFERENCE;

// private
/**
 * The PackageProperty enumeration identifies a property of an application package.
 */
typedef enum _PackageProperty
{
    PackageProperty_Name = 1,                  // q: WCHAR[]
    PackageProperty_Version = 2,               // q: WCHAR[]
    PackageProperty_Architecture = 3,          // q: ULONG (PROCESSOR_ARCHITECTURE_*)
    PackageProperty_ResourceId = 4,            // q: WCHAR[]
    PackageProperty_Publisher = 5,             // q: WCHAR[]
    PackageProperty_PublisherId = 6,           // q: WCHAR[]
    PackageProperty_FamilyName = 7,            // q: WCHAR[]
    PackageProperty_FullName = 8,              // q: WCHAR[]
    PackageProperty_Flags = 9,                 // q: ULONG
    PackageProperty_InstalledLocation = 10,    // q: WCHAR[]
    PackageProperty_DisplayName = 11,          // q: WCHAR[]
    PackageProperty_PublisherDisplayName = 12, // q: WCHAR[]
    PackageProperty_Description = 13,          // q: WCHAR[]
    PackageProperty_Logo = 14,                 // q: WCHAR[]
    PackageProperty_PackageOrigin = 15         // q: PackageOrigin
} PackageProperty;

// private
/**
 * The PACKAGE_APPLICATION_CONTEXT_REFERENCE structure represents an opaque reference to a package application context.
 */
typedef struct _PACKAGE_APPLICATION_CONTEXT_REFERENCE
{
    PVOID reserved;
} *PACKAGE_APPLICATION_CONTEXT_REFERENCE;

// private
/**
 * The PackageApplicationProperty enumeration identifies a property of an application within a package.
 */
typedef enum _PackageApplicationProperty
{
    PackageApplicationProperty_Aumid = 1,                        // q: WCHAR[]
    PackageApplicationProperty_Praid = 2,                        // q: WCHAR[]
    PackageApplicationProperty_DisplayName = 3,                  // q: WCHAR[]
    PackageApplicationProperty_Description = 4,                  // q: WCHAR[]
    PackageApplicationProperty_Logo = 5,                         // q: WCHAR[]
    PackageApplicationProperty_SmallLogo = 6,                    // q: WCHAR[]
    PackageApplicationProperty_ForegroundText = 7,               // q: ULONG
    PackageApplicationProperty_ForegroundTextString = 8,         // q: WCHAR[]
    PackageApplicationProperty_BackgroundColor = 9,              // q: ULONG
    PackageApplicationProperty_StartPage = 10,                   // q: WCHAR[]
    PackageApplicationProperty_ContentURIRulesCount = 11,        // q: ULONG
    PackageApplicationProperty_ContentURIRules = 12,             // q: WCHAR[] (multi-sz)
    PackageApplicationProperty_StaticContentURIRulesCount = 13,  // q: ULONG
    PackageApplicationProperty_StaticContentURIRules = 14,       // q: WCHAR[] (multi-sz)
    PackageApplicationProperty_DynamicContentURIRulesCount = 15, // q: ULONG
    PackageApplicationProperty_DynamicContentURIRules = 16       // q: WCHAR[] (multi-sz)
} PackageApplicationProperty;

// private
/**
 * The PACKAGE_RESOURCES_CONTEXT_REFERENCE structure represents an opaque reference to a package resources context.
 */
typedef struct _PACKAGE_RESOURCES_CONTEXT_REFERENCE
{
    PVOID reserved;
} *PACKAGE_RESOURCES_CONTEXT_REFERENCE;

// private
/**
 * The PackageResourcesProperty enumeration identifies a resources property of an application package.
 */
typedef enum _PackageResourcesProperty
{
    PackageResourcesProperty_DisplayName = 1,
    PackageResourcesProperty_PublisherDisplayName = 2,
    PackageResourcesProperty_Description = 3,
    PackageResourcesProperty_Logo = 4,
    PackageResourcesProperty_SmallLogo = 5,
    PackageResourcesProperty_StartPage = 6
} PackageResourcesProperty;

// private
/**
 * The PACKAGE_SECURITY_CONTEXT_REFERENCE structure represents an opaque reference to a package security context.
 */
typedef struct _PACKAGE_SECURITY_CONTEXT_REFERENCE
{
    PVOID reserved;
} *PACKAGE_SECURITY_CONTEXT_REFERENCE;

// private
/**
 * The PackageSecurityProperty enumeration identifies a security property of an application package.
 */
typedef enum _PackageSecurityProperty
{
    PackageSecurityProperty_SecurityFlags = 1,     // q: ULONG
    PackageSecurityProperty_AppContainerSID = 2,   // q: Sid
    PackageSecurityProperty_CapabilitiesCount = 3, // q: ULONG
    PackageSecurityProperty_Capabilities = 4       // q: Sid[]
} PackageSecurityProperty;

// private
/**
 * The TARGET_PLATFORM_CONTEXT_REFERENCE structure represents an opaque reference to a target platform context.
 */
typedef struct _TARGET_PLATFORM_CONTEXT_REFERENCE
{
    PVOID reserved;
} *TARGET_PLATFORM_CONTEXT_REFERENCE;

// private
/**
 * The TargetPlatformProperty enumeration identifies a target platform property of an application package.
 */
typedef enum _TargetPlatformProperty
{
    TargetPlatformProperty_Platform = 1,   // q: ULONG
    TargetPlatformProperty_MinVersion = 2, // q: PACKAGE_VERSION
    TargetPlatformProperty_MaxVersion = 3  // q: PACKAGE_VERSION
} TargetPlatformProperty;

// private
/**
 * The PACKAGE_GLOBALIZATION_CONTEXT_REFERENCE structure represents an opaque reference to a package globalization
 * context.
 */
typedef struct _PACKAGE_GLOBALIZATION_CONTEXT_REFERENCE
{
    PVOID reserved;
} *PACKAGE_GLOBALIZATION_CONTEXT_REFERENCE;

// private
/**
 * The PackageGlobalizationProperty enumeration identifies a globalization property of an application package.
 */
typedef enum _PackageGlobalizationProperty
{
    PackageGlobalizationProperty_ForceUtf8 = 1,                // q: ULONG
    PackageGlobalizationProperty_UseWindowsDisplayLanguage = 2 // q: ULONG
} PackageGlobalizationProperty;

#if (NTDDI_VERSION >= NTDDI_WINBLUE)

// rev
/**
 * The GetCurrentPackageContext routine retrieves a package context reference for the current package.
 *
 * \param Index The zero-based index of the package in the current package graph.
 * \param Unused Reserved; must be zero.
 * \param PackageContext Receives the package context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetCurrentPackageContext(
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_CONTEXT_REFERENCE *PackageContext
);

// rev
/**
 * The GetPackageContext routine retrieves a package context reference from a package information reference.
 *
 * \param PackageInfoReference A reference to the package information object.
 * \param Index The zero-based index of the package.
 * \param Unused Reserved; must be zero.
 * \param PackageContext Receives the package context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetPackageContext(
    _In_ PVOID PackageInfoReference, // PACKAGE_INFO_REFERENCE
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_CONTEXT_REFERENCE *PackageContext
);

// rev
/**
 * The GetPackageProperty routine retrieves a property value from a package context.
 *
 * \param PackageContext The package context reference.
 * \param PropertyId The package property identifier to query.
 * \param BufferSize A pointer to a variable that specifies the buffer size and receives the required or returned size
 * in bytes.
 * \param Buffer A pointer to the buffer receiving the property value.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetPackageProperty(
    _In_ PACKAGE_CONTEXT_REFERENCE PackageContext,
    _In_ PackageProperty PropertyId,
    _Inout_ PULONG BufferSize,
    _Out_writes_bytes_(BufferSize) PVOID Buffer
);

// rev
/**
 * The GetPackagePropertyString routine retrieves a string property value from a package context.
 *
 * \param PackageContext The package context reference.
 * \param PropertyId The package property identifier to query.
 * \param BufferLength A pointer to a variable that specifies the buffer length and receives the required or returned
 * length in characters.
 * \param Buffer A pointer to the buffer receiving the string property.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetPackagePropertyString(
    _In_ PACKAGE_CONTEXT_REFERENCE PackageContext,
    _In_ PackageProperty PropertyId,
    _Inout_ PULONG BufferLength,
    _Out_writes_(BufferLength) PWSTR Buffer
);

// rev
/**
 * The GetPackageOSMaxVersionTested routine retrieves the maximum operating system version against which the package was
 * tested.
 *
 * \param PackageContext The package context reference.
 * \param OSMaxVersionTested Receives the tested maximum OS version encoded as an integer.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetPackageOSMaxVersionTested(
    _In_ PACKAGE_CONTEXT_REFERENCE PackageContext,
    _Out_ ULONGLONG *OSMaxVersionTested // PACKAGE_VERSION
);

//
// Package Application Properties
//

// rev
/**
 * The GetCurrentPackageApplicationContext routine retrieves an application context reference for the current package.
 *
 * \param Index The zero-based index of the application in the package.
 * \param Unused Reserved; must be zero.
 * \param PackageApplicationContext Receives the package application context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetCurrentPackageApplicationContext(
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_APPLICATION_CONTEXT_REFERENCE *PackageApplicationContext
);

// rev
/**
 * The GetPackageApplicationContext routine retrieves an application context reference from a package information
 * reference.
 *
 * \param PackageInfoReference A reference to the package information object.
 * \param Index The zero-based index of the application.
 * \param Unused Reserved; must be zero.
 * \param PackageApplicationContext Receives the package application context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetPackageApplicationContext(
    _In_ PVOID PackageInfoReference, // PACKAGE_INFO_REFERENCE
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_APPLICATION_CONTEXT_REFERENCE *PackageApplicationContext
);

// rev
/**
 * The GetPackageApplicationProperty routine retrieves a property value from a package application context.
 *
 * \param PackageApplicationContext The package application context reference.
 * \param PropertyId The package application property identifier to query.
 * \param BufferSize A pointer to a variable that specifies the buffer size and receives the required or returned size
 * in bytes.
 * \param Buffer A pointer to the buffer receiving the property value.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetPackageApplicationProperty(
    _In_ PACKAGE_APPLICATION_CONTEXT_REFERENCE PackageApplicationContext,
    _In_ PackageApplicationProperty PropertyId,
    _Inout_ PULONG BufferSize,
    _Out_writes_bytes_(BufferSize) PVOID Buffer
);

// rev
/**
 * The GetPackageApplicationPropertyString routine retrieves a string property value from a package application context.
 *
 * \param PackageApplicationContext The package application context reference.
 * \param PropertyId The package application property identifier to query.
 * \param BufferLength A pointer to a variable that specifies the buffer length and receives the required or returned
 * length in characters.
 * \param Buffer A pointer to the buffer receiving the string property.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetPackageApplicationPropertyString(
    _In_ PACKAGE_APPLICATION_CONTEXT_REFERENCE PackageApplicationContext,
    _In_ PackageApplicationProperty PropertyId,
    _Inout_ PULONG BufferLength,
    _Out_writes_(BufferLength) PWSTR Buffer
);

//
// Package Resource Properties
//

// rev
/**
 * The GetCurrentPackageResourcesContext routine retrieves a resources context reference for the current package.
 *
 * \param Index The zero-based index of the resource context.
 * \param Unused Reserved; must be zero.
 * \param PackageResourcesContext Receives the package resources context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetCurrentPackageResourcesContext(
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_RESOURCES_CONTEXT_REFERENCE *PackageResourcesContext
);

// rev
/**
 * The GetPackageResourcesContext routine retrieves a resources context reference from a package information reference.
 *
 * \param PackageInfoReference A reference to the package information object.
 * \param Index The zero-based index of the resource context.
 * \param Unused Reserved; must be zero.
 * \param PackageResourcesContext Receives the package resources context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetPackageResourcesContext(
    _In_ PVOID PackageInfoReference, // PACKAGE_INFO_REFERENCE
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_RESOURCES_CONTEXT_REFERENCE *PackageResourcesContext
);

// rev
/**
 * The GetCurrentPackageApplicationResourcesContext routine retrieves an application resources context reference for the
 * current package.
 *
 * \param Index The zero-based index of the application resource context.
 * \param Unused Reserved; must be zero.
 * \param PackageResourcesContext Receives the package resources context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
ULONG
WINAPI
GetCurrentPackageApplicationResourcesContext(
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_RESOURCES_CONTEXT_REFERENCE *PackageResourcesContext
);

// rev
/**
 * The GetPackageApplicationResourcesContext routine retrieves an application resources context reference from a package
 * information reference.
 *
 * \param PackageInfoReference A reference to the package information object.
 * \param Index The zero-based index of the application resource context.
 * \param Unused Reserved; must be zero.
 * \param PackageResourcesContext Receives the package resources context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetPackageApplicationResourcesContext(
    _In_ PVOID PackageInfoReference, // PACKAGE_INFO_REFERENCE
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_RESOURCES_CONTEXT_REFERENCE *PackageResourcesContext
);

// rev
/**
 * The GetPackageResourcesProperty routine retrieves a property value from a package resources context.
 *
 * \param PackageResourcesContext The package resources context reference.
 * \param PropertyId The package resources property identifier to query.
 * \param BufferSize A pointer to a variable specifying the buffer size and receiving the required or returned size in
 * bytes.
 * \param Buffer A pointer to the buffer receiving the resources property value.
 * \param Flags An optional pointer receiving property flags.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetPackageResourcesProperty(
    _In_ PACKAGE_RESOURCES_CONTEXT_REFERENCE PackageResourcesContext,
    _In_ PackageResourcesProperty PropertyId,
    _Inout_ PULONG BufferSize,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _Out_opt_ PULONG Flags
);

//
// Package Security Properties
//

// rev
/**
 * The GetCurrentPackageSecurityContext routine retrieves a security context reference for the current package.
 *
 * \param Unused Reserved; must be zero.
 * \param PackageSecurityContext Receives the package security context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetCurrentPackageSecurityContext(
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_SECURITY_CONTEXT_REFERENCE *PackageSecurityContext
);

// rev
/**
 * The GetPackageSecurityContext routine retrieves a security context reference from a package information reference.
 *
 * \param PackageInfoReference A reference to the package information object.
 * \param Unused Reserved; must be zero.
 * \param PackageSecurityContext Receives the package security context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetPackageSecurityContext(
    _In_ PVOID PackageInfoReference, // PACKAGE_INFO_REFERENCE
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_SECURITY_CONTEXT_REFERENCE *PackageSecurityContext
);

// rev
/**
 * The GetPackageSecurityProperty routine retrieves a property value from a package security context.
 *
 * \param PackageSecurityContext The package security context reference.
 * \param PropertyId The package security property identifier to query.
 * \param BufferSize A pointer to a variable specifying the buffer size and receiving the required or returned size in
 * bytes.
 * \param Buffer A pointer to the buffer receiving the security property value.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetPackageSecurityProperty(
    _In_ PACKAGE_SECURITY_CONTEXT_REFERENCE PackageSecurityContext,
    _In_ PackageSecurityProperty PropertyId,
    _Inout_ PULONG BufferSize,
    _Out_writes_bytes_(BufferSize) PVOID Buffer
);

#endif // NTDDI_VERSION >= NTDDI_WINBLUE

#if (NTDDI_VERSION >= NTDDI_WIN10)

//
// Target Platform Properties
//

// rev
/**
 * The GetCurrentTargetPlatformContext routine retrieves a target platform context reference for the current package.
 *
 * \param Unused Reserved; must be zero.
 * \param TargetPlatformContext Receives the target platform context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetCurrentTargetPlatformContext(
    _Reserved_ ULONG_PTR Unused,
    _Out_ TARGET_PLATFORM_CONTEXT_REFERENCE *TargetPlatformContext
);

/**
 * The GetTargetPlatformContext routine retrieves a target platform context reference from a package information
 * reference.
 *
 * \param PackageInfoReference A reference to the package information object.
 * \param Unused Reserved; must be zero.
 * \param TargetPlatformContext Receives the target platform context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetTargetPlatformContext(
    _In_ PVOID PackageInfoReference, // PACKAGE_INFO_REFERENCE
    _Reserved_ ULONG_PTR Unused,
    _Out_ TARGET_PLATFORM_CONTEXT_REFERENCE *TargetPlatformContext
);

// rev
/**
 * The GetPackageTargetPlatformProperty routine retrieves a property value from a target platform context.
 *
 * \param TargetPlatformContext The target platform context reference.
 * \param PropertyId The target platform property identifier to query.
 * \param BufferSize A pointer to a variable specifying the buffer size and receiving the required or returned size in
 * bytes.
 * \param Buffer A pointer to the buffer receiving the property value.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetPackageTargetPlatformProperty(
    _In_ TARGET_PLATFORM_CONTEXT_REFERENCE TargetPlatformContext,
    _In_ TargetPlatformProperty PropertyId,
    _Inout_ PULONG BufferSize,
    _Out_writes_bytes_(BufferSize) PVOID Buffer
);

#endif // NTDDI_VERSION >= NTDDI_WIN10

#if (NTDDI_VERSION >= NTDDI_WIN10_MN)

// rev
/**
 * The GetCurrentPackageInfo3 routine retrieves package information for the current process, specifying the package path
 * type.
 *
 * \param Flags Package information flags specifying what information to retrieve.
 * \param PackagePathType The type of folder path to retrieve for the package.
 * \param BufferLength A pointer to a variable specifying the buffer size and receiving the required or returned size in
 * bytes.
 * \param Buffer A pointer to the buffer receiving the package information.
 * \param ReturnLength Optional pointer receiving the number of elements written to the buffer.
 * \return HRESULT Successful or error status.
 */
WINBASEAPI
HRESULT
WINAPI
GetCurrentPackageInfo3(
    _In_ ULONG Flags,
    _In_ ULONG PackagePathType, // PackagePathType
    _Inout_ PULONG BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) PVOID Buffer,
    _Out_opt_ PULONG ReturnLength
);

//
// Package Globalization Properties
//

// rev
/**
 * The GetCurrentPackageGlobalizationContext routine retrieves a globalization context reference for the current
 * package.
 *
 * \param Index An index specifying which globalization context to retrieve.
 * \param Unused Reserved; must be zero.
 * \param PackageGlobalizationContext Receives the package globalization context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetCurrentPackageGlobalizationContext(
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_GLOBALIZATION_CONTEXT_REFERENCE *PackageGlobalizationContext
);

// rev
/**
 * The GetPackageGlobalizationContext routine retrieves a globalization context reference from a package information
 * reference.
 *
 * \param PackageInfoReference A reference to the package information object.
 * \param Index An index specifying which globalization context to retrieve.
 * \param Unused Reserved; must be zero.
 * \param PackageGlobalizationContext Receives the package globalization context reference.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetPackageGlobalizationContext(
    _In_ PVOID PackageInfoReference, // PACKAGE_INFO_REFERENCE
    _In_ ULONG Index,
    _Reserved_ ULONG_PTR Unused,
    _Out_ PACKAGE_GLOBALIZATION_CONTEXT_REFERENCE *PackageGlobalizationContext
);

// rev
/**
 * The GetPackageGlobalizationProperty routine retrieves a property value from a package globalization context.
 *
 * \param PackageGlobalizationContext The package globalization context reference.
 * \param PropertyId The package globalization property identifier to query.
 * \param BufferSize A pointer to a variable specifying the buffer size and receiving the required or returned size in
 * bytes.
 * \param Buffer A pointer to the buffer receiving the property value.
 * \return A Win32 error code. ERROR_SUCCESS on success.
 */
WINBASEAPI
LONG
WINAPI
GetPackageGlobalizationProperty(
    _In_ PACKAGE_GLOBALIZATION_CONTEXT_REFERENCE PackageGlobalizationContext,
    _In_ PackageGlobalizationProperty PropertyId,
    _Inout_ PULONG BufferSize,
    _Out_writes_bytes_(BufferSize) PVOID Buffer
);

#endif // NTDDI_VERSION >= NTDDI_WIN10_MN

#pragma endregion

EXTERN_C_END
