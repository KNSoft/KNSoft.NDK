/*
 * Component-Based Servicing private COM definitions.
 */

#pragma once

#include "../../NT/MinDef.h"

#include <objbase.h>

EXTERN_C_START

typedef enum _CBS_INSTALL_STATE
{
    CbsInstallStatePartiallyInstalled = -19,
    CbsInstallStateCancel = -18,
    CbsInstallStateSuperseded = -17,
    CbsInstallStateDefault = -16,
    CbsInstallStateUnknown = -1,
    CbsInstallStateAbsent = 0,
    CbsInstallStateResolving = 1,
    CbsInstallStateResolved = 2,
    CbsInstallStateStaging = 3,
    CbsInstallStateStaged = 4,
    CbsInstallStateUninstallRequested = 5,
    CbsInstallStateInstallRequested = 6,
    CbsInstallStateInstalled = 7,
    CbsInstallStatePermanent = 8
} CBS_INSTALL_STATE, *PCBS_INSTALL_STATE;

typedef enum _CBS_REQUIRED_ACTION
{
    CbsRequiredActionNone = 0,
    CbsRequiredActionReboot = 1
} CBS_REQUIRED_ACTION, *PCBS_REQUIRED_ACTION;

typedef struct ICbsIdentity ICbsIdentity;
typedef struct ICbsPackage ICbsPackage;
typedef struct ICbsUpdate ICbsUpdate;
typedef struct ICbsSession ICbsSession;
typedef struct IEnumCbsUpdate IEnumCbsUpdate;

typedef struct ICbsIdentityVtbl
{
    BEGIN_INTERFACE
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(
        _In_ ICbsIdentity* This,
        _In_ REFIID InterfaceId,
        _COM_Outptr_ PVOID* Object);
    ULONG (STDMETHODCALLTYPE* AddRef)(
        _In_ ICbsIdentity* This);
    ULONG (STDMETHODCALLTYPE* Release)(
        _In_ ICbsIdentity* This);
    PVOID Reserved[4];
    HRESULT (STDMETHODCALLTYPE* LoadFromStringId)(
        _In_ ICbsIdentity* This,
        _In_ PCWSTR StringId);
    END_INTERFACE
} ICbsIdentityVtbl;

struct ICbsIdentity
{
    const ICbsIdentityVtbl* lpVtbl;
};

typedef struct ICbsPackageVtbl
{
    BEGIN_INTERFACE
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(
        _In_ ICbsPackage* This,
        _In_ REFIID InterfaceId,
        _COM_Outptr_ PVOID* Object);
    ULONG (STDMETHODCALLTYPE* AddRef)(
        _In_ ICbsPackage* This);
    ULONG (STDMETHODCALLTYPE* Release)(
        _In_ ICbsPackage* This);
    PVOID Reserved1[2];
    HRESULT (STDMETHODCALLTYPE* EnumerateUpdates)(
        _In_ ICbsPackage* This,
        _In_ INT Applicability,
        _In_ INT Selectability,
        _Outptr_ IEnumCbsUpdate** Enumerator);
    HRESULT (STDMETHODCALLTYPE* GetUpdate)(
        _In_ ICbsPackage* This,
        _In_ PCWSTR Name,
        _Outptr_ ICbsUpdate** Update);
    PVOID Reserved2[4];
    HRESULT (STDMETHODCALLTYPE* InitiateChanges)(
        _In_ ICbsPackage* This,
        _In_ UINT Options,
        _In_ CBS_INSTALL_STATE State,
        _In_opt_ IUnknown* Progress);
    END_INTERFACE
} ICbsPackageVtbl;

struct ICbsPackage
{
    const ICbsPackageVtbl* lpVtbl;
};

typedef struct ICbsUpdateVtbl
{
    BEGIN_INTERFACE
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(
        _In_ ICbsUpdate* This,
        _In_ REFIID InterfaceId,
        _COM_Outptr_ PVOID* Object);
    ULONG (STDMETHODCALLTYPE* AddRef)(
        _In_ ICbsUpdate* This);
    ULONG (STDMETHODCALLTYPE* Release)(
        _In_ ICbsUpdate* This);
    HRESULT (STDMETHODCALLTYPE* GetProperty)(
        _In_ ICbsUpdate* This,
        _In_ INT Property,
        _Outptr_ PWSTR* Value);
    PVOID Reserved1;
    HRESULT (STDMETHODCALLTYPE* GetParentUpdate)(
        _In_ ICbsUpdate* This,
        _In_ UINT Index,
        _Outptr_ PWSTR* ParentName,
        _Outptr_ PWSTR* ParentSet);
    PVOID Reserved2[2];
    HRESULT (STDMETHODCALLTYPE* GetInstallState)(
        _In_ ICbsUpdate* This,
        _Out_ CBS_INSTALL_STATE* CurrentState,
        _Out_ CBS_INSTALL_STATE* IntendedState,
        _Out_ CBS_INSTALL_STATE* RequestedState);
    HRESULT (STDMETHODCALLTYPE* SetInstallState)(
        _In_ ICbsUpdate* This,
        _In_ UINT Options,
        _In_ CBS_INSTALL_STATE State);
    END_INTERFACE
} ICbsUpdateVtbl;

struct ICbsUpdate
{
    const ICbsUpdateVtbl* lpVtbl;
};

typedef struct IEnumCbsUpdateVtbl
{
    BEGIN_INTERFACE
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(
        _In_ IEnumCbsUpdate* This,
        _In_ REFIID InterfaceId,
        _COM_Outptr_ PVOID* Object);
    ULONG (STDMETHODCALLTYPE* AddRef)(
        _In_ IEnumCbsUpdate* This);
    ULONG (STDMETHODCALLTYPE* Release)(
        _In_ IEnumCbsUpdate* This);
    HRESULT (STDMETHODCALLTYPE* Next)(
        _In_ IEnumCbsUpdate* This,
        _In_ ULONG Count,
        _Out_writes_to_(Count, *Fetched) ICbsUpdate** Updates,
        _Out_ PULONG Fetched);
    END_INTERFACE
} IEnumCbsUpdateVtbl;

struct IEnumCbsUpdate
{
    const IEnumCbsUpdateVtbl* lpVtbl;
};

typedef struct ICbsSessionVtbl
{
    BEGIN_INTERFACE
    HRESULT (STDMETHODCALLTYPE* QueryInterface)(
        _In_ ICbsSession* This,
        _In_ REFIID InterfaceId,
        _COM_Outptr_ PVOID* Object);
    ULONG (STDMETHODCALLTYPE* AddRef)(
        _In_ ICbsSession* This);
    ULONG (STDMETHODCALLTYPE* Release)(
        _In_ ICbsSession* This);
    HRESULT (STDMETHODCALLTYPE* Initialize)(
        _In_ ICbsSession* This,
        _In_ UINT Options,
        _In_ PCWSTR ClientId,
        _In_opt_ PCWSTR BootDrive,
        _In_opt_ PCWSTR WindowsDirectory);
    HRESULT (STDMETHODCALLTYPE* Finalize)(
        _In_ ICbsSession* This,
        _Out_ CBS_REQUIRED_ACTION* RequiredAction);
    PVOID Reserved1;
    HRESULT (STDMETHODCALLTYPE* OpenPackage)(
        _In_ ICbsSession* This,
        _In_ UINT Options,
        _In_ ICbsIdentity* Identity,
        _In_opt_ PCWSTR PackagePath,
        _COM_Outptr_ IUnknown** Package);
    PVOID Reserved2;
    HRESULT (STDMETHODCALLTYPE* CreateCbsIdentity)(
        _In_ ICbsSession* This,
        _Outptr_ ICbsIdentity** Identity);
    END_INTERFACE
} ICbsSessionVtbl;

struct ICbsSession
{
    const ICbsSessionVtbl* lpVtbl;
};

EXTERN_C DECLSPEC_SELECTANY CONST GUID CLSID_CbsSession =
    { 0x752073A1, 0x23F2, 0x4396, { 0x85, 0xF0, 0x8F, 0xDB, 0x87, 0x9E, 0xD0, 0xED } };
EXTERN_C DECLSPEC_SELECTANY CONST GUID IID_ICbsSession =
    { 0x75207391, 0x23F2, 0x4396, { 0x85, 0xF0, 0x8F, 0xDB, 0x87, 0x9E, 0xD0, 0xED } };
EXTERN_C DECLSPEC_SELECTANY CONST GUID IID_ICbsPackage =
    { 0x75207393, 0x23F2, 0x4396, { 0x85, 0xF0, 0x8F, 0xDB, 0x87, 0x9E, 0xD0, 0xED } };

EXTERN_C_END
