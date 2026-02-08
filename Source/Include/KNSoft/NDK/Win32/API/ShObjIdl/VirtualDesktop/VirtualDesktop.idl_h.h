

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 11:14:07 2038
 */
/* Compiler settings for ..\Include\KNSoft\NDK\Win32\API\ShObjIdl\VirtualDesktop\VirtualDesktop.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __VirtualDesktop2Eidl_h_h__
#define __VirtualDesktop2Eidl_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

#ifndef __IApplicationView_FWD_DEFINED__
#define __IApplicationView_FWD_DEFINED__
typedef interface IApplicationView IApplicationView;

#endif 	/* __IApplicationView_FWD_DEFINED__ */


#ifndef __IApplicationView_17134_FWD_DEFINED__
#define __IApplicationView_17134_FWD_DEFINED__
typedef interface IApplicationView_17134 IApplicationView_17134;

#endif 	/* __IApplicationView_17134_FWD_DEFINED__ */


#ifndef __IApplicationView_0_FWD_DEFINED__
#define __IApplicationView_0_FWD_DEFINED__
typedef interface IApplicationView_0 IApplicationView_0;

#endif 	/* __IApplicationView_0_FWD_DEFINED__ */


#ifndef __IApplicationViewCollection_FWD_DEFINED__
#define __IApplicationViewCollection_FWD_DEFINED__
typedef interface IApplicationViewCollection IApplicationViewCollection;

#endif 	/* __IApplicationViewCollection_FWD_DEFINED__ */


#ifndef __IApplicationViewCollection_0_FWD_DEFINED__
#define __IApplicationViewCollection_0_FWD_DEFINED__
typedef interface IApplicationViewCollection_0 IApplicationViewCollection_0;

#endif 	/* __IApplicationViewCollection_0_FWD_DEFINED__ */


#ifndef __IVirtualDesktop_FWD_DEFINED__
#define __IVirtualDesktop_FWD_DEFINED__
typedef interface IVirtualDesktop IVirtualDesktop;

#endif 	/* __IVirtualDesktop_FWD_DEFINED__ */


#ifndef __IVirtualDesktop_22000_FWD_DEFINED__
#define __IVirtualDesktop_22000_FWD_DEFINED__
typedef interface IVirtualDesktop_22000 IVirtualDesktop_22000;

#endif 	/* __IVirtualDesktop_22000_FWD_DEFINED__ */


#ifndef __IVirtualDesktop_20348_FWD_DEFINED__
#define __IVirtualDesktop_20348_FWD_DEFINED__
typedef interface IVirtualDesktop_20348 IVirtualDesktop_20348;

#endif 	/* __IVirtualDesktop_20348_FWD_DEFINED__ */


#ifndef __IVirtualDesktop_0_FWD_DEFINED__
#define __IVirtualDesktop_0_FWD_DEFINED__
typedef interface IVirtualDesktop_0 IVirtualDesktop_0;

#endif 	/* __IVirtualDesktop_0_FWD_DEFINED__ */


#ifndef __IVirtualDesktopPinnedApps_FWD_DEFINED__
#define __IVirtualDesktopPinnedApps_FWD_DEFINED__
typedef interface IVirtualDesktopPinnedApps IVirtualDesktopPinnedApps;

#endif 	/* __IVirtualDesktopPinnedApps_FWD_DEFINED__ */


#ifndef __IVirtualDesktopManagerInternal_FWD_DEFINED__
#define __IVirtualDesktopManagerInternal_FWD_DEFINED__
typedef interface IVirtualDesktopManagerInternal IVirtualDesktopManagerInternal;

#endif 	/* __IVirtualDesktopManagerInternal_FWD_DEFINED__ */


/* header files for imported files */
#include "WTypes.h"
#include "hstring.h"
#include "Unknwn.h"
#include "ObjectArray.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_VirtualDesktop_0000_0000 */
/* [local] */ 

#pragma region IApplicationView
typedef /* [public][public][public][public] */ 
enum __MIDL___MIDL_itf_VirtualDesktop_0000_0000_0001
    {
        AVCT_NONE	= 0,
        AVCT_DEFAULT	= 1,
        AVCT_VIRTUAL_DESKTOP	= 2
    } 	APPLICATION_VIEW_CLOAK_TYPE;

typedef /* [public][public][public][public][public][public][public] */ 
enum __MIDL___MIDL_itf_VirtualDesktop_0000_0000_0002
    {
        AVCP_NONE	= 0,
        AVCP_SMALL_SCREEN	= 1,
        AVCP_TABLET_SMALL_SCREEN	= 2,
        AVCP_VERY_SMALL_SCREEN	= 3,
        AVCP_HIGH_SCALE_FACTOR	= 4
    } 	APPLICATION_VIEW_COMPATIBILITY_POLICY;



extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0000_v0_0_s_ifspec;

#ifndef __IApplicationView_INTERFACE_DEFINED__
#define __IApplicationView_INTERFACE_DEFINED__

/* interface IApplicationView */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IApplicationView;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("372E1D3B-38D3-42E4-A15B-8AB2B178F513")
    IApplicationView : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE SetFocus( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SwitchTo( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE TryInvokeBack( 
            /* [in] */ IUnknown *Callback) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetThumbnailWindow( 
            /* [out] */ HWND *hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetMonitor( 
            /* [out] */ IUnknown **immersiveMonitor) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetVisibility( 
            /* [out] */ int *visibility) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetCloak( 
            /* [v1_enum][in] */ APPLICATION_VIEW_CLOAK_TYPE cloakType,
            int unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetPosition( 
            /* [full][in] */ GUID *guid,
            /* [out] */ IUnknown **position) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetPosition( 
            /* [in] */ IUnknown *position) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE InsertAfterWindow( 
            /* [in] */ HWND hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetExtendedFramePosition( 
            /* [out] */ RECT *rect) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetAppUserModelId( 
            /* [string][out] */ wchar_t **Id) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetAppUserModelId( 
            /* [string][in] */ wchar_t *Id) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsEqualByAppUserModelId( 
            /* [string][in] */ wchar_t *Id,
            /* [out] */ int *result) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewState( 
            /* [out] */ unsigned int *state) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetViewState( 
            /* [in] */ unsigned int state) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetNeediness( 
            /* [out] */ int *neediness) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetLastActivationTimestamp( 
            /* [out] */ unsigned long *timestamp) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetLastActivationTimestamp( 
            /* [in] */ unsigned long timestamp) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetVirtualDesktopId( 
            /* [out] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetVirtualDesktopId( 
            /* [full][in] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetShowInSwitchers( 
            /* [out] */ int *flag) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetShowInSwitchers( 
            /* [in] */ int flag) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetScaleFactor( 
            /* [out] */ int *factor) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CanReceiveInput( 
            /* [out] */ boolean *canReceiveInput) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetCompatibilityPolicyType( 
            /* [v1_enum][out] */ APPLICATION_VIEW_COMPATIBILITY_POLICY *flags) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetCompatibilityPolicyType( 
            /* [v1_enum][in] */ APPLICATION_VIEW_COMPATIBILITY_POLICY flags) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetSizeConstraints( 
            /* [in] */ IUnknown *monitor,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetSizeConstraintsForDpi( 
            /* [in] */ unsigned int uint1,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetSizeConstraintsForDpi( 
            /* [in] */ unsigned int uint1,
            /* [full][in] */ SIZE *size1,
            /* [full][in] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnMinSizePreferencesUpdated( 
            /* [in] */ HWND hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE ApplyOperation( 
            /* [in] */ IUnknown *operation) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsTray( 
            /* [out] */ boolean *isTray) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsInHighZOrderBand( 
            /* [out] */ boolean *isInHighZOrderBand) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsSplashScreenPresented( 
            /* [out] */ boolean *isSplashScreenPresented) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Flash( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetRootSwitchableOwner( 
            /* [out] */ IApplicationView **rootSwitchableOwner) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE EnumerateOwnershipTree( 
            /* [out] */ IObjectArray **ownershipTree) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetEnterpriseId( 
            /* [string][out] */ wchar_t **enterpriseId) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsMirrored( 
            /* [out] */ boolean *isMirrored) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown1( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown2( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown3( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown4( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown5( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown6( 
            int unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown7( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown8( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown9( 
            int unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown10( 
            int unknownX,
            int unknownY) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown11( 
            int unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown12( 
            /* [out] */ SIZE *size1) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IApplicationViewVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IApplicationView * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IApplicationView * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IApplicationView * This);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetFocus)
        HRESULT ( STDMETHODCALLTYPE *SetFocus )( 
            IApplicationView * This);
        
        DECLSPEC_XFGVIRT(IApplicationView, SwitchTo)
        HRESULT ( STDMETHODCALLTYPE *SwitchTo )( 
            IApplicationView * This);
        
        DECLSPEC_XFGVIRT(IApplicationView, TryInvokeBack)
        HRESULT ( STDMETHODCALLTYPE *TryInvokeBack )( 
            IApplicationView * This,
            /* [in] */ IUnknown *Callback);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetThumbnailWindow)
        HRESULT ( STDMETHODCALLTYPE *GetThumbnailWindow )( 
            IApplicationView * This,
            /* [out] */ HWND *hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetMonitor)
        HRESULT ( STDMETHODCALLTYPE *GetMonitor )( 
            IApplicationView * This,
            /* [out] */ IUnknown **immersiveMonitor);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetVisibility)
        HRESULT ( STDMETHODCALLTYPE *GetVisibility )( 
            IApplicationView * This,
            /* [out] */ int *visibility);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetCloak)
        HRESULT ( STDMETHODCALLTYPE *SetCloak )( 
            IApplicationView * This,
            /* [v1_enum][in] */ APPLICATION_VIEW_CLOAK_TYPE cloakType,
            int unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetPosition)
        HRESULT ( STDMETHODCALLTYPE *GetPosition )( 
            IApplicationView * This,
            /* [full][in] */ GUID *guid,
            /* [out] */ IUnknown **position);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetPosition)
        HRESULT ( STDMETHODCALLTYPE *SetPosition )( 
            IApplicationView * This,
            /* [in] */ IUnknown *position);
        
        DECLSPEC_XFGVIRT(IApplicationView, InsertAfterWindow)
        HRESULT ( STDMETHODCALLTYPE *InsertAfterWindow )( 
            IApplicationView * This,
            /* [in] */ HWND hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetExtendedFramePosition)
        HRESULT ( STDMETHODCALLTYPE *GetExtendedFramePosition )( 
            IApplicationView * This,
            /* [out] */ RECT *rect);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *GetAppUserModelId )( 
            IApplicationView * This,
            /* [string][out] */ wchar_t **Id);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *SetAppUserModelId )( 
            IApplicationView * This,
            /* [string][in] */ wchar_t *Id);
        
        DECLSPEC_XFGVIRT(IApplicationView, IsEqualByAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *IsEqualByAppUserModelId )( 
            IApplicationView * This,
            /* [string][in] */ wchar_t *Id,
            /* [out] */ int *result);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetViewState)
        HRESULT ( STDMETHODCALLTYPE *GetViewState )( 
            IApplicationView * This,
            /* [out] */ unsigned int *state);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetViewState)
        HRESULT ( STDMETHODCALLTYPE *SetViewState )( 
            IApplicationView * This,
            /* [in] */ unsigned int state);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetNeediness)
        HRESULT ( STDMETHODCALLTYPE *GetNeediness )( 
            IApplicationView * This,
            /* [out] */ int *neediness);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetLastActivationTimestamp)
        HRESULT ( STDMETHODCALLTYPE *GetLastActivationTimestamp )( 
            IApplicationView * This,
            /* [out] */ unsigned long *timestamp);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetLastActivationTimestamp)
        HRESULT ( STDMETHODCALLTYPE *SetLastActivationTimestamp )( 
            IApplicationView * This,
            /* [in] */ unsigned long timestamp);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetVirtualDesktopId)
        HRESULT ( STDMETHODCALLTYPE *GetVirtualDesktopId )( 
            IApplicationView * This,
            /* [out] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetVirtualDesktopId)
        HRESULT ( STDMETHODCALLTYPE *SetVirtualDesktopId )( 
            IApplicationView * This,
            /* [full][in] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetShowInSwitchers)
        HRESULT ( STDMETHODCALLTYPE *GetShowInSwitchers )( 
            IApplicationView * This,
            /* [out] */ int *flag);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetShowInSwitchers)
        HRESULT ( STDMETHODCALLTYPE *SetShowInSwitchers )( 
            IApplicationView * This,
            /* [in] */ int flag);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetScaleFactor)
        HRESULT ( STDMETHODCALLTYPE *GetScaleFactor )( 
            IApplicationView * This,
            /* [out] */ int *factor);
        
        DECLSPEC_XFGVIRT(IApplicationView, CanReceiveInput)
        HRESULT ( STDMETHODCALLTYPE *CanReceiveInput )( 
            IApplicationView * This,
            /* [out] */ boolean *canReceiveInput);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetCompatibilityPolicyType)
        HRESULT ( STDMETHODCALLTYPE *GetCompatibilityPolicyType )( 
            IApplicationView * This,
            /* [v1_enum][out] */ APPLICATION_VIEW_COMPATIBILITY_POLICY *flags);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetCompatibilityPolicyType)
        HRESULT ( STDMETHODCALLTYPE *SetCompatibilityPolicyType )( 
            IApplicationView * This,
            /* [v1_enum][in] */ APPLICATION_VIEW_COMPATIBILITY_POLICY flags);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetSizeConstraints)
        HRESULT ( STDMETHODCALLTYPE *GetSizeConstraints )( 
            IApplicationView * This,
            /* [in] */ IUnknown *monitor,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetSizeConstraintsForDpi)
        HRESULT ( STDMETHODCALLTYPE *GetSizeConstraintsForDpi )( 
            IApplicationView * This,
            /* [in] */ unsigned int uint1,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView, SetSizeConstraintsForDpi)
        HRESULT ( STDMETHODCALLTYPE *SetSizeConstraintsForDpi )( 
            IApplicationView * This,
            /* [in] */ unsigned int uint1,
            /* [full][in] */ SIZE *size1,
            /* [full][in] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView, OnMinSizePreferencesUpdated)
        HRESULT ( STDMETHODCALLTYPE *OnMinSizePreferencesUpdated )( 
            IApplicationView * This,
            /* [in] */ HWND hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView, ApplyOperation)
        HRESULT ( STDMETHODCALLTYPE *ApplyOperation )( 
            IApplicationView * This,
            /* [in] */ IUnknown *operation);
        
        DECLSPEC_XFGVIRT(IApplicationView, IsTray)
        HRESULT ( STDMETHODCALLTYPE *IsTray )( 
            IApplicationView * This,
            /* [out] */ boolean *isTray);
        
        DECLSPEC_XFGVIRT(IApplicationView, IsInHighZOrderBand)
        HRESULT ( STDMETHODCALLTYPE *IsInHighZOrderBand )( 
            IApplicationView * This,
            /* [out] */ boolean *isInHighZOrderBand);
        
        DECLSPEC_XFGVIRT(IApplicationView, IsSplashScreenPresented)
        HRESULT ( STDMETHODCALLTYPE *IsSplashScreenPresented )( 
            IApplicationView * This,
            /* [out] */ boolean *isSplashScreenPresented);
        
        DECLSPEC_XFGVIRT(IApplicationView, Flash)
        HRESULT ( STDMETHODCALLTYPE *Flash )( 
            IApplicationView * This);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetRootSwitchableOwner)
        HRESULT ( STDMETHODCALLTYPE *GetRootSwitchableOwner )( 
            IApplicationView * This,
            /* [out] */ IApplicationView **rootSwitchableOwner);
        
        DECLSPEC_XFGVIRT(IApplicationView, EnumerateOwnershipTree)
        HRESULT ( STDMETHODCALLTYPE *EnumerateOwnershipTree )( 
            IApplicationView * This,
            /* [out] */ IObjectArray **ownershipTree);
        
        DECLSPEC_XFGVIRT(IApplicationView, GetEnterpriseId)
        HRESULT ( STDMETHODCALLTYPE *GetEnterpriseId )( 
            IApplicationView * This,
            /* [string][out] */ wchar_t **enterpriseId);
        
        DECLSPEC_XFGVIRT(IApplicationView, IsMirrored)
        HRESULT ( STDMETHODCALLTYPE *IsMirrored )( 
            IApplicationView * This,
            /* [out] */ boolean *isMirrored);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown1)
        HRESULT ( STDMETHODCALLTYPE *Unknown1 )( 
            IApplicationView * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown2)
        HRESULT ( STDMETHODCALLTYPE *Unknown2 )( 
            IApplicationView * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown3)
        HRESULT ( STDMETHODCALLTYPE *Unknown3 )( 
            IApplicationView * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown4)
        HRESULT ( STDMETHODCALLTYPE *Unknown4 )( 
            IApplicationView * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown5)
        HRESULT ( STDMETHODCALLTYPE *Unknown5 )( 
            IApplicationView * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown6)
        HRESULT ( STDMETHODCALLTYPE *Unknown6 )( 
            IApplicationView * This,
            int unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown7)
        HRESULT ( STDMETHODCALLTYPE *Unknown7 )( 
            IApplicationView * This);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown8)
        HRESULT ( STDMETHODCALLTYPE *Unknown8 )( 
            IApplicationView * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown9)
        HRESULT ( STDMETHODCALLTYPE *Unknown9 )( 
            IApplicationView * This,
            int unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown10)
        HRESULT ( STDMETHODCALLTYPE *Unknown10 )( 
            IApplicationView * This,
            int unknownX,
            int unknownY);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown11)
        HRESULT ( STDMETHODCALLTYPE *Unknown11 )( 
            IApplicationView * This,
            int unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView, Unknown12)
        HRESULT ( STDMETHODCALLTYPE *Unknown12 )( 
            IApplicationView * This,
            /* [out] */ SIZE *size1);
        
        END_INTERFACE
    } IApplicationViewVtbl;

    interface IApplicationView
    {
        CONST_VTBL struct IApplicationViewVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IApplicationView_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IApplicationView_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IApplicationView_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IApplicationView_SetFocus(This)	\
    ( (This)->lpVtbl -> SetFocus(This) ) 

#define IApplicationView_SwitchTo(This)	\
    ( (This)->lpVtbl -> SwitchTo(This) ) 

#define IApplicationView_TryInvokeBack(This,Callback)	\
    ( (This)->lpVtbl -> TryInvokeBack(This,Callback) ) 

#define IApplicationView_GetThumbnailWindow(This,hwnd)	\
    ( (This)->lpVtbl -> GetThumbnailWindow(This,hwnd) ) 

#define IApplicationView_GetMonitor(This,immersiveMonitor)	\
    ( (This)->lpVtbl -> GetMonitor(This,immersiveMonitor) ) 

#define IApplicationView_GetVisibility(This,visibility)	\
    ( (This)->lpVtbl -> GetVisibility(This,visibility) ) 

#define IApplicationView_SetCloak(This,cloakType,unknown)	\
    ( (This)->lpVtbl -> SetCloak(This,cloakType,unknown) ) 

#define IApplicationView_GetPosition(This,guid,position)	\
    ( (This)->lpVtbl -> GetPosition(This,guid,position) ) 

#define IApplicationView_SetPosition(This,position)	\
    ( (This)->lpVtbl -> SetPosition(This,position) ) 

#define IApplicationView_InsertAfterWindow(This,hwnd)	\
    ( (This)->lpVtbl -> InsertAfterWindow(This,hwnd) ) 

#define IApplicationView_GetExtendedFramePosition(This,rect)	\
    ( (This)->lpVtbl -> GetExtendedFramePosition(This,rect) ) 

#define IApplicationView_GetAppUserModelId(This,Id)	\
    ( (This)->lpVtbl -> GetAppUserModelId(This,Id) ) 

#define IApplicationView_SetAppUserModelId(This,Id)	\
    ( (This)->lpVtbl -> SetAppUserModelId(This,Id) ) 

#define IApplicationView_IsEqualByAppUserModelId(This,Id,result)	\
    ( (This)->lpVtbl -> IsEqualByAppUserModelId(This,Id,result) ) 

#define IApplicationView_GetViewState(This,state)	\
    ( (This)->lpVtbl -> GetViewState(This,state) ) 

#define IApplicationView_SetViewState(This,state)	\
    ( (This)->lpVtbl -> SetViewState(This,state) ) 

#define IApplicationView_GetNeediness(This,neediness)	\
    ( (This)->lpVtbl -> GetNeediness(This,neediness) ) 

#define IApplicationView_GetLastActivationTimestamp(This,timestamp)	\
    ( (This)->lpVtbl -> GetLastActivationTimestamp(This,timestamp) ) 

#define IApplicationView_SetLastActivationTimestamp(This,timestamp)	\
    ( (This)->lpVtbl -> SetLastActivationTimestamp(This,timestamp) ) 

#define IApplicationView_GetVirtualDesktopId(This,guid)	\
    ( (This)->lpVtbl -> GetVirtualDesktopId(This,guid) ) 

#define IApplicationView_SetVirtualDesktopId(This,guid)	\
    ( (This)->lpVtbl -> SetVirtualDesktopId(This,guid) ) 

#define IApplicationView_GetShowInSwitchers(This,flag)	\
    ( (This)->lpVtbl -> GetShowInSwitchers(This,flag) ) 

#define IApplicationView_SetShowInSwitchers(This,flag)	\
    ( (This)->lpVtbl -> SetShowInSwitchers(This,flag) ) 

#define IApplicationView_GetScaleFactor(This,factor)	\
    ( (This)->lpVtbl -> GetScaleFactor(This,factor) ) 

#define IApplicationView_CanReceiveInput(This,canReceiveInput)	\
    ( (This)->lpVtbl -> CanReceiveInput(This,canReceiveInput) ) 

#define IApplicationView_GetCompatibilityPolicyType(This,flags)	\
    ( (This)->lpVtbl -> GetCompatibilityPolicyType(This,flags) ) 

#define IApplicationView_SetCompatibilityPolicyType(This,flags)	\
    ( (This)->lpVtbl -> SetCompatibilityPolicyType(This,flags) ) 

#define IApplicationView_GetSizeConstraints(This,monitor,size1,size2)	\
    ( (This)->lpVtbl -> GetSizeConstraints(This,monitor,size1,size2) ) 

#define IApplicationView_GetSizeConstraintsForDpi(This,uint1,size1,size2)	\
    ( (This)->lpVtbl -> GetSizeConstraintsForDpi(This,uint1,size1,size2) ) 

#define IApplicationView_SetSizeConstraintsForDpi(This,uint1,size1,size2)	\
    ( (This)->lpVtbl -> SetSizeConstraintsForDpi(This,uint1,size1,size2) ) 

#define IApplicationView_OnMinSizePreferencesUpdated(This,hwnd)	\
    ( (This)->lpVtbl -> OnMinSizePreferencesUpdated(This,hwnd) ) 

#define IApplicationView_ApplyOperation(This,operation)	\
    ( (This)->lpVtbl -> ApplyOperation(This,operation) ) 

#define IApplicationView_IsTray(This,isTray)	\
    ( (This)->lpVtbl -> IsTray(This,isTray) ) 

#define IApplicationView_IsInHighZOrderBand(This,isInHighZOrderBand)	\
    ( (This)->lpVtbl -> IsInHighZOrderBand(This,isInHighZOrderBand) ) 

#define IApplicationView_IsSplashScreenPresented(This,isSplashScreenPresented)	\
    ( (This)->lpVtbl -> IsSplashScreenPresented(This,isSplashScreenPresented) ) 

#define IApplicationView_Flash(This)	\
    ( (This)->lpVtbl -> Flash(This) ) 

#define IApplicationView_GetRootSwitchableOwner(This,rootSwitchableOwner)	\
    ( (This)->lpVtbl -> GetRootSwitchableOwner(This,rootSwitchableOwner) ) 

#define IApplicationView_EnumerateOwnershipTree(This,ownershipTree)	\
    ( (This)->lpVtbl -> EnumerateOwnershipTree(This,ownershipTree) ) 

#define IApplicationView_GetEnterpriseId(This,enterpriseId)	\
    ( (This)->lpVtbl -> GetEnterpriseId(This,enterpriseId) ) 

#define IApplicationView_IsMirrored(This,isMirrored)	\
    ( (This)->lpVtbl -> IsMirrored(This,isMirrored) ) 

#define IApplicationView_Unknown1(This,unknown)	\
    ( (This)->lpVtbl -> Unknown1(This,unknown) ) 

#define IApplicationView_Unknown2(This,unknown)	\
    ( (This)->lpVtbl -> Unknown2(This,unknown) ) 

#define IApplicationView_Unknown3(This,unknown)	\
    ( (This)->lpVtbl -> Unknown3(This,unknown) ) 

#define IApplicationView_Unknown4(This,unknown)	\
    ( (This)->lpVtbl -> Unknown4(This,unknown) ) 

#define IApplicationView_Unknown5(This,unknown)	\
    ( (This)->lpVtbl -> Unknown5(This,unknown) ) 

#define IApplicationView_Unknown6(This,unknown)	\
    ( (This)->lpVtbl -> Unknown6(This,unknown) ) 

#define IApplicationView_Unknown7(This)	\
    ( (This)->lpVtbl -> Unknown7(This) ) 

#define IApplicationView_Unknown8(This,unknown)	\
    ( (This)->lpVtbl -> Unknown8(This,unknown) ) 

#define IApplicationView_Unknown9(This,unknown)	\
    ( (This)->lpVtbl -> Unknown9(This,unknown) ) 

#define IApplicationView_Unknown10(This,unknownX,unknownY)	\
    ( (This)->lpVtbl -> Unknown10(This,unknownX,unknownY) ) 

#define IApplicationView_Unknown11(This,unknown)	\
    ( (This)->lpVtbl -> Unknown11(This,unknown) ) 

#define IApplicationView_Unknown12(This,size1)	\
    ( (This)->lpVtbl -> Unknown12(This,size1) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IApplicationView_INTERFACE_DEFINED__ */


#ifndef __IApplicationView_17134_INTERFACE_DEFINED__
#define __IApplicationView_17134_INTERFACE_DEFINED__

/* interface IApplicationView_17134 */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IApplicationView_17134;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("871F602A-2B58-42B4-8C4B-6C43D642C06F")
    IApplicationView_17134 : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE SetFocus( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SwitchTo( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE TryInvokeBack( 
            /* [in] */ IUnknown *Callback) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetThumbnailWindow( 
            /* [out] */ HWND *hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetMonitor( 
            /* [out] */ IUnknown **immersiveMonitor) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetVisibility( 
            /* [out] */ int *visibility) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetCloak( 
            /* [v1_enum][in] */ APPLICATION_VIEW_CLOAK_TYPE cloakType,
            int unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetPosition( 
            /* [full][in] */ GUID *guid,
            /* [out] */ IUnknown **position) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetPosition( 
            /* [in] */ IUnknown *position) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE InsertAfterWindow( 
            /* [in] */ HWND hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetExtendedFramePosition( 
            /* [out] */ RECT *rect) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetAppUserModelId( 
            /* [string][out] */ wchar_t **Id) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetAppUserModelId( 
            /* [string][in] */ wchar_t *Id) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsEqualByAppUserModelId( 
            /* [string][in] */ wchar_t *Id,
            /* [out] */ int *result) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewState( 
            /* [out] */ unsigned int *state) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetViewState( 
            /* [in] */ unsigned int state) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetNeediness( 
            /* [out] */ int *neediness) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetLastActivationTimestamp( 
            /* [out] */ unsigned long *timestamp) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetLastActivationTimestamp( 
            /* [in] */ unsigned long timestamp) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetVirtualDesktopId( 
            /* [out] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetVirtualDesktopId( 
            /* [full][in] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetShowInSwitchers( 
            /* [out] */ int *flag) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetShowInSwitchers( 
            /* [in] */ int flag) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetScaleFactor( 
            /* [out] */ int *factor) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CanReceiveInput( 
            /* [out] */ boolean *canReceiveInput) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetCompatibilityPolicyType( 
            /* [v1_enum][out] */ APPLICATION_VIEW_COMPATIBILITY_POLICY *flags) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetCompatibilityPolicyType( 
            /* [v1_enum][in] */ APPLICATION_VIEW_COMPATIBILITY_POLICY flags) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetSizeConstraints( 
            /* [in] */ IUnknown *monitor,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetSizeConstraintsForDpi( 
            /* [in] */ unsigned int uint1,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetSizeConstraintsForDpi( 
            /* [in] */ unsigned int uint1,
            /* [full][in] */ SIZE *size1,
            /* [full][in] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnMinSizePreferencesUpdated( 
            /* [in] */ HWND hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE ApplyOperation( 
            /* [in] */ IUnknown *operation) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsTray( 
            /* [out] */ boolean *isTray) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsInHighZOrderBand( 
            /* [out] */ boolean *isInHighZOrderBand) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsSplashScreenPresented( 
            /* [out] */ boolean *isSplashScreenPresented) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Flash( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetRootSwitchableOwner( 
            /* [out] */ IApplicationView_17134 **rootSwitchableOwner) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE EnumerateOwnershipTree( 
            /* [out] */ IObjectArray **ownershipTree) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetEnterpriseId( 
            /* [string][out] */ wchar_t **enterpriseId) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsMirrored( 
            /* [out] */ boolean *isMirrored) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown1( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown2( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown3( 
            /* [out] */ int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown4( 
            /* [out] */ int *unknown) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IApplicationView_17134Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IApplicationView_17134 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IApplicationView_17134 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IApplicationView_17134 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetFocus)
        HRESULT ( STDMETHODCALLTYPE *SetFocus )( 
            IApplicationView_17134 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SwitchTo)
        HRESULT ( STDMETHODCALLTYPE *SwitchTo )( 
            IApplicationView_17134 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, TryInvokeBack)
        HRESULT ( STDMETHODCALLTYPE *TryInvokeBack )( 
            IApplicationView_17134 * This,
            /* [in] */ IUnknown *Callback);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetThumbnailWindow)
        HRESULT ( STDMETHODCALLTYPE *GetThumbnailWindow )( 
            IApplicationView_17134 * This,
            /* [out] */ HWND *hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetMonitor)
        HRESULT ( STDMETHODCALLTYPE *GetMonitor )( 
            IApplicationView_17134 * This,
            /* [out] */ IUnknown **immersiveMonitor);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetVisibility)
        HRESULT ( STDMETHODCALLTYPE *GetVisibility )( 
            IApplicationView_17134 * This,
            /* [out] */ int *visibility);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetCloak)
        HRESULT ( STDMETHODCALLTYPE *SetCloak )( 
            IApplicationView_17134 * This,
            /* [v1_enum][in] */ APPLICATION_VIEW_CLOAK_TYPE cloakType,
            int unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetPosition)
        HRESULT ( STDMETHODCALLTYPE *GetPosition )( 
            IApplicationView_17134 * This,
            /* [full][in] */ GUID *guid,
            /* [out] */ IUnknown **position);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetPosition)
        HRESULT ( STDMETHODCALLTYPE *SetPosition )( 
            IApplicationView_17134 * This,
            /* [in] */ IUnknown *position);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, InsertAfterWindow)
        HRESULT ( STDMETHODCALLTYPE *InsertAfterWindow )( 
            IApplicationView_17134 * This,
            /* [in] */ HWND hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetExtendedFramePosition)
        HRESULT ( STDMETHODCALLTYPE *GetExtendedFramePosition )( 
            IApplicationView_17134 * This,
            /* [out] */ RECT *rect);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *GetAppUserModelId )( 
            IApplicationView_17134 * This,
            /* [string][out] */ wchar_t **Id);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *SetAppUserModelId )( 
            IApplicationView_17134 * This,
            /* [string][in] */ wchar_t *Id);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, IsEqualByAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *IsEqualByAppUserModelId )( 
            IApplicationView_17134 * This,
            /* [string][in] */ wchar_t *Id,
            /* [out] */ int *result);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetViewState)
        HRESULT ( STDMETHODCALLTYPE *GetViewState )( 
            IApplicationView_17134 * This,
            /* [out] */ unsigned int *state);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetViewState)
        HRESULT ( STDMETHODCALLTYPE *SetViewState )( 
            IApplicationView_17134 * This,
            /* [in] */ unsigned int state);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetNeediness)
        HRESULT ( STDMETHODCALLTYPE *GetNeediness )( 
            IApplicationView_17134 * This,
            /* [out] */ int *neediness);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetLastActivationTimestamp)
        HRESULT ( STDMETHODCALLTYPE *GetLastActivationTimestamp )( 
            IApplicationView_17134 * This,
            /* [out] */ unsigned long *timestamp);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetLastActivationTimestamp)
        HRESULT ( STDMETHODCALLTYPE *SetLastActivationTimestamp )( 
            IApplicationView_17134 * This,
            /* [in] */ unsigned long timestamp);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetVirtualDesktopId)
        HRESULT ( STDMETHODCALLTYPE *GetVirtualDesktopId )( 
            IApplicationView_17134 * This,
            /* [out] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetVirtualDesktopId)
        HRESULT ( STDMETHODCALLTYPE *SetVirtualDesktopId )( 
            IApplicationView_17134 * This,
            /* [full][in] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetShowInSwitchers)
        HRESULT ( STDMETHODCALLTYPE *GetShowInSwitchers )( 
            IApplicationView_17134 * This,
            /* [out] */ int *flag);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetShowInSwitchers)
        HRESULT ( STDMETHODCALLTYPE *SetShowInSwitchers )( 
            IApplicationView_17134 * This,
            /* [in] */ int flag);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetScaleFactor)
        HRESULT ( STDMETHODCALLTYPE *GetScaleFactor )( 
            IApplicationView_17134 * This,
            /* [out] */ int *factor);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, CanReceiveInput)
        HRESULT ( STDMETHODCALLTYPE *CanReceiveInput )( 
            IApplicationView_17134 * This,
            /* [out] */ boolean *canReceiveInput);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetCompatibilityPolicyType)
        HRESULT ( STDMETHODCALLTYPE *GetCompatibilityPolicyType )( 
            IApplicationView_17134 * This,
            /* [v1_enum][out] */ APPLICATION_VIEW_COMPATIBILITY_POLICY *flags);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetCompatibilityPolicyType)
        HRESULT ( STDMETHODCALLTYPE *SetCompatibilityPolicyType )( 
            IApplicationView_17134 * This,
            /* [v1_enum][in] */ APPLICATION_VIEW_COMPATIBILITY_POLICY flags);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetSizeConstraints)
        HRESULT ( STDMETHODCALLTYPE *GetSizeConstraints )( 
            IApplicationView_17134 * This,
            /* [in] */ IUnknown *monitor,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetSizeConstraintsForDpi)
        HRESULT ( STDMETHODCALLTYPE *GetSizeConstraintsForDpi )( 
            IApplicationView_17134 * This,
            /* [in] */ unsigned int uint1,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, SetSizeConstraintsForDpi)
        HRESULT ( STDMETHODCALLTYPE *SetSizeConstraintsForDpi )( 
            IApplicationView_17134 * This,
            /* [in] */ unsigned int uint1,
            /* [full][in] */ SIZE *size1,
            /* [full][in] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, OnMinSizePreferencesUpdated)
        HRESULT ( STDMETHODCALLTYPE *OnMinSizePreferencesUpdated )( 
            IApplicationView_17134 * This,
            /* [in] */ HWND hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, ApplyOperation)
        HRESULT ( STDMETHODCALLTYPE *ApplyOperation )( 
            IApplicationView_17134 * This,
            /* [in] */ IUnknown *operation);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, IsTray)
        HRESULT ( STDMETHODCALLTYPE *IsTray )( 
            IApplicationView_17134 * This,
            /* [out] */ boolean *isTray);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, IsInHighZOrderBand)
        HRESULT ( STDMETHODCALLTYPE *IsInHighZOrderBand )( 
            IApplicationView_17134 * This,
            /* [out] */ boolean *isInHighZOrderBand);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, IsSplashScreenPresented)
        HRESULT ( STDMETHODCALLTYPE *IsSplashScreenPresented )( 
            IApplicationView_17134 * This,
            /* [out] */ boolean *isSplashScreenPresented);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, Flash)
        HRESULT ( STDMETHODCALLTYPE *Flash )( 
            IApplicationView_17134 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetRootSwitchableOwner)
        HRESULT ( STDMETHODCALLTYPE *GetRootSwitchableOwner )( 
            IApplicationView_17134 * This,
            /* [out] */ IApplicationView_17134 **rootSwitchableOwner);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, EnumerateOwnershipTree)
        HRESULT ( STDMETHODCALLTYPE *EnumerateOwnershipTree )( 
            IApplicationView_17134 * This,
            /* [out] */ IObjectArray **ownershipTree);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, GetEnterpriseId)
        HRESULT ( STDMETHODCALLTYPE *GetEnterpriseId )( 
            IApplicationView_17134 * This,
            /* [string][out] */ wchar_t **enterpriseId);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, IsMirrored)
        HRESULT ( STDMETHODCALLTYPE *IsMirrored )( 
            IApplicationView_17134 * This,
            /* [out] */ boolean *isMirrored);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, Unknown1)
        HRESULT ( STDMETHODCALLTYPE *Unknown1 )( 
            IApplicationView_17134 * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, Unknown2)
        HRESULT ( STDMETHODCALLTYPE *Unknown2 )( 
            IApplicationView_17134 * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, Unknown3)
        HRESULT ( STDMETHODCALLTYPE *Unknown3 )( 
            IApplicationView_17134 * This,
            /* [out] */ int *unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView_17134, Unknown4)
        HRESULT ( STDMETHODCALLTYPE *Unknown4 )( 
            IApplicationView_17134 * This,
            /* [out] */ int *unknown);
        
        END_INTERFACE
    } IApplicationView_17134Vtbl;

    interface IApplicationView_17134
    {
        CONST_VTBL struct IApplicationView_17134Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IApplicationView_17134_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IApplicationView_17134_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IApplicationView_17134_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IApplicationView_17134_SetFocus(This)	\
    ( (This)->lpVtbl -> SetFocus(This) ) 

#define IApplicationView_17134_SwitchTo(This)	\
    ( (This)->lpVtbl -> SwitchTo(This) ) 

#define IApplicationView_17134_TryInvokeBack(This,Callback)	\
    ( (This)->lpVtbl -> TryInvokeBack(This,Callback) ) 

#define IApplicationView_17134_GetThumbnailWindow(This,hwnd)	\
    ( (This)->lpVtbl -> GetThumbnailWindow(This,hwnd) ) 

#define IApplicationView_17134_GetMonitor(This,immersiveMonitor)	\
    ( (This)->lpVtbl -> GetMonitor(This,immersiveMonitor) ) 

#define IApplicationView_17134_GetVisibility(This,visibility)	\
    ( (This)->lpVtbl -> GetVisibility(This,visibility) ) 

#define IApplicationView_17134_SetCloak(This,cloakType,unknown)	\
    ( (This)->lpVtbl -> SetCloak(This,cloakType,unknown) ) 

#define IApplicationView_17134_GetPosition(This,guid,position)	\
    ( (This)->lpVtbl -> GetPosition(This,guid,position) ) 

#define IApplicationView_17134_SetPosition(This,position)	\
    ( (This)->lpVtbl -> SetPosition(This,position) ) 

#define IApplicationView_17134_InsertAfterWindow(This,hwnd)	\
    ( (This)->lpVtbl -> InsertAfterWindow(This,hwnd) ) 

#define IApplicationView_17134_GetExtendedFramePosition(This,rect)	\
    ( (This)->lpVtbl -> GetExtendedFramePosition(This,rect) ) 

#define IApplicationView_17134_GetAppUserModelId(This,Id)	\
    ( (This)->lpVtbl -> GetAppUserModelId(This,Id) ) 

#define IApplicationView_17134_SetAppUserModelId(This,Id)	\
    ( (This)->lpVtbl -> SetAppUserModelId(This,Id) ) 

#define IApplicationView_17134_IsEqualByAppUserModelId(This,Id,result)	\
    ( (This)->lpVtbl -> IsEqualByAppUserModelId(This,Id,result) ) 

#define IApplicationView_17134_GetViewState(This,state)	\
    ( (This)->lpVtbl -> GetViewState(This,state) ) 

#define IApplicationView_17134_SetViewState(This,state)	\
    ( (This)->lpVtbl -> SetViewState(This,state) ) 

#define IApplicationView_17134_GetNeediness(This,neediness)	\
    ( (This)->lpVtbl -> GetNeediness(This,neediness) ) 

#define IApplicationView_17134_GetLastActivationTimestamp(This,timestamp)	\
    ( (This)->lpVtbl -> GetLastActivationTimestamp(This,timestamp) ) 

#define IApplicationView_17134_SetLastActivationTimestamp(This,timestamp)	\
    ( (This)->lpVtbl -> SetLastActivationTimestamp(This,timestamp) ) 

#define IApplicationView_17134_GetVirtualDesktopId(This,guid)	\
    ( (This)->lpVtbl -> GetVirtualDesktopId(This,guid) ) 

#define IApplicationView_17134_SetVirtualDesktopId(This,guid)	\
    ( (This)->lpVtbl -> SetVirtualDesktopId(This,guid) ) 

#define IApplicationView_17134_GetShowInSwitchers(This,flag)	\
    ( (This)->lpVtbl -> GetShowInSwitchers(This,flag) ) 

#define IApplicationView_17134_SetShowInSwitchers(This,flag)	\
    ( (This)->lpVtbl -> SetShowInSwitchers(This,flag) ) 

#define IApplicationView_17134_GetScaleFactor(This,factor)	\
    ( (This)->lpVtbl -> GetScaleFactor(This,factor) ) 

#define IApplicationView_17134_CanReceiveInput(This,canReceiveInput)	\
    ( (This)->lpVtbl -> CanReceiveInput(This,canReceiveInput) ) 

#define IApplicationView_17134_GetCompatibilityPolicyType(This,flags)	\
    ( (This)->lpVtbl -> GetCompatibilityPolicyType(This,flags) ) 

#define IApplicationView_17134_SetCompatibilityPolicyType(This,flags)	\
    ( (This)->lpVtbl -> SetCompatibilityPolicyType(This,flags) ) 

#define IApplicationView_17134_GetSizeConstraints(This,monitor,size1,size2)	\
    ( (This)->lpVtbl -> GetSizeConstraints(This,monitor,size1,size2) ) 

#define IApplicationView_17134_GetSizeConstraintsForDpi(This,uint1,size1,size2)	\
    ( (This)->lpVtbl -> GetSizeConstraintsForDpi(This,uint1,size1,size2) ) 

#define IApplicationView_17134_SetSizeConstraintsForDpi(This,uint1,size1,size2)	\
    ( (This)->lpVtbl -> SetSizeConstraintsForDpi(This,uint1,size1,size2) ) 

#define IApplicationView_17134_OnMinSizePreferencesUpdated(This,hwnd)	\
    ( (This)->lpVtbl -> OnMinSizePreferencesUpdated(This,hwnd) ) 

#define IApplicationView_17134_ApplyOperation(This,operation)	\
    ( (This)->lpVtbl -> ApplyOperation(This,operation) ) 

#define IApplicationView_17134_IsTray(This,isTray)	\
    ( (This)->lpVtbl -> IsTray(This,isTray) ) 

#define IApplicationView_17134_IsInHighZOrderBand(This,isInHighZOrderBand)	\
    ( (This)->lpVtbl -> IsInHighZOrderBand(This,isInHighZOrderBand) ) 

#define IApplicationView_17134_IsSplashScreenPresented(This,isSplashScreenPresented)	\
    ( (This)->lpVtbl -> IsSplashScreenPresented(This,isSplashScreenPresented) ) 

#define IApplicationView_17134_Flash(This)	\
    ( (This)->lpVtbl -> Flash(This) ) 

#define IApplicationView_17134_GetRootSwitchableOwner(This,rootSwitchableOwner)	\
    ( (This)->lpVtbl -> GetRootSwitchableOwner(This,rootSwitchableOwner) ) 

#define IApplicationView_17134_EnumerateOwnershipTree(This,ownershipTree)	\
    ( (This)->lpVtbl -> EnumerateOwnershipTree(This,ownershipTree) ) 

#define IApplicationView_17134_GetEnterpriseId(This,enterpriseId)	\
    ( (This)->lpVtbl -> GetEnterpriseId(This,enterpriseId) ) 

#define IApplicationView_17134_IsMirrored(This,isMirrored)	\
    ( (This)->lpVtbl -> IsMirrored(This,isMirrored) ) 

#define IApplicationView_17134_Unknown1(This,unknown)	\
    ( (This)->lpVtbl -> Unknown1(This,unknown) ) 

#define IApplicationView_17134_Unknown2(This,unknown)	\
    ( (This)->lpVtbl -> Unknown2(This,unknown) ) 

#define IApplicationView_17134_Unknown3(This,unknown)	\
    ( (This)->lpVtbl -> Unknown3(This,unknown) ) 

#define IApplicationView_17134_Unknown4(This,unknown)	\
    ( (This)->lpVtbl -> Unknown4(This,unknown) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IApplicationView_17134_INTERFACE_DEFINED__ */


#ifndef __IApplicationView_0_INTERFACE_DEFINED__
#define __IApplicationView_0_INTERFACE_DEFINED__

/* interface IApplicationView_0 */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IApplicationView_0;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("9AC0B5C8-1484-4C5B-9533-4134A0F97CEA")
    IApplicationView_0 : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE SetFocus( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SwitchTo( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE TryInvokeBack( 
            /* [in] */ IUnknown *Callback) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetThumbnailWindow( 
            /* [out] */ HWND *hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetMonitor( 
            /* [out] */ IUnknown **immersiveMonitor) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetVisibility( 
            /* [out] */ int *visibility) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetCloak( 
            /* [v1_enum][in] */ APPLICATION_VIEW_CLOAK_TYPE cloakType,
            int unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetPosition( 
            /* [full][in] */ GUID *guid,
            /* [out] */ IUnknown **position) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetPosition( 
            /* [in] */ IUnknown *position) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE InsertAfterWindow( 
            /* [in] */ HWND hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetExtendedFramePosition( 
            /* [out] */ RECT *rect) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetAppUserModelId( 
            /* [string][out] */ wchar_t **Id) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetAppUserModelId( 
            /* [string][in] */ wchar_t *Id) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsEqualByAppUserModelId( 
            /* [string][in] */ wchar_t *Id,
            /* [out] */ int *result) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewState( 
            /* [out] */ unsigned int *state) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetViewState( 
            /* [in] */ unsigned int state) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetNeediness( 
            /* [out] */ int *neediness) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetLastActivationTimestamp( 
            /* [out] */ unsigned long *timestamp) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetLastActivationTimestamp( 
            /* [in] */ unsigned long timestamp) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetVirtualDesktopId( 
            /* [out] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetVirtualDesktopId( 
            /* [full][in] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetShowInSwitchers( 
            /* [out] */ int *flag) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetShowInSwitchers( 
            /* [in] */ int flag) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetScaleFactor( 
            /* [out] */ int *factor) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CanReceiveInput( 
            /* [out] */ boolean *canReceiveInput) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetCompatibilityPolicyType( 
            /* [v1_enum][out] */ APPLICATION_VIEW_COMPATIBILITY_POLICY *flags) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetCompatibilityPolicyType( 
            /* [v1_enum][in] */ APPLICATION_VIEW_COMPATIBILITY_POLICY flags) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetPositionPriority( 
            /* [out] */ IUnknown **priority) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetPositionPriority( 
            /* [in] */ IUnknown *priority) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetSizeConstraints( 
            /* [in] */ IUnknown *monitor,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetSizeConstraintsForDpi( 
            /* [in] */ unsigned int uint1,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetSizeConstraintsForDpi( 
            /* [in] */ unsigned int uint1,
            /* [full][in] */ SIZE *size1,
            /* [full][in] */ SIZE *size2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE QuerySizeConstraintsFromApp( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnMinSizePreferencesUpdated( 
            /* [in] */ HWND hwnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE ApplyOperation( 
            /* [in] */ IUnknown *operation) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsTray( 
            /* [out] */ boolean *isTray) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsInHighZOrderBand( 
            /* [out] */ boolean *isInHighZOrderBand) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsSplashScreenPresented( 
            /* [out] */ boolean *isSplashScreenPresented) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Flash( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetRootSwitchableOwner( 
            /* [out] */ IApplicationView_0 **rootSwitchableOwner) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE EnumerateOwnershipTree( 
            /* [out] */ IObjectArray **ownershipTree) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetEnterpriseId( 
            /* [string][out] */ wchar_t **enterpriseId) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsMirrored( 
            /* [out] */ boolean *isMirrored) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IApplicationView_0Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IApplicationView_0 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IApplicationView_0 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IApplicationView_0 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetFocus)
        HRESULT ( STDMETHODCALLTYPE *SetFocus )( 
            IApplicationView_0 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SwitchTo)
        HRESULT ( STDMETHODCALLTYPE *SwitchTo )( 
            IApplicationView_0 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, TryInvokeBack)
        HRESULT ( STDMETHODCALLTYPE *TryInvokeBack )( 
            IApplicationView_0 * This,
            /* [in] */ IUnknown *Callback);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetThumbnailWindow)
        HRESULT ( STDMETHODCALLTYPE *GetThumbnailWindow )( 
            IApplicationView_0 * This,
            /* [out] */ HWND *hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetMonitor)
        HRESULT ( STDMETHODCALLTYPE *GetMonitor )( 
            IApplicationView_0 * This,
            /* [out] */ IUnknown **immersiveMonitor);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetVisibility)
        HRESULT ( STDMETHODCALLTYPE *GetVisibility )( 
            IApplicationView_0 * This,
            /* [out] */ int *visibility);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetCloak)
        HRESULT ( STDMETHODCALLTYPE *SetCloak )( 
            IApplicationView_0 * This,
            /* [v1_enum][in] */ APPLICATION_VIEW_CLOAK_TYPE cloakType,
            int unknown);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetPosition)
        HRESULT ( STDMETHODCALLTYPE *GetPosition )( 
            IApplicationView_0 * This,
            /* [full][in] */ GUID *guid,
            /* [out] */ IUnknown **position);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetPosition)
        HRESULT ( STDMETHODCALLTYPE *SetPosition )( 
            IApplicationView_0 * This,
            /* [in] */ IUnknown *position);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, InsertAfterWindow)
        HRESULT ( STDMETHODCALLTYPE *InsertAfterWindow )( 
            IApplicationView_0 * This,
            /* [in] */ HWND hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetExtendedFramePosition)
        HRESULT ( STDMETHODCALLTYPE *GetExtendedFramePosition )( 
            IApplicationView_0 * This,
            /* [out] */ RECT *rect);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *GetAppUserModelId )( 
            IApplicationView_0 * This,
            /* [string][out] */ wchar_t **Id);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *SetAppUserModelId )( 
            IApplicationView_0 * This,
            /* [string][in] */ wchar_t *Id);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, IsEqualByAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *IsEqualByAppUserModelId )( 
            IApplicationView_0 * This,
            /* [string][in] */ wchar_t *Id,
            /* [out] */ int *result);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetViewState)
        HRESULT ( STDMETHODCALLTYPE *GetViewState )( 
            IApplicationView_0 * This,
            /* [out] */ unsigned int *state);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetViewState)
        HRESULT ( STDMETHODCALLTYPE *SetViewState )( 
            IApplicationView_0 * This,
            /* [in] */ unsigned int state);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetNeediness)
        HRESULT ( STDMETHODCALLTYPE *GetNeediness )( 
            IApplicationView_0 * This,
            /* [out] */ int *neediness);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetLastActivationTimestamp)
        HRESULT ( STDMETHODCALLTYPE *GetLastActivationTimestamp )( 
            IApplicationView_0 * This,
            /* [out] */ unsigned long *timestamp);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetLastActivationTimestamp)
        HRESULT ( STDMETHODCALLTYPE *SetLastActivationTimestamp )( 
            IApplicationView_0 * This,
            /* [in] */ unsigned long timestamp);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetVirtualDesktopId)
        HRESULT ( STDMETHODCALLTYPE *GetVirtualDesktopId )( 
            IApplicationView_0 * This,
            /* [out] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetVirtualDesktopId)
        HRESULT ( STDMETHODCALLTYPE *SetVirtualDesktopId )( 
            IApplicationView_0 * This,
            /* [full][in] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetShowInSwitchers)
        HRESULT ( STDMETHODCALLTYPE *GetShowInSwitchers )( 
            IApplicationView_0 * This,
            /* [out] */ int *flag);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetShowInSwitchers)
        HRESULT ( STDMETHODCALLTYPE *SetShowInSwitchers )( 
            IApplicationView_0 * This,
            /* [in] */ int flag);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetScaleFactor)
        HRESULT ( STDMETHODCALLTYPE *GetScaleFactor )( 
            IApplicationView_0 * This,
            /* [out] */ int *factor);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, CanReceiveInput)
        HRESULT ( STDMETHODCALLTYPE *CanReceiveInput )( 
            IApplicationView_0 * This,
            /* [out] */ boolean *canReceiveInput);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetCompatibilityPolicyType)
        HRESULT ( STDMETHODCALLTYPE *GetCompatibilityPolicyType )( 
            IApplicationView_0 * This,
            /* [v1_enum][out] */ APPLICATION_VIEW_COMPATIBILITY_POLICY *flags);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetCompatibilityPolicyType)
        HRESULT ( STDMETHODCALLTYPE *SetCompatibilityPolicyType )( 
            IApplicationView_0 * This,
            /* [v1_enum][in] */ APPLICATION_VIEW_COMPATIBILITY_POLICY flags);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetPositionPriority)
        HRESULT ( STDMETHODCALLTYPE *GetPositionPriority )( 
            IApplicationView_0 * This,
            /* [out] */ IUnknown **priority);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetPositionPriority)
        HRESULT ( STDMETHODCALLTYPE *SetPositionPriority )( 
            IApplicationView_0 * This,
            /* [in] */ IUnknown *priority);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetSizeConstraints)
        HRESULT ( STDMETHODCALLTYPE *GetSizeConstraints )( 
            IApplicationView_0 * This,
            /* [in] */ IUnknown *monitor,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetSizeConstraintsForDpi)
        HRESULT ( STDMETHODCALLTYPE *GetSizeConstraintsForDpi )( 
            IApplicationView_0 * This,
            /* [in] */ unsigned int uint1,
            /* [out] */ SIZE *size1,
            /* [out] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, SetSizeConstraintsForDpi)
        HRESULT ( STDMETHODCALLTYPE *SetSizeConstraintsForDpi )( 
            IApplicationView_0 * This,
            /* [in] */ unsigned int uint1,
            /* [full][in] */ SIZE *size1,
            /* [full][in] */ SIZE *size2);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, QuerySizeConstraintsFromApp)
        HRESULT ( STDMETHODCALLTYPE *QuerySizeConstraintsFromApp )( 
            IApplicationView_0 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, OnMinSizePreferencesUpdated)
        HRESULT ( STDMETHODCALLTYPE *OnMinSizePreferencesUpdated )( 
            IApplicationView_0 * This,
            /* [in] */ HWND hwnd);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, ApplyOperation)
        HRESULT ( STDMETHODCALLTYPE *ApplyOperation )( 
            IApplicationView_0 * This,
            /* [in] */ IUnknown *operation);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, IsTray)
        HRESULT ( STDMETHODCALLTYPE *IsTray )( 
            IApplicationView_0 * This,
            /* [out] */ boolean *isTray);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, IsInHighZOrderBand)
        HRESULT ( STDMETHODCALLTYPE *IsInHighZOrderBand )( 
            IApplicationView_0 * This,
            /* [out] */ boolean *isInHighZOrderBand);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, IsSplashScreenPresented)
        HRESULT ( STDMETHODCALLTYPE *IsSplashScreenPresented )( 
            IApplicationView_0 * This,
            /* [out] */ boolean *isSplashScreenPresented);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, Flash)
        HRESULT ( STDMETHODCALLTYPE *Flash )( 
            IApplicationView_0 * This);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetRootSwitchableOwner)
        HRESULT ( STDMETHODCALLTYPE *GetRootSwitchableOwner )( 
            IApplicationView_0 * This,
            /* [out] */ IApplicationView_0 **rootSwitchableOwner);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, EnumerateOwnershipTree)
        HRESULT ( STDMETHODCALLTYPE *EnumerateOwnershipTree )( 
            IApplicationView_0 * This,
            /* [out] */ IObjectArray **ownershipTree);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, GetEnterpriseId)
        HRESULT ( STDMETHODCALLTYPE *GetEnterpriseId )( 
            IApplicationView_0 * This,
            /* [string][out] */ wchar_t **enterpriseId);
        
        DECLSPEC_XFGVIRT(IApplicationView_0, IsMirrored)
        HRESULT ( STDMETHODCALLTYPE *IsMirrored )( 
            IApplicationView_0 * This,
            /* [out] */ boolean *isMirrored);
        
        END_INTERFACE
    } IApplicationView_0Vtbl;

    interface IApplicationView_0
    {
        CONST_VTBL struct IApplicationView_0Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IApplicationView_0_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IApplicationView_0_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IApplicationView_0_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IApplicationView_0_SetFocus(This)	\
    ( (This)->lpVtbl -> SetFocus(This) ) 

#define IApplicationView_0_SwitchTo(This)	\
    ( (This)->lpVtbl -> SwitchTo(This) ) 

#define IApplicationView_0_TryInvokeBack(This,Callback)	\
    ( (This)->lpVtbl -> TryInvokeBack(This,Callback) ) 

#define IApplicationView_0_GetThumbnailWindow(This,hwnd)	\
    ( (This)->lpVtbl -> GetThumbnailWindow(This,hwnd) ) 

#define IApplicationView_0_GetMonitor(This,immersiveMonitor)	\
    ( (This)->lpVtbl -> GetMonitor(This,immersiveMonitor) ) 

#define IApplicationView_0_GetVisibility(This,visibility)	\
    ( (This)->lpVtbl -> GetVisibility(This,visibility) ) 

#define IApplicationView_0_SetCloak(This,cloakType,unknown)	\
    ( (This)->lpVtbl -> SetCloak(This,cloakType,unknown) ) 

#define IApplicationView_0_GetPosition(This,guid,position)	\
    ( (This)->lpVtbl -> GetPosition(This,guid,position) ) 

#define IApplicationView_0_SetPosition(This,position)	\
    ( (This)->lpVtbl -> SetPosition(This,position) ) 

#define IApplicationView_0_InsertAfterWindow(This,hwnd)	\
    ( (This)->lpVtbl -> InsertAfterWindow(This,hwnd) ) 

#define IApplicationView_0_GetExtendedFramePosition(This,rect)	\
    ( (This)->lpVtbl -> GetExtendedFramePosition(This,rect) ) 

#define IApplicationView_0_GetAppUserModelId(This,Id)	\
    ( (This)->lpVtbl -> GetAppUserModelId(This,Id) ) 

#define IApplicationView_0_SetAppUserModelId(This,Id)	\
    ( (This)->lpVtbl -> SetAppUserModelId(This,Id) ) 

#define IApplicationView_0_IsEqualByAppUserModelId(This,Id,result)	\
    ( (This)->lpVtbl -> IsEqualByAppUserModelId(This,Id,result) ) 

#define IApplicationView_0_GetViewState(This,state)	\
    ( (This)->lpVtbl -> GetViewState(This,state) ) 

#define IApplicationView_0_SetViewState(This,state)	\
    ( (This)->lpVtbl -> SetViewState(This,state) ) 

#define IApplicationView_0_GetNeediness(This,neediness)	\
    ( (This)->lpVtbl -> GetNeediness(This,neediness) ) 

#define IApplicationView_0_GetLastActivationTimestamp(This,timestamp)	\
    ( (This)->lpVtbl -> GetLastActivationTimestamp(This,timestamp) ) 

#define IApplicationView_0_SetLastActivationTimestamp(This,timestamp)	\
    ( (This)->lpVtbl -> SetLastActivationTimestamp(This,timestamp) ) 

#define IApplicationView_0_GetVirtualDesktopId(This,guid)	\
    ( (This)->lpVtbl -> GetVirtualDesktopId(This,guid) ) 

#define IApplicationView_0_SetVirtualDesktopId(This,guid)	\
    ( (This)->lpVtbl -> SetVirtualDesktopId(This,guid) ) 

#define IApplicationView_0_GetShowInSwitchers(This,flag)	\
    ( (This)->lpVtbl -> GetShowInSwitchers(This,flag) ) 

#define IApplicationView_0_SetShowInSwitchers(This,flag)	\
    ( (This)->lpVtbl -> SetShowInSwitchers(This,flag) ) 

#define IApplicationView_0_GetScaleFactor(This,factor)	\
    ( (This)->lpVtbl -> GetScaleFactor(This,factor) ) 

#define IApplicationView_0_CanReceiveInput(This,canReceiveInput)	\
    ( (This)->lpVtbl -> CanReceiveInput(This,canReceiveInput) ) 

#define IApplicationView_0_GetCompatibilityPolicyType(This,flags)	\
    ( (This)->lpVtbl -> GetCompatibilityPolicyType(This,flags) ) 

#define IApplicationView_0_SetCompatibilityPolicyType(This,flags)	\
    ( (This)->lpVtbl -> SetCompatibilityPolicyType(This,flags) ) 

#define IApplicationView_0_GetPositionPriority(This,priority)	\
    ( (This)->lpVtbl -> GetPositionPriority(This,priority) ) 

#define IApplicationView_0_SetPositionPriority(This,priority)	\
    ( (This)->lpVtbl -> SetPositionPriority(This,priority) ) 

#define IApplicationView_0_GetSizeConstraints(This,monitor,size1,size2)	\
    ( (This)->lpVtbl -> GetSizeConstraints(This,monitor,size1,size2) ) 

#define IApplicationView_0_GetSizeConstraintsForDpi(This,uint1,size1,size2)	\
    ( (This)->lpVtbl -> GetSizeConstraintsForDpi(This,uint1,size1,size2) ) 

#define IApplicationView_0_SetSizeConstraintsForDpi(This,uint1,size1,size2)	\
    ( (This)->lpVtbl -> SetSizeConstraintsForDpi(This,uint1,size1,size2) ) 

#define IApplicationView_0_QuerySizeConstraintsFromApp(This)	\
    ( (This)->lpVtbl -> QuerySizeConstraintsFromApp(This) ) 

#define IApplicationView_0_OnMinSizePreferencesUpdated(This,hwnd)	\
    ( (This)->lpVtbl -> OnMinSizePreferencesUpdated(This,hwnd) ) 

#define IApplicationView_0_ApplyOperation(This,operation)	\
    ( (This)->lpVtbl -> ApplyOperation(This,operation) ) 

#define IApplicationView_0_IsTray(This,isTray)	\
    ( (This)->lpVtbl -> IsTray(This,isTray) ) 

#define IApplicationView_0_IsInHighZOrderBand(This,isInHighZOrderBand)	\
    ( (This)->lpVtbl -> IsInHighZOrderBand(This,isInHighZOrderBand) ) 

#define IApplicationView_0_IsSplashScreenPresented(This,isSplashScreenPresented)	\
    ( (This)->lpVtbl -> IsSplashScreenPresented(This,isSplashScreenPresented) ) 

#define IApplicationView_0_Flash(This)	\
    ( (This)->lpVtbl -> Flash(This) ) 

#define IApplicationView_0_GetRootSwitchableOwner(This,rootSwitchableOwner)	\
    ( (This)->lpVtbl -> GetRootSwitchableOwner(This,rootSwitchableOwner) ) 

#define IApplicationView_0_EnumerateOwnershipTree(This,ownershipTree)	\
    ( (This)->lpVtbl -> EnumerateOwnershipTree(This,ownershipTree) ) 

#define IApplicationView_0_GetEnterpriseId(This,enterpriseId)	\
    ( (This)->lpVtbl -> GetEnterpriseId(This,enterpriseId) ) 

#define IApplicationView_0_IsMirrored(This,isMirrored)	\
    ( (This)->lpVtbl -> IsMirrored(This,isMirrored) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IApplicationView_0_INTERFACE_DEFINED__ */


/* interface __MIDL_itf_VirtualDesktop_0000_0003 */
/* [local] */ 

#pragma endregion
#pragma region IApplicationViewCollection


extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0003_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0003_v0_0_s_ifspec;

#ifndef __IApplicationViewCollection_INTERFACE_DEFINED__
#define __IApplicationViewCollection_INTERFACE_DEFINED__

/* interface IApplicationViewCollection */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IApplicationViewCollection;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("1841C6D7-4F9D-42C0-AF41-8747538F10E5")
    IApplicationViewCollection : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetViews( 
            /* [out] */ IObjectArray **array) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewsByZOrder( 
            /* [out] */ IObjectArray **array) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewsByAppUserModelId( 
            /* [string][in] */ wchar_t *Id,
            /* [out] */ IObjectArray **array) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewForHwnd( 
            /* [full][in] */ HWND hwnd,
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewForApplication( 
            /* [in] */ IUnknown *application,
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewForAppUserModelId( 
            /* [string][in] */ wchar_t *Id,
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewInFocus( 
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown1( 
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RefreshCollection( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RegisterForApplicationViewChanges( 
            /* [in] */ IUnknown *listener,
            /* [out] */ int *cookie) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE UnregisterForApplicationViewChanges( 
            /* [in] */ int cookie) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IApplicationViewCollectionVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IApplicationViewCollection * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IApplicationViewCollection * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IApplicationViewCollection * This);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, GetViews)
        HRESULT ( STDMETHODCALLTYPE *GetViews )( 
            IApplicationViewCollection * This,
            /* [out] */ IObjectArray **array);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, GetViewsByZOrder)
        HRESULT ( STDMETHODCALLTYPE *GetViewsByZOrder )( 
            IApplicationViewCollection * This,
            /* [out] */ IObjectArray **array);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, GetViewsByAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *GetViewsByAppUserModelId )( 
            IApplicationViewCollection * This,
            /* [string][in] */ wchar_t *Id,
            /* [out] */ IObjectArray **array);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, GetViewForHwnd)
        HRESULT ( STDMETHODCALLTYPE *GetViewForHwnd )( 
            IApplicationViewCollection * This,
            /* [full][in] */ HWND hwnd,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, GetViewForApplication)
        HRESULT ( STDMETHODCALLTYPE *GetViewForApplication )( 
            IApplicationViewCollection * This,
            /* [in] */ IUnknown *application,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, GetViewForAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *GetViewForAppUserModelId )( 
            IApplicationViewCollection * This,
            /* [string][in] */ wchar_t *Id,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, GetViewInFocus)
        HRESULT ( STDMETHODCALLTYPE *GetViewInFocus )( 
            IApplicationViewCollection * This,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, Unknown1)
        HRESULT ( STDMETHODCALLTYPE *Unknown1 )( 
            IApplicationViewCollection * This,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, RefreshCollection)
        HRESULT ( STDMETHODCALLTYPE *RefreshCollection )( 
            IApplicationViewCollection * This);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, RegisterForApplicationViewChanges)
        HRESULT ( STDMETHODCALLTYPE *RegisterForApplicationViewChanges )( 
            IApplicationViewCollection * This,
            /* [in] */ IUnknown *listener,
            /* [out] */ int *cookie);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection, UnregisterForApplicationViewChanges)
        HRESULT ( STDMETHODCALLTYPE *UnregisterForApplicationViewChanges )( 
            IApplicationViewCollection * This,
            /* [in] */ int cookie);
        
        END_INTERFACE
    } IApplicationViewCollectionVtbl;

    interface IApplicationViewCollection
    {
        CONST_VTBL struct IApplicationViewCollectionVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IApplicationViewCollection_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IApplicationViewCollection_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IApplicationViewCollection_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IApplicationViewCollection_GetViews(This,array)	\
    ( (This)->lpVtbl -> GetViews(This,array) ) 

#define IApplicationViewCollection_GetViewsByZOrder(This,array)	\
    ( (This)->lpVtbl -> GetViewsByZOrder(This,array) ) 

#define IApplicationViewCollection_GetViewsByAppUserModelId(This,Id,array)	\
    ( (This)->lpVtbl -> GetViewsByAppUserModelId(This,Id,array) ) 

#define IApplicationViewCollection_GetViewForHwnd(This,hwnd,view)	\
    ( (This)->lpVtbl -> GetViewForHwnd(This,hwnd,view) ) 

#define IApplicationViewCollection_GetViewForApplication(This,application,view)	\
    ( (This)->lpVtbl -> GetViewForApplication(This,application,view) ) 

#define IApplicationViewCollection_GetViewForAppUserModelId(This,Id,view)	\
    ( (This)->lpVtbl -> GetViewForAppUserModelId(This,Id,view) ) 

#define IApplicationViewCollection_GetViewInFocus(This,view)	\
    ( (This)->lpVtbl -> GetViewInFocus(This,view) ) 

#define IApplicationViewCollection_Unknown1(This,view)	\
    ( (This)->lpVtbl -> Unknown1(This,view) ) 

#define IApplicationViewCollection_RefreshCollection(This)	\
    ( (This)->lpVtbl -> RefreshCollection(This) ) 

#define IApplicationViewCollection_RegisterForApplicationViewChanges(This,listener,cookie)	\
    ( (This)->lpVtbl -> RegisterForApplicationViewChanges(This,listener,cookie) ) 

#define IApplicationViewCollection_UnregisterForApplicationViewChanges(This,cookie)	\
    ( (This)->lpVtbl -> UnregisterForApplicationViewChanges(This,cookie) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IApplicationViewCollection_INTERFACE_DEFINED__ */


#ifndef __IApplicationViewCollection_0_INTERFACE_DEFINED__
#define __IApplicationViewCollection_0_INTERFACE_DEFINED__

/* interface IApplicationViewCollection_0 */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IApplicationViewCollection_0;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("2C08ADF0-A386-4B35-9250-0FE183476FCC")
    IApplicationViewCollection_0 : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetViews( 
            /* [out] */ IObjectArray **array) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewsByZOrder( 
            /* [out] */ IObjectArray **array) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewsByAppUserModelId( 
            /* [string][in] */ wchar_t *Id,
            /* [out] */ IObjectArray **array) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewForHwnd( 
            /* [full][in] */ HWND hwnd,
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewForApplication( 
            /* [in] */ IUnknown *application,
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewForAppUserModelId( 
            /* [string][in] */ wchar_t *Id,
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetViewInFocus( 
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown1( 
            /* [out] */ IApplicationView **view) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RefreshCollection( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RegisterForApplicationViewChanges( 
            /* [in] */ IUnknown *listener,
            /* [out] */ int *cookie) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RegisterForApplicationViewPositionChanges( 
            /* [in] */ IUnknown *listener,
            /* [out] */ int *cookie) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE UnregisterForApplicationViewChanges( 
            /* [in] */ int cookie) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IApplicationViewCollection_0Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IApplicationViewCollection_0 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IApplicationViewCollection_0 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IApplicationViewCollection_0 * This);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, GetViews)
        HRESULT ( STDMETHODCALLTYPE *GetViews )( 
            IApplicationViewCollection_0 * This,
            /* [out] */ IObjectArray **array);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, GetViewsByZOrder)
        HRESULT ( STDMETHODCALLTYPE *GetViewsByZOrder )( 
            IApplicationViewCollection_0 * This,
            /* [out] */ IObjectArray **array);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, GetViewsByAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *GetViewsByAppUserModelId )( 
            IApplicationViewCollection_0 * This,
            /* [string][in] */ wchar_t *Id,
            /* [out] */ IObjectArray **array);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, GetViewForHwnd)
        HRESULT ( STDMETHODCALLTYPE *GetViewForHwnd )( 
            IApplicationViewCollection_0 * This,
            /* [full][in] */ HWND hwnd,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, GetViewForApplication)
        HRESULT ( STDMETHODCALLTYPE *GetViewForApplication )( 
            IApplicationViewCollection_0 * This,
            /* [in] */ IUnknown *application,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, GetViewForAppUserModelId)
        HRESULT ( STDMETHODCALLTYPE *GetViewForAppUserModelId )( 
            IApplicationViewCollection_0 * This,
            /* [string][in] */ wchar_t *Id,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, GetViewInFocus)
        HRESULT ( STDMETHODCALLTYPE *GetViewInFocus )( 
            IApplicationViewCollection_0 * This,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, Unknown1)
        HRESULT ( STDMETHODCALLTYPE *Unknown1 )( 
            IApplicationViewCollection_0 * This,
            /* [out] */ IApplicationView **view);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, RefreshCollection)
        HRESULT ( STDMETHODCALLTYPE *RefreshCollection )( 
            IApplicationViewCollection_0 * This);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, RegisterForApplicationViewChanges)
        HRESULT ( STDMETHODCALLTYPE *RegisterForApplicationViewChanges )( 
            IApplicationViewCollection_0 * This,
            /* [in] */ IUnknown *listener,
            /* [out] */ int *cookie);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, RegisterForApplicationViewPositionChanges)
        HRESULT ( STDMETHODCALLTYPE *RegisterForApplicationViewPositionChanges )( 
            IApplicationViewCollection_0 * This,
            /* [in] */ IUnknown *listener,
            /* [out] */ int *cookie);
        
        DECLSPEC_XFGVIRT(IApplicationViewCollection_0, UnregisterForApplicationViewChanges)
        HRESULT ( STDMETHODCALLTYPE *UnregisterForApplicationViewChanges )( 
            IApplicationViewCollection_0 * This,
            /* [in] */ int cookie);
        
        END_INTERFACE
    } IApplicationViewCollection_0Vtbl;

    interface IApplicationViewCollection_0
    {
        CONST_VTBL struct IApplicationViewCollection_0Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IApplicationViewCollection_0_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IApplicationViewCollection_0_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IApplicationViewCollection_0_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IApplicationViewCollection_0_GetViews(This,array)	\
    ( (This)->lpVtbl -> GetViews(This,array) ) 

#define IApplicationViewCollection_0_GetViewsByZOrder(This,array)	\
    ( (This)->lpVtbl -> GetViewsByZOrder(This,array) ) 

#define IApplicationViewCollection_0_GetViewsByAppUserModelId(This,Id,array)	\
    ( (This)->lpVtbl -> GetViewsByAppUserModelId(This,Id,array) ) 

#define IApplicationViewCollection_0_GetViewForHwnd(This,hwnd,view)	\
    ( (This)->lpVtbl -> GetViewForHwnd(This,hwnd,view) ) 

#define IApplicationViewCollection_0_GetViewForApplication(This,application,view)	\
    ( (This)->lpVtbl -> GetViewForApplication(This,application,view) ) 

#define IApplicationViewCollection_0_GetViewForAppUserModelId(This,Id,view)	\
    ( (This)->lpVtbl -> GetViewForAppUserModelId(This,Id,view) ) 

#define IApplicationViewCollection_0_GetViewInFocus(This,view)	\
    ( (This)->lpVtbl -> GetViewInFocus(This,view) ) 

#define IApplicationViewCollection_0_Unknown1(This,view)	\
    ( (This)->lpVtbl -> Unknown1(This,view) ) 

#define IApplicationViewCollection_0_RefreshCollection(This)	\
    ( (This)->lpVtbl -> RefreshCollection(This) ) 

#define IApplicationViewCollection_0_RegisterForApplicationViewChanges(This,listener,cookie)	\
    ( (This)->lpVtbl -> RegisterForApplicationViewChanges(This,listener,cookie) ) 

#define IApplicationViewCollection_0_RegisterForApplicationViewPositionChanges(This,listener,cookie)	\
    ( (This)->lpVtbl -> RegisterForApplicationViewPositionChanges(This,listener,cookie) ) 

#define IApplicationViewCollection_0_UnregisterForApplicationViewChanges(This,cookie)	\
    ( (This)->lpVtbl -> UnregisterForApplicationViewChanges(This,cookie) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IApplicationViewCollection_0_INTERFACE_DEFINED__ */


/* interface __MIDL_itf_VirtualDesktop_0000_0005 */
/* [local] */ 

#pragma endregion
#pragma region IVirtualDesktop


extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0005_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0005_v0_0_s_ifspec;

#ifndef __IVirtualDesktop_INTERFACE_DEFINED__
#define __IVirtualDesktop_INTERFACE_DEFINED__

/* interface IVirtualDesktop */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IVirtualDesktop;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("3F07F4BE-B107-441A-AF0F-39D82529072C")
    IVirtualDesktop : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE IsViewVisible( 
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *isVisible) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetId( 
            /* [out] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetName( 
            /* [out] */ HSTRING *name) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetWallpaperPath( 
            /* [out] */ HSTRING *path) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsRemote( 
            /* [out] */ boolean *isRemote) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IVirtualDesktopVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IVirtualDesktop * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IVirtualDesktop * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IVirtualDesktop * This);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop, IsViewVisible)
        HRESULT ( STDMETHODCALLTYPE *IsViewVisible )( 
            IVirtualDesktop * This,
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *isVisible);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop, GetId)
        HRESULT ( STDMETHODCALLTYPE *GetId )( 
            IVirtualDesktop * This,
            /* [out] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop, GetName)
        HRESULT ( STDMETHODCALLTYPE *GetName )( 
            IVirtualDesktop * This,
            /* [out] */ HSTRING *name);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop, GetWallpaperPath)
        HRESULT ( STDMETHODCALLTYPE *GetWallpaperPath )( 
            IVirtualDesktop * This,
            /* [out] */ HSTRING *path);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop, IsRemote)
        HRESULT ( STDMETHODCALLTYPE *IsRemote )( 
            IVirtualDesktop * This,
            /* [out] */ boolean *isRemote);
        
        END_INTERFACE
    } IVirtualDesktopVtbl;

    interface IVirtualDesktop
    {
        CONST_VTBL struct IVirtualDesktopVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IVirtualDesktop_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IVirtualDesktop_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IVirtualDesktop_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IVirtualDesktop_IsViewVisible(This,view,isVisible)	\
    ( (This)->lpVtbl -> IsViewVisible(This,view,isVisible) ) 

#define IVirtualDesktop_GetId(This,guid)	\
    ( (This)->lpVtbl -> GetId(This,guid) ) 

#define IVirtualDesktop_GetName(This,name)	\
    ( (This)->lpVtbl -> GetName(This,name) ) 

#define IVirtualDesktop_GetWallpaperPath(This,path)	\
    ( (This)->lpVtbl -> GetWallpaperPath(This,path) ) 

#define IVirtualDesktop_IsRemote(This,isRemote)	\
    ( (This)->lpVtbl -> IsRemote(This,isRemote) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IVirtualDesktop_INTERFACE_DEFINED__ */


#ifndef __IVirtualDesktop_22000_INTERFACE_DEFINED__
#define __IVirtualDesktop_22000_INTERFACE_DEFINED__

/* interface IVirtualDesktop_22000 */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IVirtualDesktop_22000;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("536D3495-B208-4CC9-AE26-DE8111275BF8")
    IVirtualDesktop_22000 : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE IsViewVisible( 
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *isVisible) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetId( 
            /* [out] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown1( 
            int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetName( 
            /* [out] */ HSTRING *name) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetWallpaperPath( 
            /* [out] */ HSTRING *path) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IVirtualDesktop_22000Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IVirtualDesktop_22000 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IVirtualDesktop_22000 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IVirtualDesktop_22000 * This);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_22000, IsViewVisible)
        HRESULT ( STDMETHODCALLTYPE *IsViewVisible )( 
            IVirtualDesktop_22000 * This,
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *isVisible);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_22000, GetId)
        HRESULT ( STDMETHODCALLTYPE *GetId )( 
            IVirtualDesktop_22000 * This,
            /* [out] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_22000, Unknown1)
        HRESULT ( STDMETHODCALLTYPE *Unknown1 )( 
            IVirtualDesktop_22000 * This,
            int *unknown);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_22000, GetName)
        HRESULT ( STDMETHODCALLTYPE *GetName )( 
            IVirtualDesktop_22000 * This,
            /* [out] */ HSTRING *name);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_22000, GetWallpaperPath)
        HRESULT ( STDMETHODCALLTYPE *GetWallpaperPath )( 
            IVirtualDesktop_22000 * This,
            /* [out] */ HSTRING *path);
        
        END_INTERFACE
    } IVirtualDesktop_22000Vtbl;

    interface IVirtualDesktop_22000
    {
        CONST_VTBL struct IVirtualDesktop_22000Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IVirtualDesktop_22000_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IVirtualDesktop_22000_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IVirtualDesktop_22000_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IVirtualDesktop_22000_IsViewVisible(This,view,isVisible)	\
    ( (This)->lpVtbl -> IsViewVisible(This,view,isVisible) ) 

#define IVirtualDesktop_22000_GetId(This,guid)	\
    ( (This)->lpVtbl -> GetId(This,guid) ) 

#define IVirtualDesktop_22000_Unknown1(This,unknown)	\
    ( (This)->lpVtbl -> Unknown1(This,unknown) ) 

#define IVirtualDesktop_22000_GetName(This,name)	\
    ( (This)->lpVtbl -> GetName(This,name) ) 

#define IVirtualDesktop_22000_GetWallpaperPath(This,path)	\
    ( (This)->lpVtbl -> GetWallpaperPath(This,path) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IVirtualDesktop_22000_INTERFACE_DEFINED__ */


#ifndef __IVirtualDesktop_20348_INTERFACE_DEFINED__
#define __IVirtualDesktop_20348_INTERFACE_DEFINED__

/* interface IVirtualDesktop_20348 */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IVirtualDesktop_20348;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("62FDF88B-11CA-4AFB-8BD8-2296DFAE49E2")
    IVirtualDesktop_20348 : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE IsViewVisible( 
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *isVisible) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetId( 
            /* [out] */ GUID *guid) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unknown1( 
            int *unknown) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetName( 
            /* [out] */ HSTRING *name) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IVirtualDesktop_20348Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IVirtualDesktop_20348 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IVirtualDesktop_20348 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IVirtualDesktop_20348 * This);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_20348, IsViewVisible)
        HRESULT ( STDMETHODCALLTYPE *IsViewVisible )( 
            IVirtualDesktop_20348 * This,
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *isVisible);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_20348, GetId)
        HRESULT ( STDMETHODCALLTYPE *GetId )( 
            IVirtualDesktop_20348 * This,
            /* [out] */ GUID *guid);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_20348, Unknown1)
        HRESULT ( STDMETHODCALLTYPE *Unknown1 )( 
            IVirtualDesktop_20348 * This,
            int *unknown);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_20348, GetName)
        HRESULT ( STDMETHODCALLTYPE *GetName )( 
            IVirtualDesktop_20348 * This,
            /* [out] */ HSTRING *name);
        
        END_INTERFACE
    } IVirtualDesktop_20348Vtbl;

    interface IVirtualDesktop_20348
    {
        CONST_VTBL struct IVirtualDesktop_20348Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IVirtualDesktop_20348_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IVirtualDesktop_20348_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IVirtualDesktop_20348_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IVirtualDesktop_20348_IsViewVisible(This,view,isVisible)	\
    ( (This)->lpVtbl -> IsViewVisible(This,view,isVisible) ) 

#define IVirtualDesktop_20348_GetId(This,guid)	\
    ( (This)->lpVtbl -> GetId(This,guid) ) 

#define IVirtualDesktop_20348_Unknown1(This,unknown)	\
    ( (This)->lpVtbl -> Unknown1(This,unknown) ) 

#define IVirtualDesktop_20348_GetName(This,name)	\
    ( (This)->lpVtbl -> GetName(This,name) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IVirtualDesktop_20348_INTERFACE_DEFINED__ */


#ifndef __IVirtualDesktop_0_INTERFACE_DEFINED__
#define __IVirtualDesktop_0_INTERFACE_DEFINED__

/* interface IVirtualDesktop_0 */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IVirtualDesktop_0;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("FF72FFDD-BE7E-43FC-9C03-AD81681E88E4")
    IVirtualDesktop_0 : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE IsViewVisible( 
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *isVisible) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetId( 
            /* [out] */ GUID *guid) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IVirtualDesktop_0Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IVirtualDesktop_0 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IVirtualDesktop_0 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IVirtualDesktop_0 * This);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_0, IsViewVisible)
        HRESULT ( STDMETHODCALLTYPE *IsViewVisible )( 
            IVirtualDesktop_0 * This,
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *isVisible);
        
        DECLSPEC_XFGVIRT(IVirtualDesktop_0, GetId)
        HRESULT ( STDMETHODCALLTYPE *GetId )( 
            IVirtualDesktop_0 * This,
            /* [out] */ GUID *guid);
        
        END_INTERFACE
    } IVirtualDesktop_0Vtbl;

    interface IVirtualDesktop_0
    {
        CONST_VTBL struct IVirtualDesktop_0Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IVirtualDesktop_0_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IVirtualDesktop_0_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IVirtualDesktop_0_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IVirtualDesktop_0_IsViewVisible(This,view,isVisible)	\
    ( (This)->lpVtbl -> IsViewVisible(This,view,isVisible) ) 

#define IVirtualDesktop_0_GetId(This,guid)	\
    ( (This)->lpVtbl -> GetId(This,guid) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IVirtualDesktop_0_INTERFACE_DEFINED__ */


/* interface __MIDL_itf_VirtualDesktop_0000_0009 */
/* [local] */ 

#pragma endregion
#pragma region IVirtualDesktopPinnedApps


extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0009_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0009_v0_0_s_ifspec;

#ifndef __IVirtualDesktopPinnedApps_INTERFACE_DEFINED__
#define __IVirtualDesktopPinnedApps_INTERFACE_DEFINED__

/* interface IVirtualDesktopPinnedApps */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IVirtualDesktopPinnedApps;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("4CE81583-1E4C-4632-A621-07A53543148F")
    IVirtualDesktopPinnedApps : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE IsAppIdPinned( 
            /* [string][in] */ wchar_t *appId) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE PinAppID( 
            /* [string][in] */ wchar_t *appId) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE UnpinAppID( 
            /* [string][in] */ wchar_t *appId) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE IsViewPinned( 
            /* [in] */ IApplicationView *applicationView,
            /* [out] */ boolean *pinned) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE PinView( 
            /* [in] */ IApplicationView *applicationView) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE UnpinView( 
            /* [in] */ IApplicationView *applicationView) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IVirtualDesktopPinnedAppsVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IVirtualDesktopPinnedApps * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IVirtualDesktopPinnedApps * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IVirtualDesktopPinnedApps * This);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopPinnedApps, IsAppIdPinned)
        HRESULT ( STDMETHODCALLTYPE *IsAppIdPinned )( 
            IVirtualDesktopPinnedApps * This,
            /* [string][in] */ wchar_t *appId);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopPinnedApps, PinAppID)
        HRESULT ( STDMETHODCALLTYPE *PinAppID )( 
            IVirtualDesktopPinnedApps * This,
            /* [string][in] */ wchar_t *appId);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopPinnedApps, UnpinAppID)
        HRESULT ( STDMETHODCALLTYPE *UnpinAppID )( 
            IVirtualDesktopPinnedApps * This,
            /* [string][in] */ wchar_t *appId);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopPinnedApps, IsViewPinned)
        HRESULT ( STDMETHODCALLTYPE *IsViewPinned )( 
            IVirtualDesktopPinnedApps * This,
            /* [in] */ IApplicationView *applicationView,
            /* [out] */ boolean *pinned);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopPinnedApps, PinView)
        HRESULT ( STDMETHODCALLTYPE *PinView )( 
            IVirtualDesktopPinnedApps * This,
            /* [in] */ IApplicationView *applicationView);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopPinnedApps, UnpinView)
        HRESULT ( STDMETHODCALLTYPE *UnpinView )( 
            IVirtualDesktopPinnedApps * This,
            /* [in] */ IApplicationView *applicationView);
        
        END_INTERFACE
    } IVirtualDesktopPinnedAppsVtbl;

    interface IVirtualDesktopPinnedApps
    {
        CONST_VTBL struct IVirtualDesktopPinnedAppsVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IVirtualDesktopPinnedApps_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IVirtualDesktopPinnedApps_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IVirtualDesktopPinnedApps_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IVirtualDesktopPinnedApps_IsAppIdPinned(This,appId)	\
    ( (This)->lpVtbl -> IsAppIdPinned(This,appId) ) 

#define IVirtualDesktopPinnedApps_PinAppID(This,appId)	\
    ( (This)->lpVtbl -> PinAppID(This,appId) ) 

#define IVirtualDesktopPinnedApps_UnpinAppID(This,appId)	\
    ( (This)->lpVtbl -> UnpinAppID(This,appId) ) 

#define IVirtualDesktopPinnedApps_IsViewPinned(This,applicationView,pinned)	\
    ( (This)->lpVtbl -> IsViewPinned(This,applicationView,pinned) ) 

#define IVirtualDesktopPinnedApps_PinView(This,applicationView)	\
    ( (This)->lpVtbl -> PinView(This,applicationView) ) 

#define IVirtualDesktopPinnedApps_UnpinView(This,applicationView)	\
    ( (This)->lpVtbl -> UnpinView(This,applicationView) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IVirtualDesktopPinnedApps_INTERFACE_DEFINED__ */


/* interface __MIDL_itf_VirtualDesktop_0000_0010 */
/* [local] */ 

#pragma endregion
#pragma region IVirtualDesktopManagerInternal
typedef /* [public][public] */ 
enum __MIDL___MIDL_itf_VirtualDesktop_0000_0010_0001
    {
        VDMI_ADD_LEFT_DIRECTION	= 3,
        VDMI_ADD_RIGHT_DIRECTION	= 4
    } 	VDMI_ADJACENT_DESKTOP_DIRECTION;



extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0010_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0010_v0_0_s_ifspec;

#ifndef __IVirtualDesktopManagerInternal_INTERFACE_DEFINED__
#define __IVirtualDesktopManagerInternal_INTERFACE_DEFINED__

/* interface IVirtualDesktopManagerInternal */
/* [unique][uuid][object] */ 


EXTERN_C const IID IID_IVirtualDesktopManagerInternal;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("53F5CA0B-158F-4124-900C-057158060B27")
    IVirtualDesktopManagerInternal : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetCount( 
            /* [out] */ int *Count) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE MoveViewToDesktop( 
            /* [in] */ IApplicationView *view,
            /* [in] */ IVirtualDesktop *desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CanViewMoveDesktops( 
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *canMove) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetCurrentDesktop( 
            /* [out] */ IVirtualDesktop **desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetDesktops( 
            /* [out] */ IObjectArray **desktops) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetAdjacentDesktop( 
            /* [in] */ IVirtualDesktop *from,
            /* [v1_enum][in] */ VDMI_ADJACENT_DESKTOP_DIRECTION direction,
            /* [out] */ IVirtualDesktop **desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SwitchDesktop( 
            /* [in] */ IVirtualDesktop *desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SwitchDesktopAndMoveForegroundView( 
            /* [in] */ IVirtualDesktop *desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CreateDesktop( 
            /* [out] */ IVirtualDesktop **desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE MoveDesktop( 
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ int nIndex) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RemoveDesktop( 
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ IVirtualDesktop *fallback) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE FindDesktop( 
            /* [full][in] */ GUID *desktopid,
            /* [out] */ IVirtualDesktop **desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetDesktopSwitchIncludeExcludeViews( 
            /* [in] */ IVirtualDesktop *desktop,
            /* [out] */ IObjectArray **unknown1,
            /* [out] */ IObjectArray **unknown2) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetDesktopName( 
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ HSTRING *name) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetDesktopWallpaper( 
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ HSTRING *path) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE UpdateWallpaperPathForAllDesktops( 
            /* [in] */ HSTRING *path) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CopyDesktopState( 
            /* [in] */ IApplicationView *pView0,
            /* [in] */ IApplicationView *pView1) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CreateRemoteDesktop( 
            /* [in] */ HSTRING *path,
            /* [out] */ IVirtualDesktop **desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SwitchRemoteDesktop( 
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ int switchtype) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SwitchDesktopWithAnimation( 
            /* [in] */ IVirtualDesktop *desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetLastActiveDesktop( 
            /* [out] */ IVirtualDesktop **desktop) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE WaitForAnimationToComplete( void) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IVirtualDesktopManagerInternalVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IVirtualDesktopManagerInternal * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IVirtualDesktopManagerInternal * This);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, GetCount)
        HRESULT ( STDMETHODCALLTYPE *GetCount )( 
            IVirtualDesktopManagerInternal * This,
            /* [out] */ int *Count);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, MoveViewToDesktop)
        HRESULT ( STDMETHODCALLTYPE *MoveViewToDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IApplicationView *view,
            /* [in] */ IVirtualDesktop *desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, CanViewMoveDesktops)
        HRESULT ( STDMETHODCALLTYPE *CanViewMoveDesktops )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IApplicationView *view,
            /* [out] */ boolean *canMove);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, GetCurrentDesktop)
        HRESULT ( STDMETHODCALLTYPE *GetCurrentDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [out] */ IVirtualDesktop **desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, GetDesktops)
        HRESULT ( STDMETHODCALLTYPE *GetDesktops )( 
            IVirtualDesktopManagerInternal * This,
            /* [out] */ IObjectArray **desktops);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, GetAdjacentDesktop)
        HRESULT ( STDMETHODCALLTYPE *GetAdjacentDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *from,
            /* [v1_enum][in] */ VDMI_ADJACENT_DESKTOP_DIRECTION direction,
            /* [out] */ IVirtualDesktop **desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, SwitchDesktop)
        HRESULT ( STDMETHODCALLTYPE *SwitchDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, SwitchDesktopAndMoveForegroundView)
        HRESULT ( STDMETHODCALLTYPE *SwitchDesktopAndMoveForegroundView )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, CreateDesktop)
        HRESULT ( STDMETHODCALLTYPE *CreateDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [out] */ IVirtualDesktop **desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, MoveDesktop)
        HRESULT ( STDMETHODCALLTYPE *MoveDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ int nIndex);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, RemoveDesktop)
        HRESULT ( STDMETHODCALLTYPE *RemoveDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ IVirtualDesktop *fallback);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, FindDesktop)
        HRESULT ( STDMETHODCALLTYPE *FindDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [full][in] */ GUID *desktopid,
            /* [out] */ IVirtualDesktop **desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, GetDesktopSwitchIncludeExcludeViews)
        HRESULT ( STDMETHODCALLTYPE *GetDesktopSwitchIncludeExcludeViews )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop,
            /* [out] */ IObjectArray **unknown1,
            /* [out] */ IObjectArray **unknown2);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, SetDesktopName)
        HRESULT ( STDMETHODCALLTYPE *SetDesktopName )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ HSTRING *name);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, SetDesktopWallpaper)
        HRESULT ( STDMETHODCALLTYPE *SetDesktopWallpaper )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ HSTRING *path);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, UpdateWallpaperPathForAllDesktops)
        HRESULT ( STDMETHODCALLTYPE *UpdateWallpaperPathForAllDesktops )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ HSTRING *path);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, CopyDesktopState)
        HRESULT ( STDMETHODCALLTYPE *CopyDesktopState )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IApplicationView *pView0,
            /* [in] */ IApplicationView *pView1);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, CreateRemoteDesktop)
        HRESULT ( STDMETHODCALLTYPE *CreateRemoteDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ HSTRING *path,
            /* [out] */ IVirtualDesktop **desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, SwitchRemoteDesktop)
        HRESULT ( STDMETHODCALLTYPE *SwitchRemoteDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop,
            /* [in] */ int switchtype);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, SwitchDesktopWithAnimation)
        HRESULT ( STDMETHODCALLTYPE *SwitchDesktopWithAnimation )( 
            IVirtualDesktopManagerInternal * This,
            /* [in] */ IVirtualDesktop *desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, GetLastActiveDesktop)
        HRESULT ( STDMETHODCALLTYPE *GetLastActiveDesktop )( 
            IVirtualDesktopManagerInternal * This,
            /* [out] */ IVirtualDesktop **desktop);
        
        DECLSPEC_XFGVIRT(IVirtualDesktopManagerInternal, WaitForAnimationToComplete)
        HRESULT ( STDMETHODCALLTYPE *WaitForAnimationToComplete )( 
            IVirtualDesktopManagerInternal * This);
        
        END_INTERFACE
    } IVirtualDesktopManagerInternalVtbl;

    interface IVirtualDesktopManagerInternal
    {
        CONST_VTBL struct IVirtualDesktopManagerInternalVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IVirtualDesktopManagerInternal_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IVirtualDesktopManagerInternal_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IVirtualDesktopManagerInternal_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IVirtualDesktopManagerInternal_GetCount(This,Count)	\
    ( (This)->lpVtbl -> GetCount(This,Count) ) 

#define IVirtualDesktopManagerInternal_MoveViewToDesktop(This,view,desktop)	\
    ( (This)->lpVtbl -> MoveViewToDesktop(This,view,desktop) ) 

#define IVirtualDesktopManagerInternal_CanViewMoveDesktops(This,view,canMove)	\
    ( (This)->lpVtbl -> CanViewMoveDesktops(This,view,canMove) ) 

#define IVirtualDesktopManagerInternal_GetCurrentDesktop(This,desktop)	\
    ( (This)->lpVtbl -> GetCurrentDesktop(This,desktop) ) 

#define IVirtualDesktopManagerInternal_GetDesktops(This,desktops)	\
    ( (This)->lpVtbl -> GetDesktops(This,desktops) ) 

#define IVirtualDesktopManagerInternal_GetAdjacentDesktop(This,from,direction,desktop)	\
    ( (This)->lpVtbl -> GetAdjacentDesktop(This,from,direction,desktop) ) 

#define IVirtualDesktopManagerInternal_SwitchDesktop(This,desktop)	\
    ( (This)->lpVtbl -> SwitchDesktop(This,desktop) ) 

#define IVirtualDesktopManagerInternal_SwitchDesktopAndMoveForegroundView(This,desktop)	\
    ( (This)->lpVtbl -> SwitchDesktopAndMoveForegroundView(This,desktop) ) 

#define IVirtualDesktopManagerInternal_CreateDesktop(This,desktop)	\
    ( (This)->lpVtbl -> CreateDesktop(This,desktop) ) 

#define IVirtualDesktopManagerInternal_MoveDesktop(This,desktop,nIndex)	\
    ( (This)->lpVtbl -> MoveDesktop(This,desktop,nIndex) ) 

#define IVirtualDesktopManagerInternal_RemoveDesktop(This,desktop,fallback)	\
    ( (This)->lpVtbl -> RemoveDesktop(This,desktop,fallback) ) 

#define IVirtualDesktopManagerInternal_FindDesktop(This,desktopid,desktop)	\
    ( (This)->lpVtbl -> FindDesktop(This,desktopid,desktop) ) 

#define IVirtualDesktopManagerInternal_GetDesktopSwitchIncludeExcludeViews(This,desktop,unknown1,unknown2)	\
    ( (This)->lpVtbl -> GetDesktopSwitchIncludeExcludeViews(This,desktop,unknown1,unknown2) ) 

#define IVirtualDesktopManagerInternal_SetDesktopName(This,desktop,name)	\
    ( (This)->lpVtbl -> SetDesktopName(This,desktop,name) ) 

#define IVirtualDesktopManagerInternal_SetDesktopWallpaper(This,desktop,path)	\
    ( (This)->lpVtbl -> SetDesktopWallpaper(This,desktop,path) ) 

#define IVirtualDesktopManagerInternal_UpdateWallpaperPathForAllDesktops(This,path)	\
    ( (This)->lpVtbl -> UpdateWallpaperPathForAllDesktops(This,path) ) 

#define IVirtualDesktopManagerInternal_CopyDesktopState(This,pView0,pView1)	\
    ( (This)->lpVtbl -> CopyDesktopState(This,pView0,pView1) ) 

#define IVirtualDesktopManagerInternal_CreateRemoteDesktop(This,path,desktop)	\
    ( (This)->lpVtbl -> CreateRemoteDesktop(This,path,desktop) ) 

#define IVirtualDesktopManagerInternal_SwitchRemoteDesktop(This,desktop,switchtype)	\
    ( (This)->lpVtbl -> SwitchRemoteDesktop(This,desktop,switchtype) ) 

#define IVirtualDesktopManagerInternal_SwitchDesktopWithAnimation(This,desktop)	\
    ( (This)->lpVtbl -> SwitchDesktopWithAnimation(This,desktop) ) 

#define IVirtualDesktopManagerInternal_GetLastActiveDesktop(This,desktop)	\
    ( (This)->lpVtbl -> GetLastActiveDesktop(This,desktop) ) 

#define IVirtualDesktopManagerInternal_WaitForAnimationToComplete(This)	\
    ( (This)->lpVtbl -> WaitForAnimationToComplete(This) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IVirtualDesktopManagerInternal_INTERFACE_DEFINED__ */


/* interface __MIDL_itf_VirtualDesktop_0000_0011 */
/* [local] */ 

#pragma endregion


extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0011_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_VirtualDesktop_0000_0011_v0_0_s_ifspec;

/* Additional Prototypes for ALL interfaces */

unsigned long             __RPC_USER  HSTRING_UserSize(     unsigned long *, unsigned long            , HSTRING * ); 
unsigned char * __RPC_USER  HSTRING_UserMarshal(  unsigned long *, unsigned char *, HSTRING * ); 
unsigned char * __RPC_USER  HSTRING_UserUnmarshal(unsigned long *, unsigned char *, HSTRING * ); 
void                      __RPC_USER  HSTRING_UserFree(     unsigned long *, HSTRING * ); 

unsigned long             __RPC_USER  HWND_UserSize(     unsigned long *, unsigned long            , HWND * ); 
unsigned char * __RPC_USER  HWND_UserMarshal(  unsigned long *, unsigned char *, HWND * ); 
unsigned char * __RPC_USER  HWND_UserUnmarshal(unsigned long *, unsigned char *, HWND * ); 
void                      __RPC_USER  HWND_UserFree(     unsigned long *, HWND * ); 

unsigned long             __RPC_USER  HSTRING_UserSize64(     unsigned long *, unsigned long            , HSTRING * ); 
unsigned char * __RPC_USER  HSTRING_UserMarshal64(  unsigned long *, unsigned char *, HSTRING * ); 
unsigned char * __RPC_USER  HSTRING_UserUnmarshal64(unsigned long *, unsigned char *, HSTRING * ); 
void                      __RPC_USER  HSTRING_UserFree64(     unsigned long *, HSTRING * ); 

unsigned long             __RPC_USER  HWND_UserSize64(     unsigned long *, unsigned long            , HWND * ); 
unsigned char * __RPC_USER  HWND_UserMarshal64(  unsigned long *, unsigned char *, HWND * ); 
unsigned char * __RPC_USER  HWND_UserUnmarshal64(unsigned long *, unsigned char *, HWND * ); 
void                      __RPC_USER  HWND_UserFree64(     unsigned long *, HWND * ); 

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


