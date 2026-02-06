

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


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



#ifdef __cplusplus
extern "C"{
#endif 


#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef struct _IID
{
    unsigned long x;
    unsigned short s1;
    unsigned short s2;
    unsigned char  c[8];
} IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        EXTERN_C __declspec(selectany) const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif // !_MIDL_USE_GUIDDEF_

MIDL_DEFINE_GUID(IID, IID_IApplicationView,0x372E1D3B,0x38D3,0x42E4,0xA1,0x5B,0x8A,0xB2,0xB1,0x78,0xF5,0x13);


MIDL_DEFINE_GUID(IID, IID_IApplicationView_17134,0x871F602A,0x2B58,0x42B4,0x8C,0x4B,0x6C,0x43,0xD6,0x42,0xC0,0x6F);


MIDL_DEFINE_GUID(IID, IID_IApplicationView_0,0x9AC0B5C8,0x1484,0x4C5B,0x95,0x33,0x41,0x34,0xA0,0xF9,0x7C,0xEA);


MIDL_DEFINE_GUID(IID, IID_IApplicationViewCollection,0x1841C6D7,0x4F9D,0x42C0,0xAF,0x41,0x87,0x47,0x53,0x8F,0x10,0xE5);


MIDL_DEFINE_GUID(IID, IID_IApplicationViewCollection_0,0x2C08ADF0,0xA386,0x4B35,0x92,0x50,0x0F,0xE1,0x83,0x47,0x6F,0xCC);


MIDL_DEFINE_GUID(IID, IID_IVirtualDesktop,0x3F07F4BE,0xB107,0x441A,0xAF,0x0F,0x39,0xD8,0x25,0x29,0x07,0x2C);


MIDL_DEFINE_GUID(IID, IID_IVirtualDesktop_22000,0x536D3495,0xB208,0x4CC9,0xAE,0x26,0xDE,0x81,0x11,0x27,0x5B,0xF8);


MIDL_DEFINE_GUID(IID, IID_IVirtualDesktop_20348,0x62FDF88B,0x11CA,0x4AFB,0x8B,0xD8,0x22,0x96,0xDF,0xAE,0x49,0xE2);


MIDL_DEFINE_GUID(IID, IID_IVirtualDesktop_0,0xFF72FFDD,0xBE7E,0x43FC,0x9C,0x03,0xAD,0x81,0x68,0x1E,0x88,0xE4);


MIDL_DEFINE_GUID(IID, IID_IVirtualDesktopPinnedApps,0x4CE81583,0x1E4C,0x4632,0xA6,0x21,0x07,0xA5,0x35,0x43,0x14,0x8F);


MIDL_DEFINE_GUID(IID, IID_IVirtualDesktopManagerInternal,0x53F5CA0B,0x158F,0x4124,0x90,0x0C,0x05,0x71,0x58,0x06,0x0B,0x27);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



