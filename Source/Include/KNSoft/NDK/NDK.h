/*
 * KNSoft.NDK (https://github.com/KNSoft/KNSoft.NDK)
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MIT license.
 */

#pragma once

#include "NT/NT.h"

/* Windows.h and winioctl.h */

#define _WINSOCKAPI_ // Use WinSock2.h
#include <Windows.h>

#include <initguid.h>
#include <winioctl.h>

#include "Win32/WinBase.h"
#include "Win32/WinUser.h"
#include "Win32/WinRT/HString/HString.h"
#include "Win32/CommCtrl.h"
#include "Win32/UxTheme.h"
#include "NT/Afd.h"

/* APIs */

#include "Win32/Ntdll/Ntdll.h"
#include "Win32/Kernel32/Kernel32.h"
#include "Win32/KernelBase.h"
#include "Win32/SecHost.h"
#include "Win32/User32/User32.h"
#include "Win32/UserMgrCli.h"
#include "Win32/WinSta.h"
#include "Win32/AdvAPI32.h"
#include "Win32/ComBase/ComBase.h"
#include "Win32/CBS/CbsApi.h"
#include "Win32/CBS/CbsCore.h"
#include "Win32/FVE/FveApi.h"
#include "Win32/ShObjIdl/ShObjIdl_core.h"
#include "Win32/msidle/msidle.h"
#include "Win32/msftedit.h"

/* Enable extensions */

#ifndef _KNSOFT_NDK_NO_EXTENSION
#include "NDK.Ext.h"
#endif

/* Sanity checks */
_STATIC_ASSERT(__alignof(LARGE_INTEGER) == 8);
_STATIC_ASSERT(__alignof(PROCESS_CYCLE_TIME_INFORMATION) == 8);
