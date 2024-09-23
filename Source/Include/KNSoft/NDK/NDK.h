﻿/*
 * KNSoft.NDK (https://github.com/KNSoft/KNSoft.NDK)
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MIT license.
 */

#pragma once

#include "NT/NT.h"

/* Windows.h */

#include <Windows.h>
#include "Win32/Def/WinUser.h"
#include "Win32/Def/CommCtrl.h"

/* APIs */

#include "Win32/API/Kernel32.h"
#include "Win32/API/Ntdll.h"
#include "Win32/API/SecHost.h"
#include "Win32/API/User32.h"
#include "Win32/API/UserMgrCli.h"
#include "Win32/API/WinSta.h"

/* Additional headers */

#include <intrin.h>
#include <suppress.h>

/* Enable extensions */

#ifndef _KNSOFT_NDK_NO_EXTENSION
#include "Package/Extension.h"
#endif
