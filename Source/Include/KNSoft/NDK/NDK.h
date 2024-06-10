/*
 * KNSoft.NDK (https://github.com/KNSoft/KNSoft.NDK)
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MPL-2.0 license.
 */

#pragma once

#include "NT/NT.h"

/* Windows.h */

#include <Windows.h>
#include "WinDef/Addendum/WinUser.h"
#include "WinDef/Addendum/winsta.h"

/* APIs */

#include "WinDef/API/Ntdll.h"
#include "WinDef/API/Kernel32.h"
#include "WinDef/API/User32.h"
#include "WinDef/API/WinSta.h"

/* Additional headers */

#include <intrin.h>
#include <suppress.h>

/* Enable extensions */

#ifndef _KNSOFT_NDK_NO_EXTENSION
#include "Extension/Extension.h"
#endif

#ifndef _KNSOFT_NDK_NO_EXTENSION_MSTOOLCHAIN
#include "Extension/MSToolChain.h"
#endif
