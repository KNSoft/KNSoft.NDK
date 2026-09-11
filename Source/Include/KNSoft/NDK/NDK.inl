/*
 * KNSoft.NDK (https://github.com/KNSoft/KNSoft.NDK) Inline implementations
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MIT license.
 */

#pragma once

#ifdef _KNSOFT_NDK_NO_EXTENSION
#errro("KNSoft.NDK: NDK.inl conflicts with _KNSOFT_NDK_NO_EXTENSION.")
#endif

#include "NDK.h"

#include "NT/NT.inl"
#include "Win32/Kernel32/Kernel32.inl"
#include "Win32/Shell32.inl"
#include "Win32/WinRT/HString.inl"
#include "Win32/msidle/msidle.inl"
