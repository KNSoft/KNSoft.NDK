#pragma once

#include "../../NT/MinDef.h"

#include <WinBase.h>

EXTERN_C_START

// private // ole32.dll
/**
 * The UpdateDCOMSettings routine updates the system Distributed COM (DCOM) settings and security configuration.
 */
WINBASEAPI
VOID
WINAPI
UpdateDCOMSettings(VOID);

EXTERN_C_END
