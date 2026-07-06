#pragma once

#include "MinDef.h"

#include <consoleapi.h>
#include <consoleapi2.h>
#include <consoleapi3.h>

EXTERN_C_START

#include "../3rdParty/terminal/dep/Console/ntcon.h"

#include "../3rdParty/terminal/dep/Console/condrv.h"
#include "../3rdParty/terminal/dep/Console/ConIoSrv.h"

#pragma push_macro("ReadConsole")
#ifdef ReadConsole
#undef ReadConsole
#endif
#pragma push_macro("WriteConsole")
#ifdef WriteConsole
#undef WriteConsole
#endif
#include "../3rdParty/terminal/dep/Console/conmsgl1.h"
#pragma pop_macro("ReadConsole")
#pragma pop_macro("WriteConsole")

#include "../3rdParty/terminal/dep/Console/conmsgl2.h"
#include "../3rdParty/terminal/dep/Console/conmsgl3.h"

EXTERN_C_END
