#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* wdm.h & phnt */

/**
 * The ALTERNATIVE_ARCHITECTURE_TYPE enumeration specifies the hardware
 * architecture variant used by the system.
 *
 * \remarks NEC98x86 represents the NEC PC-98 architecture,
 * supported only on very early Windows releases.
 */
typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign,                 // None == 0 == standard design
    NEC98x86,                       // NEC PC98xx series on X86
    EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

/**
 * PROCESSOR_FEATURE_MAX defines the maximum number of processor feature flags
 * that may be reported by the system.
 */
#define PROCESSOR_FEATURE_MAX 64

EXTERN_C_END
