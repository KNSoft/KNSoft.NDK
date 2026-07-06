#pragma once

#include "MinDef.h"

EXTERN_C_START

#pragma region CSRSS

/* FIXME: from microsoft/terminal ntcsrmsg.h */
#define CSR_MAKE_API_NUMBER(DllIndex, ApiIndex) 0
typedef PVOID PCSR_API_MSG;
typedef PVOID PCSR_CAPTURE_HEADER;

/* From microsoft/terminal csrmsg.h */

typedef enum _USER_API_NUMBER {
    UserpEndTask,
} USER_API_NUMBER, *PUSER_API_NUMBER;

typedef struct _ENDTASKMSG {
    HANDLE ProcessId;
    ULONG ConsoleEventCode;
    ULONG ConsoleFlags;
} ENDTASKMSG, *PENDTASKMSG;

typedef struct _USER_API_MSG {
    union {
        ENDTASKMSG EndTask;
    } u;
} USER_API_MSG, *PUSER_API_MSG;

#pragma endregion

EXTERN_C_END
