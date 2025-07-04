IFDEF _M_X64
include ksamd64.inc
; ELSEIFDEF _M_IX86
; include ks386.inc ; Removed since Windows SDK 10.0.18362.0
ENDIF

include CallConv.Inc

include NDK.mac

IFDEF _WIN64
SIZE_T equ <QWORD>
ELSE
SIZE_T equ <DWORD>
ENDIF

MAXBYTE  equ 0FFh
MAXWORD  equ 0FFFFh
MAXDWORD equ 0FFFFFFFFh
MAXQWORD equ 0FFFFFFFFFFFFFFFFh
