#pragma once

#include "../MinDef.h"
#include "Process/EnvironmentBlock.h"

EXTERN_C_START

/* ntddk.h */
/**
 * The RtlGetCallersAddress routine retrieves the return addresses of the caller and caller's caller.
 *
 * \param CallersAddress A pointer that receives the caller's return address.
 * \param CallersCaller A pointer that receives the return address of the caller's caller.
 * \remarks This routine is deprecated. Callers should prefer the intrinsic _ReturnAddress.
 */
NTSYSAPI
VOID
NTAPI
RtlGetCallersAddress(
    _Out_ PVOID* CallersAddress,
    _Out_ PVOID* CallersCaller);

/* phnt */

/**
 * The RtlPushFrame routine pushes an active frame onto the current thread's active frame stack.
 *
 * \param Frame A pointer to the TEB_ACTIVE_FRAME to push.
 */
NTSYSAPI
VOID
NTAPI
RtlPushFrame(
    _In_ PTEB_ACTIVE_FRAME Frame);

/**
 * The RtlPopFrame routine pops an active frame from the current thread's active frame stack.
 *
 * \param Frame A pointer to the TEB_ACTIVE_FRAME to pop.
 */
NTSYSAPI
VOID
NTAPI
RtlPopFrame(
    _In_ PTEB_ACTIVE_FRAME Frame);

/**
 * The RtlGetFrame routine returns the topmost active frame on the current thread's active frame stack.
 *
 * \return PTEB_ACTIVE_FRAME A pointer to the current active frame, or `NULL` if the stack is empty.
 */
NTSYSAPI
PTEB_ACTIVE_FRAME
NTAPI
RtlGetFrame(VOID);

/* ntddk.h & phnt */

/**
 * Flags controlling RtlWalkFrameChain stack capture.
 */
#define RTL_WALK_USER_MODE_STACK 0x00000001
#define RTL_WALK_KERNEL_STACK 0x00000002
#define RTL_WALK_USER_KERNEL_STACK 0x00000003
#define RTL_WALK_VALID_FLAGS 0x00000006

#define RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT 8

/**
 * The RtlWalkFrameChain routine captures the current call stack as an array of return addresses.
 *
 * \param Callers A buffer that receives the captured return addresses.
 * \param Count The maximum number of frames to capture.
 * \param Flags Flags controlling the walk, including the number of leading frames to skip.
 * \return The number of frames captured.
 */
NTSYSAPI
ULONG
NTAPI
RtlWalkFrameChain(
    _Out_writes_(Count - (Flags >> RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT)) PVOID *Callers,
    _In_ ULONG Count,
    _In_ ULONG Flags);

EXTERN_C_END
