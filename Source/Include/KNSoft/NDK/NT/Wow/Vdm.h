#pragma once

#include "../MinDef.h"

EXTERN_C_START

/* phnt */

/**
 * The VDMSERVICECLASS enumeration identifies the Virtual DOS Machine (VDM) service requested through NtVdmControl.
 */
typedef enum _VDMSERVICECLASS
{
    VdmStartExecution,
    VdmQueueInterrupt,
    VdmDelayInterrupt,
    VdmInitialize,
    VdmFeatures,
    VdmSetInt21Handler,
    VdmQueryDir,
    VdmPrinterDirectIoOpen,
    VdmPrinterDirectIoClose,
    VdmPrinterInitialize,
    VdmSetLdtEntries,
    VdmSetProcessLdtInfo,
    VdmAdlibEmulation,
    VdmPMCliControl,
    VdmQueryVdmProcess,
    VdmPreInitialize
} VDMSERVICECLASS, *PVDMSERVICECLASS;

/**
 * The NtVdmControl routine performs a control operation for the Virtual DOS Machine (VDM) subsystem.
 *
 * \param[in] Service The VDM service operation to perform.
 * \param[in, out] ServiceData Pointer to the service-specific data buffer.
 * \return NTSTATUS Successful or errant status.
 */
_Kernel_entry_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtVdmControl(
    _In_ VDMSERVICECLASS Service,
    _Inout_ PVOID ServiceData);

EXTERN_C_END
