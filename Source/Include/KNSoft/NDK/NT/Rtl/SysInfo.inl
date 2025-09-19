#pragma once

#include "../../NDK.h"

EXTERN_C_START

__inline
BOOLEAN
NTAPI
_Inline_RtlIsProcessorFeaturePresent(
    _In_ ULONG ProcessorFeature)
{
    return ProcessorFeature < PROCESSOR_FEATURE_MAX ?
        SharedUserData->ProcessorFeatures[ProcessorFeature] :
        FALSE;
}

EXTERN_C_END
