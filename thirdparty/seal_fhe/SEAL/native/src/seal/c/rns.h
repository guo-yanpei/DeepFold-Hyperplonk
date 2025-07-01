#pragma once

#include "seal/c/defines.h"
#include <stdint.h>

SEAL_C_FUNC RNSBase_Create(void *memoryPoolHandle, uint64_t coeff_length, void **coeffs, void **rnsbase);

SEAL_C_FUNC RNSBase_Destroy(void *thisptr);

SEAL_C_FUNC RNSBase_DecomposeArray(void *thisptr, uint64_t *value, uint64_t count, void *memoryPoolHandle);

SEAL_C_FUNC RNSBase_ComposeArray(void *thisptr, uint64_t *value, uint64_t count, void *memoryPoolHandle);