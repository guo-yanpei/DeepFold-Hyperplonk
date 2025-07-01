#pragma once

#include "seal/c/defines.h"
#include <stdint.h>

SEAL_C_FUNC PolynomialArray_Create(void *memoryPoolHandle, void **poly_array);

SEAL_C_FUNC PolynomialArray_CreateFromCiphertext(void *memoryPoolHandle, void *context, void *ciphertext, void **poly_array);

SEAL_C_FUNC PolynomialArray_CreateFromPublicKey(void *memoryPoolHandle, void *context, void *public_key, void **poly_array);

SEAL_C_FUNC PolynomialArray_CreateFromSecretKey(void *memoryPoolHandle, void *context, void *secret_key, void **poly_array);

SEAL_C_FUNC PolynomialArray_Copy(void *copy, void **poly_array);

SEAL_C_FUNC PolynomialArray_Destroy(void *thisptr);

SEAL_C_FUNC PolynomialArray_IsReserved(void *thisptr, bool *is_reserved);

SEAL_C_FUNC PolynomialArray_IsRns(void *thisptr, bool *is_rns);

SEAL_C_FUNC PolynomialArray_IsMultiprecision(void *thisptr, bool *is_multiprecision);

// SEAL_C_FUNC PolynomialArray_InsertPolynomial(void *thisptr, uint64_t poly_index, uint64_t *array);

SEAL_C_FUNC PolynomialArray_ToRns(void *thisptr);

SEAL_C_FUNC PolynomialArray_ToMultiprecision(void *thisptr);

SEAL_C_FUNC PolynomialArray_GetPolynomial(void *thisptr, uint64_t poly_index, uint64_t *data);

SEAL_C_FUNC PolynomialArray_ExportSize(void *thisptr, uint64_t *size);

SEAL_C_FUNC PolynomialArray_PerformExport(void *thisptr, uint64_t *data);

SEAL_C_FUNC PolynomialArray_PolySize(void *thisptr, uint64_t *size);

SEAL_C_FUNC PolynomialArray_PolyModulusDegree(void *thisptr, uint64_t *size);

SEAL_C_FUNC PolynomialArray_CoeffModulusSize(void *thisptr, uint64_t *size);

SEAL_C_FUNC PolynomialArray_Drop(void *thisptr, void **poly_array);