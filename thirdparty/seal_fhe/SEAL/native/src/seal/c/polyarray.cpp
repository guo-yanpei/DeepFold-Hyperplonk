// SEALNet
#include "seal/c/rns.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/polyarray.h"
#include "seal/c/polyarray.h"

using namespace std;
using namespace seal;
using namespace seal::c;
using namespace seal::util;



SEAL_C_FUNC PolynomialArray_Create(void *memoryPoolHandle, void **poly_array)
{
    IfNullRet(poly_array, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);

    try
    {
        PolynomialArray *array = new PolynomialArray(*handle);
        *poly_array = array;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC PolynomialArray_CreateFromCiphertext(void *memoryPoolHandle, void *context, void *ciphertext, void **poly_array)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);

    const Ciphertext *cipher = FromVoid<Ciphertext>(ciphertext);
    IfNullRet(cipher, E_POINTER);

    IfNullRet(poly_array, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);

    try
    {
        PolynomialArray *array = new PolynomialArray(*ctx, *cipher, *handle);
        *poly_array = array;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC PolynomialArray_CreateFromPublicKey(void *memoryPoolHandle, void *context, void *public_key, void **poly_array)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);

    const PublicKey *pk = FromVoid<PublicKey>(public_key);
    IfNullRet(pk, E_POINTER);

    IfNullRet(poly_array, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);

    try
    {
        PolynomialArray *array = new PolynomialArray(*ctx, *pk, *handle);
        *poly_array = array;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC PolynomialArray_CreateFromSecretKey(
    void *memoryPoolHandle, void *context, void *secret_key, void **poly_array)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);

    const SecretKey *sk = FromVoid<SecretKey>(secret_key);
    IfNullRet(sk, E_POINTER);

    IfNullRet(poly_array, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);

    try
    {
        PolynomialArray *array = new PolynomialArray(*ctx, *sk, *handle);
        *poly_array = array;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC PolynomialArray_Copy(void *copy, void **poly_array)
{
    PolynomialArray *copyptr = FromVoid<PolynomialArray>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(poly_array, E_POINTER);

    PolynomialArray *pa = new PolynomialArray(*copyptr);
    *poly_array = pa;
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_Destroy(void *thisptr)
{
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);

    delete poly_array;
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_IsReserved(void *thisptr, bool *is_reserved)
{
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(is_reserved, E_POINTER);

    *is_reserved = poly_array->is_reserved();
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_IsRns(void *thisptr, bool *is_rns)
{
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(is_rns, E_POINTER);

    *is_rns = poly_array->is_rns();
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_IsMultiprecision(void *thisptr, bool *is_multiprecision)
{
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(is_multiprecision, E_POINTER);

    *is_multiprecision = poly_array->is_multiprecision();
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_ToRns(void *thisptr) {
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);

    poly_array->to_rns();

    return S_OK;
}

SEAL_C_FUNC PolynomialArray_ToMultiprecision(void *thisptr) {
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);

    poly_array->to_multiprecision();

    return S_OK;

}

SEAL_C_FUNC PolynomialArray_GetPolynomial(void *thisptr, uint64_t poly_index, uint64_t *data){
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(data, E_POINTER);

    try
    {
        *data = *(*poly_array).get_polynomial(poly_index);
        return S_OK;
    }
    catch (const out_of_range &)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEAL_C_FUNC PolynomialArray_ExportSize(void *thisptr, uint64_t *size) {
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = poly_array->export_size();
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_PerformExport(void *thisptr, uint64_t *data) {
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(data, E_POINTER);

    poly_array->perform_export(data);
    return S_OK;
}


SEAL_C_FUNC PolynomialArray_PolySize(void *thisptr, uint64_t *size) {
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = poly_array->poly_size();
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_PolyModulusDegree(void *thisptr, uint64_t *size) {
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = poly_array->poly_modulus_degree();
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_CoeffModulusSize(void *thisptr, uint64_t *size) {
    PolynomialArray *poly_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(poly_array, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = poly_array->coeff_modulus_size();
    return S_OK;
}

SEAL_C_FUNC PolynomialArray_Drop(void *thisptr, void **poly_array)
{
    PolynomialArray *this_array = FromVoid<PolynomialArray>(thisptr);
    IfNullRet(this_array, E_POINTER);

    IfNullRet(poly_array, E_POINTER);
    try
    {
        PolynomialArray result = this_array->drop();

        // Move to the heap
        PolynomialArray *return_array = new PolynomialArray(result);
        *poly_array = return_array;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}