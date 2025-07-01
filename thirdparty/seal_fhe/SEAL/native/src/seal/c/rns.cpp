// SEALNet
#include "seal/c/rns.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/ciphertext.h"
#include "seal/util/rns.h"

using namespace std;
using namespace seal;
using namespace seal::c;
using namespace seal::util;

SEAL_C_FUNC RNSBase_Create(void *memoryPoolHandle, uint64_t coeffs_length, void **coeffs, void **rnsbase) {
    IfNullRet(coeffs, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);

    Modulus **coeff_array = reinterpret_cast<Modulus **>(coeffs);
    vector<Modulus> coefficients(coeffs_length);

    for (uint64_t i = 0; i < coeffs_length; i++)
    {
        coefficients[i] = *coeff_array[i];
    }

    try
    {
        RNSBase *base = new RNSBase(coefficients, *handle);
        *rnsbase = base;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }


}

SEAL_C_FUNC RNSBase_DecomposeArray(void *thisptr, uint64_t *value, uint64_t count, void *memoryPoolHandle) {
    RNSBase *rnsbase = FromVoid<RNSBase>(thisptr);
    IfNullRet(rnsbase, E_POINTER);

    IfNullRet(value, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);

    rnsbase->decompose_array(value, util::safe_cast<size_t>(count), *handle);
    return S_OK;
}

SEAL_C_FUNC RNSBase_ComposeArray(void *thisptr, uint64_t *value, uint64_t count, void *memoryPoolHandle) {
    RNSBase *rnsbase = FromVoid<RNSBase>(thisptr);
    IfNullRet(rnsbase, E_POINTER);

    IfNullRet(value, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);

    rnsbase->compose_array(value, util::safe_cast<size_t>(count), *handle);
    return S_OK;
}

SEAL_C_FUNC RNSBase_Destroy(void *thisptr) {
    RNSBase *rnsbase = FromVoid<RNSBase>(thisptr);
    IfNullRet(rnsbase, E_POINTER);

    delete rnsbase;
    return S_OK;
}