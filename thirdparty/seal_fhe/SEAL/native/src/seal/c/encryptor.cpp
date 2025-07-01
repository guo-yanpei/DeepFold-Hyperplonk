// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/encryptor.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/encryptor.h"

#include <optional>

using namespace std;
using namespace seal;
using namespace seal::c;

// Enables access to private members of seal::Encryptor.
using ph = struct seal::Encryptor::EncryptorPrivateHelper
{
    static void encrypt_symmetric_internal(
        Encryptor *encryptor, const Plaintext &plain, bool save_seed, Ciphertext &destination, MemoryPoolHandle pool)
    {
        encryptor->encrypt_internal(plain, false, save_seed, destination, pool);
    }

    static void encrypt_zero_symmetric_internal(
        Encryptor *encryptor, parms_id_type parms_id, bool save_seed, Ciphertext &destination, MemoryPoolHandle pool)
    {
        encryptor->encrypt_zero_internal(parms_id, false, save_seed, destination, pool);
    }

    static void encrypt_zero_symmetric_internal(
        Encryptor *encryptor, bool save_seed, Ciphertext &destination, MemoryPoolHandle pool)
    {
        encryptor->encrypt_zero_internal(encryptor->context_.first_parms_id(), false, save_seed, destination, pool);
    }
};

SEAL_C_FUNC Encryptor_Create(void *context, void *public_key, void *secret_key, void **encryptor)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    PublicKey *pkey = FromVoid<PublicKey>(public_key);
    SecretKey *skey = FromVoid<SecretKey>(secret_key);
    IfNullRet(encryptor, E_POINTER);
    if (nullptr == pkey && nullptr == skey)
    {
        return E_POINTER;
    }

    try
    {
        Encryptor *enc;
        if (nullptr != pkey)
        {
            enc = new Encryptor(*ctx, *pkey);
            if (nullptr != skey)
            {
                enc->set_secret_key(*skey);
            }
        }
        else
        {
            enc = new Encryptor(*ctx, *skey);
        }
        *encryptor = enc;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Encryptor_SetPublicKey(void *thisptr, void *public_key)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    PublicKey *pkey = FromVoid<PublicKey>(public_key);
    IfNullRet(pkey, E_POINTER);

    try
    {
        encryptor->set_public_key(*pkey);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Encryptor_SetSecretKey(void *thisptr, void *secret_key)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    SecretKey *skey = FromVoid<SecretKey>(secret_key);
    IfNullRet(skey, E_POINTER);

    try
    {
        encryptor->set_secret_key(*skey);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Encryptor_Encrypt(void *thisptr, void *plaintext, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    try
    {
        encryptor->encrypt(*plain, *cipher, *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}


SEAL_C_FUNC Encryptor_EncryptReturnComponents(
    void *thisptr, 
    void *plaintext, 
    bool disable_special_modulus, 
    void *destination, 
    void *u_destination, 
    void *e_destination, 
    void *remainder_destination,
    void *pool_handle) 
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    PolynomialArray *u_dest = FromVoid<PolynomialArray>(u_destination);
    IfNullRet(u_dest, E_POINTER);
    PolynomialArray *e_dest = FromVoid<PolynomialArray>(e_destination);
    IfNullRet(e_dest, E_POINTER);
    Plaintext *r_dest = FromVoid<Plaintext>(remainder_destination);
    IfNullRet(r_dest, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    try
    {
        encryptor->encrypt(
            *plain, 
            disable_special_modulus, 
            *cipher, 
            *u_dest, 
            *e_dest, 
            *r_dest, 
            {}, 
            *pool
        );
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_EncryptReturnComponentsSetSeed(
    void *thisptr,
    void *plaintext,
    bool disable_special_modulus,
    void *destination,
    void *u_destination,
    void *e_destination,
    void *remainder_destination,
    void *seed,
    void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    PolynomialArray *u_dest = FromVoid<PolynomialArray>(u_destination);
    IfNullRet(u_dest, E_POINTER);
    PolynomialArray *e_dest = FromVoid<PolynomialArray>(e_destination);
    IfNullRet(e_dest, E_POINTER);
    Plaintext *r_dest = FromVoid<Plaintext>(remainder_destination);
    IfNullRet(r_dest, E_POINTER);
    std::array<std::uint64_t, prng_seed_uint64_count> *seed_array = FromVoid<std::array<std::uint64_t, prng_seed_uint64_count>>(seed);
    IfNullRet(seed_array, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    auto seed_arr = std::optional<std::array<std::uint64_t, prng_seed_uint64_count>>{*seed_array};

    try
    {
        encryptor->encrypt(
            *plain, 
            disable_special_modulus, 
            *cipher, 
            *u_dest, 
            *e_dest,  
            *r_dest,
            seed_arr,
            *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_EncryptZero1(void *thisptr, uint64_t *parms_id, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        encryptor->encrypt_zero(parms, *cipher, *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_EncryptZero2(void *thisptr, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    try
    {
        encryptor->encrypt_zero(*cipher, *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_EncryptSymmetric(
    void *thisptr, void *plaintext, bool save_seed, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    try
    {
        ph::encrypt_symmetric_internal(encryptor, *plain, save_seed, *cipher, *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_EncryptSymmetricReturnComponents(
    void *thisptr, void *plaintext, void *destination, void *e_destination,
    void *remainder_destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    PolynomialArray *e_dest = FromVoid<PolynomialArray>(e_destination);
    IfNullRet(e_dest, E_POINTER);
    Plaintext *r_dest = FromVoid<Plaintext>(remainder_destination);
    IfNullRet(r_dest, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    try
    {
        encryptor->encrypt_symmetric(*plain, *cipher, *e_dest, *r_dest, {}, *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_EncryptSymmetricReturnComponentsSetSeed(
    void *thisptr, void *plaintext, void *destination, void *e_destination, void *remainder_destination, void *seed,
    void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    PolynomialArray *e_dest = FromVoid<PolynomialArray>(e_destination);
    IfNullRet(e_dest, E_POINTER);
    Plaintext *r_dest = FromVoid<Plaintext>(remainder_destination);
    IfNullRet(r_dest, E_POINTER);
    std::array<std::uint64_t, prng_seed_uint64_count> *seed_array =
        FromVoid<std::array<std::uint64_t, prng_seed_uint64_count>>(seed);
    IfNullRet(seed_array, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    auto seed_arr = std::optional<std::array<std::uint64_t, prng_seed_uint64_count>>{ *seed_array };

    try
    {
        encryptor->encrypt_symmetric(*plain, *cipher, *e_dest, *r_dest, seed_arr, *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_EncryptZeroSymmetric1(
    void *thisptr, uint64_t *parms_id, bool save_seed, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        ph::encrypt_zero_symmetric_internal(encryptor, parms, save_seed, *cipher, *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_EncryptZeroSymmetric2(void *thisptr, bool save_seed, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    try
    {
        ph::encrypt_zero_symmetric_internal(encryptor, save_seed, *cipher, *pool);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC Encryptor_Destroy(void *thisptr)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);

    delete encryptor;
    return S_OK;
}
