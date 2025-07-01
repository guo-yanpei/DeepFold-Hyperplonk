// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/encryptionparams.h"
#include "seal/polyarray.h"
#include "seal/publickey.h"
#include "seal/randomgen.h"
#include "seal/secretkey.h"
#include <cstdint>
#include <optional>

namespace seal
{
    namespace util
    {
        /**
        Generate a uniform ternary polynomial and store in RNS representation.

        @param[in] prng A uniform random generator
        @param[in] parms EncryptionParameters used to parameterize an RNS polynomial
        @param[out] destination Allocated space to store a random polynomial
        */
        void sample_poly_ternary(
            std::shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms,
            std::uint64_t *destination);

        /**
        Generate a polynomial from a normal distribution and store in RNS representation.

        @param[in] prng A uniform random generator
        @param[in] parms EncryptionParameters used to parameterize an RNS polynomial
        @param[out] destination Allocated space to store a random polynomial
        */
        void sample_poly_normal(
            std::shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms,
            std::uint64_t *destination);

        /**
        Generate a polynomial from a centered binomial distribution and store in RNS representation.

        @param[in] prng A uniform random generator.
        @param[in] parms EncryptionParameters used to parameterize an RNS polynomial
        @param[out] destination Allocated space to store a random polynomial
        */
        void sample_poly_cbd(
            std::shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms,
            std::uint64_t *destination);

        /**
        Generate a uniformly random polynomial and store in RNS representation.

        @param[in] prng A uniform random generator
        @param[in] parms EncryptionParameters used to parameterize an RNS polynomial
        @param[out] destination Allocated space to store a random polynomial
        */
        void sample_poly_uniform(
            std::shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms,
            std::uint64_t *destination);

        /**
        Generate a uniformly random polynomial and store in RNS representation.
        This implementation corresponds to Microsoft SEAL 3.4 and earlier.

        @param[in] prng A uniform random generator
        @param[in] parms EncryptionParameters used to parameterize an RNS polynomial
        @param[out] destination Allocated space to store a random polynomial
        */
        void sample_poly_uniform_seal_3_4(
            std::shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms,
            std::uint64_t *destination);

        /**
        Generate a uniformly random polynomial and store in RNS representation.
        This implementation corresponds to Microsoft SEAL 3.5 and earlier.

        @param[in] prng A uniform random generator
        @param[in] parms EncryptionParameters used to parameterize an RNS polynomial
        @param[out] destination Allocated space to store a random polynomial
        */
        void sample_poly_uniform_seal_3_5(
            std::shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms,
            std::uint64_t *destination);

        /**
        Create an encryption of zero with a public key and store in a ciphertext.

        @param[in] public_key The public key used for encryption
        @param[in] context The SEALContext containing a chain of ContextData
        @param[in] parms_id Indicates the level of encryption
        @param[in] is_ntt_form If true, store ciphertext in NTT form
        @param[in] export_components Whether to export the ciphertext components (u, e_i)
        @param[out] destination The output ciphertext - an encryption of zero
        @param[out] u The u component.
        @param[out] e The e component.
        @param[in] (Optional) Set seed for a deterministic encryption. NOTE:
        while one can provide this parameter, it is currently disabled in the
        encryption function. If you want to provide a seed, you will need to
        uncomment code in this function's definition.
        */
        void encrypt_zero_asymmetric(
            const PublicKey &public_key, 
            const SEALContext &context, 
            parms_id_type parms_id, 
            bool is_ntt_form,
            bool export_components,
            Ciphertext &destination,
            PolynomialArray &u_destination,
            PolynomialArray &e_destination,
            std::optional<prng_seed_type> seed = std::nullopt
        );

        /**
        Create an encryption of zero with a secret key and store in a ciphertext.

        @param[out] destination The output ciphertext - an encryption of zero
        @param[out] e The e component.
        @param[in] secret_key The secret key used for encryption
        @param[in] context The SEALContext containing a chain of ContextData
        @param[in] parms_id Indicates the level of encryption
        @param[in] is_ntt_form If true, store ciphertext in NTT form
        @param[in] save_seed If true, the second component of ciphertext is
        replaced with the random seed used to sample this component
        @param[in] export_components Whether to export the ciphertext noise component (e_i)
        @param[in] (Optional) Set seed for a deterministic encryption. NOTE:
        while one can provide this parameter, it is currently disabled in the
        encryption function. If you want to provide a seed, you will need to
        uncomment code in this function's definition.
        */
        void encrypt_zero_symmetric(
            const SecretKey &secret_key, 
            const SEALContext &context, 
            parms_id_type parms_id, 
            bool is_ntt_form,
            bool save_seed, 
            bool export_components,
            Ciphertext &destination,
            PolynomialArray &e_destination,
            std::optional<prng_seed_type> seed = std::nullopt
        );
    } // namespace util
} // namespace seal
