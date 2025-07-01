// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/batchencoder.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(DecryptorTest, InvariantNoiseAndBudget)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(1 << 6);
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));
        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk, keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;

        encryptor.encrypt_zero(ct);
        
        auto invariant_noise = decryptor.invariant_noise(ct);
        auto invariant_noise_budget = decryptor.invariant_noise_budget(ct);

        auto calculated_noise_budget = floor(-log2(2. * invariant_noise));

        ASSERT_DOUBLE_EQ(calculated_noise_budget, static_cast<double>(invariant_noise_budget));
    }

        TEST(DecryptorTest, CanGetNoise)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        size_t poly_degree = 8192;
        parms.set_plain_modulus(plain_modulus);
        parms.set_poly_modulus_degree(poly_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree));
        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk, keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext ct;
        Plaintext pt;
        Ciphertext noise;

        encryptor.encrypt_zero(ct);

        auto invariant_noise = decryptor.invariant_noise(ct);

        auto context_data = context.get_context_data(ct.parms_id());
        auto &coeff_modulus = context_data->parms().coeff_modulus();

        double total_coeff = 1.0;

        for (auto coeff_mod : coeff_modulus) {
            total_coeff *= static_cast<double>(coeff_mod.value());
        }

        auto variant_noise = invariant_noise * total_coeff;

        decryptor.decrypt_and_extract_noise(ct, pt, noise);

        ASSERT_EQ(1, pt.coeff_count());
        ASSERT_EQ(0, pt[0]);

        ASSERT_EQ(2, noise.size());
        ASSERT_EQ(poly_degree, noise.poly_modulus_degree());
        ASSERT_EQ(ct.coeff_modulus_size(), noise.coeff_modulus_size());

        auto coeff_count = ct.coeff_modulus_size();

        util::StrideIter<const uint64_t*> wide_noise_poly(noise.data(), coeff_count);
        
        util::MemoryPool& pool = MemoryManager::GetPool();

        auto modulus_neg_threshold(allocate_uint(coeff_count, pool));
        util::half_round_up_uint(context_data->total_coeff_modulus(), coeff_count, modulus_neg_threshold.get());

        auto current_val(allocate_uint(coeff_count, pool));
        util::set_zero_uint(coeff_count, current_val.get());

        // Iterate over each coefficient in the noise polynomial and
        // assert it's less than or equal than the variant noise.
        SEAL_ITERATE(wide_noise_poly, noise.poly_modulus_degree(), [&](auto I) {
            if (is_greater_than_or_equal_uint(I, modulus_neg_threshold.get(), coeff_count))
            {
                util::sub_uint(context_data->total_coeff_modulus(), I, coeff_count, current_val.get());
            }
            else
            {
                util::set_uint(I, coeff_count, current_val.get());
            }

            double cur_noise = 0.0;

            for (size_t i = 0; i < coeff_count; i++) {
                auto power = static_cast<double>(sizeof(uint64_t) * 8 * i);
                auto word = static_cast<double>(current_val.get()[i]);
                cur_noise += word * exp2(power);
            }

            ASSERT_LE(cur_noise, variant_noise);
        });

    }
}