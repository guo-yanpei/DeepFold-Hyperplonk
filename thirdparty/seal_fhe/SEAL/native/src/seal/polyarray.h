#pragma once

#include "seal/context.h"
#include "seal/ciphertext.h"
#include "seal/memorymanager.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include <stdexcept>

using namespace seal::util;

namespace seal
{

        /**
        A class holding an RNS based polynomial array that can only be loaded
        with data once. This class keeps a copy of the coefficient modulus
        associated with the array so that it can be used to convert back and
        forth between RNS and multiprecision form.
        */
        class PolynomialArray
        {
            public:
                /**
                Creates an uninitialized PolynomialArray instance from a
                given pool. This is created so that a reference can be passed
                into a function and whatever polynomial array of interest can be
                converted into functions that return a polynomial array.
                */
                PolynomialArray(MemoryPoolHandle pool = MemoryManager::GetPool()):
                pool_(std::move(pool))
                {}

                /**
                Create a PolynomialArray from a ciphertext.
                */
                PolynomialArray(
                    const SEALContext &context, const Ciphertext &ciphertext, MemoryPoolHandle pool
                );

                /**
                Create a PolynomialArray from a public key. Note that the
                special modulus is dropped from this representation.
                */
                PolynomialArray(
                    const SEALContext &context, const PublicKey &public_key, MemoryPoolHandle pool
                );

                /**
                Create a PolynomialArray from a secret key.
                */
                PolynomialArray(
                    const SEALContext &context, const SecretKey &secret_key, MemoryPoolHandle pool
                );

                /**
                Creates a new ciphertext by copying a given one.

                @param[in] source The ciphertext to move from
                */
                PolynomialArray(const PolynomialArray &copy);

                /**
                Creates a new ciphertext by moving a given one.

                @param[in] source The ciphertext to move from
                */
                PolynomialArray(PolynomialArray &&source) = default;

                ~PolynomialArray()
                {
                    if (zero_on_destruction_) {
                        util::set_zero_uint(len_, data_.get());

                        // We also reset all the elements in the class to make
                        // the bits associated with a deallocated object look
                        // the same as a new object that is unreserved.
                        poly_size_ = 0;
                        coeff_size_ = 0;
                        coeff_modulus_size_ = 0;
                        poly_len_ = 0;
                        len_ = 0;
                        reserved_ = false;
                        zero_on_destruction_ = true;
                        is_rns_ = true;
                    }
                }

                /**
                Copies a given ciphertext to the current one.

                @param[in] assign The ciphertext to copy from
                */
                PolynomialArray &operator=(const PolynomialArray &assign);

                /**
                Reserve space for a specfic polynomial. This can only be called
                once; further calls with throw a logic error indicating that the
                array has already been reserved.
                */
                void reserve(
                    std::size_t poly_size, std::size_t coeff_size, const std::vector<Modulus> &rnsbase
                );

                /**
                Whether or not the polynomial array has been loaded with data.
                */
                bool is_reserved() {
                    return reserved_;
                }

                /**
                A polynomial array can either be represented in RNS form, or in
                multi-precision form. Returns whether it is currently in RNS form.
                */
                bool is_rns() {
                    return is_rns_;
                }

                /**
                A polynomial array can either be represented in RNS form, or in
                multi-precision form. Returns whether it is currently in
                multi-precision form.
                */
                bool is_multiprecision() {
                    return !is_rns_;
                }

                /**
                Insert a polynomial into the data array of the
                */
                void insert_polynomial(std::size_t poly_index, const uint64_t* array) {

                    // This performs a check that the polynomial is in bounds.
                    auto poly_start = get_polynomial(poly_index);

                    if (polynomial_reserved_[poly_index]) {
                        throw std::logic_error("Attempted to overwrite a polynomial in PolynomialArray.");
                    }

                    util::set_uint(array, poly_len_, poly_start);

                    polynomial_reserved_[poly_index] = true;
                }

                /**
                Modifies the polynomial array in place to multi-precision form.
                */
                void to_multiprecision();

                /**
                Modifies the polynomial array in place to RNS form.
                */
                void to_rns();

                /**
                Return a reference to the first element of the polynomial array.
                */
                SEAL_NODISCARD inline std::uint64_t *get() noexcept
                {
                    return data_.get();
                }

                /**
                Return a constant reference to the first element of the polynomial array.
                */
                SEAL_NODISCARD inline const std::uint64_t *get() const noexcept
                {
                    return data_.get();
                }

                /**
                Get a pointer to the start of a specific polynomial in the
                polynomial array. Throws a logic error if the index is larger
                than the number of polynomials held by the polynomial array.
                */
                SEAL_NODISCARD inline std::uint64_t *get_polynomial(std::size_t poly_index) 
                {
                    if (poly_index >= poly_size_) {
                        throw std::logic_error("Polynomial index greater than number of polynomials stored");
                    }
   
                    auto poly_start = data_.get() + poly_len_ * poly_index;
                    return poly_start;
                }

                /**
                Get a pointer to the start of a specific polynomial in the
                polynomial array. Throws a logic error if the index is larger
                than the number of polynomials held by the polynomial array.
                */
                SEAL_NODISCARD inline const std::uint64_t *get_polynomial(std::size_t poly_index) const  
                {
                    if (poly_index >= poly_size_) {
                        throw std::logic_error("Polynomial index greater than number of polynomials stored");
                    }
   
                    auto poly_start = data_.get() + poly_len_ * poly_index;
                    return poly_start;
                }

                /**
                Returns the number of polynomials stored.
                */
                SEAL_NODISCARD inline std::size_t poly_size() const noexcept
                {
                    return poly_size_;
                }

                /**
                Returns the number of coefficient in each polynomial stored.
                */
                SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
                {
                    return coeff_size_;
                }

                /**
                Returns the number of primes in the coefficient modulus of the
                associated encryption parameters.
                */
                SEAL_NODISCARD inline std::size_t coeff_modulus_size() const noexcept
                {
                    return coeff_modulus_size_;
                }


                /**
                Returns how many uint64_t are used to store the array. For use
                with `perform_export`.
                */
                SEAL_NODISCARD inline std::size_t export_size() const
                {
                    return len_;
                }

                /**
                Copy the polynomial array to a data buffer.
                */
                void perform_export(uint64_t *data) const
                {
                    util::set_uint(data_.get(), len_, data);
                }

                /**
                Switches the polynomial array down one modulus by dropping the
                last modulus in the set.
                */
                PolynomialArray drop() const;

            private:
                // We make an independent function instead of setting on
                // initialization so that we can allocate a
                // PolynomialArray without knowing the modulus yet (it
                // gets passed in later)
                void set_modulus(const std::vector<Modulus> &coeff_modulus){
                    coeff_modulus_ = coeff_modulus;
                    coeff_modulus_size_ = coeff_modulus.size();

                    rnsbase_ = allocate<RNSBase>(pool_, coeff_modulus, pool_);
                }

                MemoryPoolHandle pool_;
                Pointer<uint64_t> data_;
                std::vector<Modulus> coeff_modulus_;
                Pointer<RNSBase> rnsbase_;

                std::size_t poly_size_ = 0;
                std::size_t coeff_size_ = 0;
                std::size_t coeff_modulus_size_ = 0;
                std::size_t poly_len_ = 0;
                std::size_t len_ = 0;

                bool reserved_ = false;
                std::vector<bool> polynomial_reserved_;

                bool zero_on_destruction_ = true;

                // Is this array in RNS form or in multiprecision form?
                bool is_rns_ = true;
        };
}
