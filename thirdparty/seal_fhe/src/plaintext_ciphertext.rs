use core::hash::Hash;
use std::ffi::{c_void, CString};
use std::ptr::null_mut;
use std::vec;

use crate::{bindgen, serialization::CompressionType, Context, FromBytes, ToBytes};
use crate::{encoder, error::*, Asym, Encryptor};

use serde::ser::Error;
use serde::{Serialize, Serializer};

use super::encoder::BFVEncoder;

#[derive(Debug, Eq)]
/**
 * Class to store a plaintext element. The data for the plaintext is
 * a polynomial with coefficients modulo the plaintext modulus. The degree
 * of the plaintext polynomial must be one less than the degree of the
 * polynomial modulus. The backing array always allocates one 64-bit word
 * per each coefficient of the polynomial.
 *
 * # Memory Management
 * The coefficient count of a plaintext refers to the number of word-size
 * coefficients in the plaintext, whereas its capacity refers to the number
 * of word-size coefficients that fit in the current memory allocation. In
 * high-performance applications unnecessary re-allocations should be avoided
 * by reserving enough memory for the plaintext to begin with either by
 * providing the desired capacity to the constructor as an extra argument, or
 * by calling the reserve function at any time.
 *
 * When the scheme is SchemeType.BFV each coefficient of a plaintext is
 * a 64-bit word, but when the scheme is SchemeType.CKKS the plaintext is
 * by default stored in an NTT transformed form with respect to each of the
 * primes in the coefficient modulus. Thus, the size of the allocation that
 * is needed is the size of the coefficient modulus (number of primes) times
 * the degree of the polynomial modulus. In addition, a valid CKKS plaintext
 * will also store the ParmsId for the corresponding encryption parameters.
 */
pub struct Plaintext {
    handle: *mut c_void,
}

unsafe impl Sync for Plaintext {}
unsafe impl Send for Plaintext {}

impl Clone for Plaintext {
    fn clone(&self) -> Self {
        let mut copy = null_mut();

        convert_seal_error(unsafe { bindgen::Plaintext_Create5(self.handle, &mut copy) })
            .expect("Internal error: Failed to copy plaintext.");

        Self { handle: copy }
    }
}

impl AsRef<Plaintext> for Plaintext {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl PartialEq for Plaintext {
    fn eq(&self, other: &Self) -> bool {
        if self.len() == other.len() {
            for i in 0..self.len() {
                if self.get_coefficient(i) != other.get_coefficient(i) {
                    return false;
                }
            }

            true
        } else {
            false
        }
    }
}

impl Hash for Plaintext {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for i in 0..self.len() {
            let c = self.get_coefficient(i);
            state.write_u64(c);
        }
    }
}

impl Serialize for Plaintext {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut num_bytes: i64 = 0;

        convert_seal_error(unsafe {
            bindgen::Plaintext_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })
        .map_err(|e| {
            S::Error::custom(format!("Failed to get private key serialized size: {}", e))
        })?;

        let bytes = self
            .as_bytes()
            .map_err(|e| S::Error::custom(format!("Failed to serialize bytes: {}", e)))?;

        serializer.serialize_bytes(&bytes)
    }
}

impl FromBytes for Plaintext {
    /**
     * Deserializes a byte stream into a plaintext. This requires a context, which is why
     * Plaintext doesn't `impl Deserialize`.
     */
    fn from_bytes(context: &Context, data: &[u8]) -> Result<Self> {
        let mut bytes_read = 0;

        let plaintext = Plaintext::new()?;

        convert_seal_error(unsafe {
            // While the interface marks data as mut, SEAL doesn't actually modify it, so we're okay.
            bindgen::Plaintext_Load(
                plaintext.handle,
                context.get_handle(),
                data.as_ptr() as *mut u8,
                data.len() as u64,
                &mut bytes_read,
            )
        })?;

        Ok(plaintext)
    }
}

impl ToBytes for Plaintext {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        convert_seal_error(unsafe {
            bindgen::Plaintext_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(num_bytes as usize);
        let mut bytes_written: i64 = 0;

        convert_seal_error(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::Plaintext_Save(
                self.handle,
                data_ptr,
                num_bytes as u64,
                CompressionType::ZStd as u8,
                &mut bytes_written,
            )
        })?;

        unsafe { data.set_len(bytes_written as usize) };

        Ok(data)
    }
}

impl Plaintext {
    /**
     * size of a single plaintext
     */
    pub const SIZE: usize = 1; // Todo: size

    pub fn inv(&self, encoder: &BFVEncoder) -> Self {
        encoder.encode_unsigned(&[0]).unwrap()
    }

    pub fn get_value(&self, encoder: &BFVEncoder) -> Vec<u64> {
        encoder.decode_unsigned(&self).unwrap()
    }

    /**
     * Returns the handle to the underlying SEAL object.
     */
    pub fn get_handle(&self) -> *mut c_void {
        self.handle
    }

    pub fn random_pt(encoder: &BFVEncoder) -> Self {
        let plain_modulus = encoder.get_params().get_plain_modulus().value();
        let degree = encoder.get_slot_count();
        let vec_random_u64 = (0..degree).into_iter().map(|_| rand::random_range(0..plain_modulus)).collect::<Vec<u64>>();
        encoder.encode_unsigned(&vec_random_u64).unwrap()
    }

    pub fn inverse_2(encoder: &BFVEncoder) -> Self {
        let modulus = encoder.get_params().get_plain_modulus().value();
        if modulus % 2 == 0 {
            panic!("invalid modulus!")
        }
        Self::from_int((modulus + 1) / 2, encoder)
    }

    /**
     * Adds 2 pts
     */
    pub fn add(&self, rhs: &Self, encoder: &BFVEncoder) -> Self {
        let pt1 = encoder.decode_unsigned(&self).unwrap();
        let pt2 = encoder.decode_unsigned(&rhs).unwrap();
        assert_eq!(pt1.len(), pt2.len());

        // // need to substract the modulus if exceeded
        let res: Vec<u64> = pt1
            .into_iter()
            .zip(pt2)
            .map(|(x, y)| {
                let mut sum = x + y;
                let modulus = encoder.get_params().get_plain_modulus().value();
                if sum >= modulus {
                    sum -= modulus;
                }
                sum
            })
            .collect::<Vec<u64>>();

        encoder.encode_unsigned(&res).unwrap()
    }

    /**
     * Substracts rhs from self
     */
    pub fn sub(&self, rhs: &Self, encoder: &BFVEncoder) -> Self {
        let pt1 = encoder.decode_unsigned(&self).unwrap();
        let pt2 = encoder.decode_unsigned(&rhs).unwrap();
        assert_eq!(pt1.len(), pt2.len());

        let modulus = encoder.get_params().get_plain_modulus().value();
        let diffs = pt1
            .into_iter()
            .zip(pt2)
            .map(|(x, y)| {
                let diff;
                if x >= y {
                    diff = x - y;
                } else {
                    diff = x + modulus - y;
                }
                diff
            })
            .collect::<Vec<u64>>();
        encoder.encode_unsigned(&diffs).unwrap()
    }

    pub fn neg(&self, encoder: &BFVEncoder) -> Self {
        let modulus = encoder.get_params().get_plain_modulus().value();
        let v = encoder.decode_unsigned(self).unwrap();
        let res = v
            .into_iter()
            .map(|x| if x == 0 { 0 } else { modulus - x })
            .collect::<Vec<u64>>();
        encoder.encode_unsigned(&res).unwrap()
    }

    /**
     * Mults 2 pts
     */
    pub fn mult(&self, rhs: &Self, encoder: &BFVEncoder) -> Self {
        let pt1 = encoder.decode_unsigned(&self).unwrap();
        let pt2 = encoder.decode_unsigned(&rhs).unwrap();
        assert_eq!(pt1.len(), pt2.len());

        // // need to substract the modulus if exceeded
        let res: Vec<u64> = pt1
            .into_iter()
            .zip(pt2)
            .map(|(x, y)| {
                let mut prod = (x as u128) * (y as u128);
                let modulus = encoder.get_params().get_plain_modulus().value() as u128;
                prod = prod % modulus;
                prod as u64
            })
            .collect::<Vec<u64>>();

        encoder.encode_unsigned(&res).unwrap()
    }

    /**
     * Constructs an empty plaintext allocating no memory.
     */
    pub fn new() -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        convert_seal_error(unsafe { bindgen::Plaintext_Create1(null_mut(), &mut handle) })?;

        Ok(Self { handle })
    }

    /**
     * Converts a u64 to Plaintext
     */
    pub fn from_int(a: u64, encoder: &BFVEncoder) -> Self {
        let slot = encoder.get_slot_count();
        encoder.encode_unsigned(&vec![a; slot]).unwrap()
    }

    /**
     * Constructs a plaintext from a given hexadecimal string describing the
     * plaintext polynomial.
     *
     * The string description of the polynomial must adhere to the format
     * returned by ToString(), which is of the form "7FFx^3 + 1x^1 + 3"
     * and summarized by the following
     * rules:
     * 1. Terms are listed in order of strictly decreasing exponent
     * 2. Coefficient values are non-negative and in hexadecimal format (upper
     *    and lower case letters are both supported)
     * 3. Exponents are positive and in decimal format
     * 4. Zero coefficient terms (including the constant term) may be (but do
     *    not have to be) omitted
     * 5. Term with the exponent value of one must be exactly written as x^1
     * 6. Term with the exponent value of zero (the constant term) must be written
     *    as just a hexadecimal number without exponent
     * 7. Terms must be separated by exactly \[space\]+\[space\] and minus is not
     *    allowed
     * 8. Other than the +, no other terms should have whitespace
     *
     * * `hex_str`: The formatted polynomial string specifying the plaintext
     *   polynomial.
     *
     * # Panics
     * Panics if `hex_str` contains a null character anywhere but the end of the string.
     */
    pub fn from_hex_string(hex_str: &str) -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        let hex_string = CString::new(hex_str).unwrap();

        convert_seal_error(unsafe {
            bindgen::Plaintext_Create4(hex_string.as_ptr() as *mut u8, null_mut(), &mut handle)
        })?;

        Ok(Self { handle })
    }

    /**
     * Gets the coefficient at the given location. Coefficients are ordered
     * from lowest to highest degree, with the first value being the constant
     * coefficient.
     *
     * # Panics
     * Panics if index is greater than len().
     */
    pub fn get_coefficient(&self, index: usize) -> u64 {
        let mut coeff: u64 = 0;

        if index > self.len() {
            panic!("Index {} out of bounds {}", index, self.len());
        }

        convert_seal_error(unsafe {
            bindgen::Plaintext_CoeffAt(self.handle, index as u64, &mut coeff)
        })
        .expect("Fatal error in Plaintext::index().");

        coeff
    }

    /**
     * Sets the coefficient at the given location. Coefficients are ordered
     * from lowest to highest degree, with the first value being the constant
     * coefficient.
     *
     * # Panics
     * Panics if index is greater than len().
     */
    pub fn set_coefficient(&mut self, index: usize, value: u64) {
        if index > self.len() {
            panic!("Index {} out of bounds {}", index, self.len());
        }

        convert_seal_error(unsafe {
            bindgen::Plaintext_SetCoeffAt(self.handle, index as u64, value)
        })
        .expect("Fatal error in Plaintext::index().");
    }

    /**
     * Sets the number of coefficients this plaintext can hold.
     */
    pub fn resize(&mut self, count: usize) {
        convert_seal_error(unsafe { bindgen::Plaintext_Resize(self.handle, count as u64) })
            .expect("Fatal error in Plaintext::resize().");
    }

    /**
     * Returns the number of coefficients this plaintext can hold.
     */
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        let mut size: u64 = 0;

        convert_seal_error(unsafe { bindgen::Plaintext_CoeffCount(self.handle, &mut size) })
            .expect("Fatal error in Plaintext::index().");

        size as usize
    }

    /**
     * Returns whether the plaintext is in NTT form.
     */
    pub fn is_ntt_form(&self) -> bool {
        let mut result = false;

        convert_seal_error(unsafe { bindgen::Plaintext_IsNTTForm(self.handle, &mut result) })
            .expect("Fatal error in Plaintext::is_ntt_form().");

        result
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        convert_seal_error(unsafe { bindgen::Plaintext_Destroy(self.handle) })
            .expect("Internal error in Plaintext::drop.");
    }
}

/**
 * Class to store a ciphertext element. The data for a ciphertext consists
 * of two or more polynomials, which are in Microsoft SEAL stored in a CRT
 * form with respect to the factors of the coefficient modulus. This data
 * itself is not meant to be modified directly by the user, but is instead
 * operated on by functions in the Evaluator class. The size of the backing
 * array of a ciphertext depends on the encryption parameters and the size
 * of the ciphertext (at least 2). If the PolyModulusDegree encryption
 * parameter is N, and the number of primes in the CoeffModulus encryption
 * parameter is K, then the ciphertext backing array requires precisely
 * 8*N*K*size bytes of memory. A ciphertext also carries with it the
 * parmsId of its associated encryption parameters, which is used to check
 * the validity of the ciphertext for homomorphic operations and decryption.
 *
 * # Memory Management
 * The size of a ciphertext refers to the number of polynomials it contains,
 * whereas its capacity refers to the number of polynomials that fit in the
 * current memory allocation. In high-performance applications unnecessary
 * re-allocations should be avoided by reserving enough memory for the
 * ciphertext to begin with either by providing the desired capacity to the
 * constructor as an extra argument, or by calling the reserve function at
 * any time.
 */
#[derive(Debug)]
pub struct Ciphertext {
    handle: *mut c_void,
}

unsafe impl Sync for Ciphertext {}
unsafe impl Send for Ciphertext {}

impl Clone for Ciphertext {
    fn clone(&self) -> Self {
        let mut handle = null_mut();

        convert_seal_error(unsafe { bindgen::Ciphertext_Create2(self.handle, &mut handle) })
            .expect("Fatal error: Failed to clone ciphertext");

        Self { handle }
    }
}

impl AsRef<Ciphertext> for Ciphertext {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Ciphertext {
    /**
     * Returns the handle to the underlying SEAL object.
     */
    pub fn get_handle(&self) -> *mut c_void {
        self.handle
    }

    /**
     * Creates a new empty plaintext. Use an encoder to populate with a value.
     */
    pub fn new() -> Result<Self> {
        let mut handle: *mut c_void = null_mut();

        convert_seal_error(unsafe { bindgen::Ciphertext_Create1(null_mut(), &mut handle) })?;

        Ok(Self { handle })
    }

    /**
     * Creates a ciphertext that encrypts the given u64
     */
    pub fn from_int(a: u64, encoder: &BFVEncoder, encryptor: &Encryptor<Asym>) -> Self {
        let pt = Plaintext::from_int(a, encoder);
        encryptor.encrypt(&pt).unwrap()
    }

    pub fn random_ct(encoder: &BFVEncoder, encryptor: &Encryptor<Asym>) -> Self {
        let pt = Plaintext::random_pt(encoder);
        encryptor.encrypt(&pt).unwrap()
    }

    /**
     * Returns the number of polynomials in this ciphertext.
     */
    pub fn num_polynomials(&self) -> u64 {
        let mut size: u64 = 0;

        convert_seal_error(unsafe { bindgen::Ciphertext_Size(self.handle, &mut size) }).unwrap();

        size
    }

    /**
     * Returns the number of components in the coefficient modulus.
     */
    pub fn coeff_modulus_size(&self) -> u64 {
        let mut size: u64 = 0;

        convert_seal_error(unsafe { bindgen::Ciphertext_CoeffModulusSize(self.handle, &mut size) })
            .unwrap();

        size
    }

    /**
     * Returns the value at a specific point in the coefficient array. This is
     * not publically exported as it leaks the encoding of the array.
     */
    #[allow(dead_code)]
    pub(crate) fn get_data(&self, index: usize) -> Result<u64> {
        let mut value: u64 = 0;

        convert_seal_error(unsafe {
            bindgen::Ciphertext_GetDataAt1(self.handle, index as u64, &mut value)
        })?;

        Ok(value)
    }

    /**
     * Returns the coefficient in the form the ciphertext is currently in (NTT
     * form or not). For BFV, this will be the coefficient in the residual
     * number system (RNS) format.
     */
    pub fn get_coefficient(&self, poly_index: usize, coeff_index: usize) -> Result<Vec<u64>> {
        let size = self.coeff_modulus_size();
        let mut data: Vec<u64> = Vec::with_capacity(size as usize);

        convert_seal_error(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::Ciphertext_GetDataAt2(
                self.handle,
                poly_index as u64,
                coeff_index as u64,
                data_ptr,
            )
        })?;

        unsafe { data.set_len(size as usize) };

        Ok(data.clone())
    }

    /**
     * Returns whether the ciphertext is in NTT form.
     */
    pub fn is_ntt_form(&self) -> bool {
        let mut result = false;

        convert_seal_error(unsafe { bindgen::Ciphertext_IsNTTForm(self.handle, &mut result) })
            .expect("Fatal error in Plaintext::is_ntt_form().");

        result
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl ToBytes for Ciphertext {
    fn as_bytes(&self) -> Result<Vec<u8>> {
        let mut num_bytes: i64 = 0;

        convert_seal_error(unsafe {
            bindgen::Ciphertext_SaveSize(self.handle, CompressionType::ZStd as u8, &mut num_bytes)
        })?;

        let mut data: Vec<u8> = Vec::with_capacity(num_bytes as usize);
        let mut bytes_written: i64 = 0;

        convert_seal_error(unsafe {
            let data_ptr = data.as_mut_ptr();

            bindgen::Ciphertext_Save(
                self.handle,
                data_ptr,
                num_bytes as u64,
                CompressionType::ZStd as u8,
                &mut bytes_written,
            )
        })?;

        unsafe { data.set_len(bytes_written as usize) };

        Ok(data)
    }
}

impl FromBytes for Ciphertext {
    fn from_bytes(context: &Context, bytes: &[u8]) -> Result<Self> {
        let ciphertext = Self::new()?;
        let mut bytes_read = 0i64;

        convert_seal_error(unsafe {
            bindgen::Ciphertext_Load(
                ciphertext.handle,
                context.handle,
                bytes.as_ptr() as *mut u8,
                bytes.len() as u64,
                &mut bytes_read,
            )
        })?;

        Ok(ciphertext)
    }
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        convert_seal_error(unsafe { bindgen::Ciphertext_Destroy(self.handle) })
            .expect("Internal error in Ciphertext::drop");
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        key_generator, BfvEncryptionParametersBuilder, CoefficientModulus, Decryptor, EncryptionParameters, KeyGenerator, PlainModulus, PublicKey, SecretKey
    };

    use super::*;
    fn gen_params_n_ctx() -> (EncryptionParameters, Context) {
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(8192)
            .set_coefficient_modulus(
                CoefficientModulus::create(8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulus::batching(8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, crate::SecurityLevel::TC128).unwrap();

        (params, ctx)
    }

    fn gen_key(ctx: &Context) -> (KeyGenerator, PublicKey, SecretKey) {
        let key_gen = KeyGenerator::new(&ctx).unwrap();
        let public_key = key_gen.create_public_key();
        let secret_key = key_gen.secret_key();
        (key_gen, public_key, secret_key)
    }

    #[test]
    fn test_enc() {
        let (params, ctx) = gen_params_n_ctx();
        let (key_gen, pk, sk) = gen_key(&ctx);
        let encoder = BFVEncoder::new(&ctx, &params).unwrap();
        let encryptor = Encryptor::<Asym>::new(&ctx, &pk).unwrap();
        let decryptor = Decryptor::new(&ctx, &sk).unwrap();
        let p = encoder.encode_unsigned(&[10]).unwrap();
        let c = encryptor.encrypt(&p).unwrap();
        let p2 = decryptor.decrypt(&c).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn can_add_ppp() {
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(8192)
            .set_coefficient_modulus(
                CoefficientModulus::create(8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulus::batching(8192, 20).unwrap())
            .build()
            .unwrap();

        let modulus = PlainModulus::batching(8192, 20).unwrap().value();

        let ctx = Context::new(&params, false, crate::SecurityLevel::TC128).unwrap();

        let encoder = BFVEncoder::new(&ctx, &params).unwrap();

        let pt1 = encoder.encode_unsigned(&[modulus - 1]).unwrap();
        let pt2 = encoder.encode_unsigned(&[modulus - 2]).unwrap();

        let pt3 = Plaintext::add(&pt1, &pt2, &encoder);

        let num = encoder.decode_unsigned(&pt3).unwrap()[0];
        assert_eq!(num, modulus - 3);
    }

    #[test]
    fn test_neg() {
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(8192)
            .set_coefficient_modulus(
                CoefficientModulus::create(8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulus::batching(8192, 20).unwrap())
            .build()
            .unwrap();

        let modulus = PlainModulus::batching(8192, 20).unwrap().value();

        let ctx = Context::new(&params, false, crate::SecurityLevel::TC128).unwrap();

        let encoder = BFVEncoder::new(&ctx, &params).unwrap();

        let p = Plaintext::from_int(1234, &encoder);
        let i = p.neg(&encoder);
        assert_eq!(encoder.decode_unsigned(&i).unwrap()[0], modulus - 1234);
    }

    #[test]
    fn test_inverse_2() {
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(8192)
            .set_coefficient_modulus(
                CoefficientModulus::create(8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulus::batching(8192, 20).unwrap())
            .build()
            .unwrap();

        let modulus = PlainModulus::batching(8192, 20).unwrap().value();

        let ctx = Context::new(&params, false, crate::SecurityLevel::TC128).unwrap();

        let encoder = BFVEncoder::new(&ctx, &params).unwrap();

        let t = Plaintext::from_int(2, &encoder);
        let i = Plaintext::inverse_2(&encoder);
        let m = Plaintext::mult(&t, &i, &encoder);
        assert_eq!(encoder.decode_unsigned(&m).unwrap()[0], 1);
    }

    #[test]
    fn can_sub_ppp() {
        let modulus = PlainModulus::batching(8192, 20).unwrap();
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(8192)
            .set_coefficient_modulus(
                CoefficientModulus::create(8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(modulus.clone())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, crate::SecurityLevel::TC128).unwrap();

        let encoder = BFVEncoder::new(&ctx, &params).unwrap();

        let pt1 = encoder.encode_unsigned(&[10u64]).unwrap();
        let pt2 = encoder.encode_unsigned(&[20u64]).unwrap();

        let pt3 = Plaintext::sub(&pt1, &pt2, &encoder);

        let num = encoder.decode_unsigned(&pt3).unwrap()[0];
        assert_eq!(num, modulus.value() - 10);
    }

    #[test]
    fn can_mult_ppp() {
        let params = BfvEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(8192)
            .set_coefficient_modulus(
                CoefficientModulus::create(8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .set_plain_modulus(PlainModulus::batching(8192, 20).unwrap())
            .build()
            .unwrap();

        let ctx = Context::new(&params, false, crate::SecurityLevel::TC128).unwrap();

        let encoder = BFVEncoder::new(&ctx, &params).unwrap();

        let pt1 = encoder.encode_unsigned(&[10u64]).unwrap();
        let pt2 = encoder.encode_unsigned(&[20u64]).unwrap();

        let pt3 = Plaintext::mult(&pt1, &pt2, &encoder);

        let num = encoder.decode_unsigned(&pt3).unwrap()[0];
        assert_eq!(num, 200u64);
    }

    #[test]
    fn can_create_and_destroy_ciphertext() {
        let ciphertext = Ciphertext::new().unwrap();

        std::mem::drop(ciphertext);
    }

    #[test]
    fn can_create_and_destroy_plaintext() {
        let plaintext = Plaintext::new().unwrap();

        std::mem::drop(plaintext);
    }

    #[test]
    fn plaintext_coefficients_in_increasing_order() {
        let plaintext = Plaintext::from_hex_string("1234x^2 + 4321").unwrap();

        assert_eq!(plaintext.get_coefficient(0), 0x4321);
        assert_eq!(plaintext.get_coefficient(1), 0);
        assert_eq!(plaintext.get_coefficient(2), 0x1234);
    }
}
