use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use rand::RngCore;

pub mod bn_254;
pub mod goldilocks64;

pub trait Field:
    Copy
    + Clone
    + Debug
    + Default
    + PartialEq
    + From<u32>
    + From<Self::BaseField>
    + Neg<Output = Self>
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
{
    const NAME: &'static str;
    const SIZE: usize;
    type BaseField: Field;

    fn zero() -> Self;
    fn is_zero(&self) -> bool;
    fn one() -> Self;
    fn random(rng: impl RngCore) -> Self;
    fn square(&self) -> Self {
        self.clone() * self.clone()
    }
    fn inv_2() -> Self;
    fn double(&self) -> Self {
        self.clone() + self.clone()
    }
    fn exp(&self, exponent: usize) -> Self;
    fn inv(&self) -> Option<Self>;
    fn add_base_elem(&self, rhs: Self::BaseField) -> Self;
    fn add_assign_base_elem(&mut self, rhs: Self::BaseField);
    fn mul_base_elem(&self, rhs: Self::BaseField) -> Self;
    fn mul_assign_base_elem(&mut self, rhs: Self::BaseField);
    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self;
    fn serialize_into(&self, buffer: &mut [u8]);
    fn deserialize_from(buffer: &[u8]) -> Self;
}

pub trait FftField: Field + From<Self::FftBaseField> {
    const LOG_ORDER: u32;
    const ROOT_OF_UNITY: Self;
    type FftBaseField: FftField<BaseField = Self::BaseField>;
}

pub trait PairingField: Field {
    type E: Pairing;
    type G1: Into<<Self::E as Pairing>::G1Prepared> + UniformRand + Clone + Copy;
    type G2: Into<<Self::E as Pairing>::G2Prepared> + UniformRand + Clone + Copy;

    fn g1_mul(g1: Self::G1, x: Self) -> Self::G1;
    fn g2_mul(g2: Self::G2, x: Self) -> Self::G2;
}

pub fn batch_inverse<F: Field>(v: &mut [F]) {
    let mut aux = vec![v[0]];
    let len = v.len();
    for i in 1..len {
        aux.push(aux[i - 1] * v[i]);
    }
    let mut prod = aux[len - 1].inv().unwrap();
    for i in (1..len).rev() {
        (prod, v[i]) = (prod * v[i], prod * aux[i - 1]);
    }
    v[0] = prod;
}

pub fn as_bytes_vec<F: Field>(v: &[F]) -> Vec<u8> {
    let mut buffer = vec![0; F::SIZE * v.len()];
    let mut cnt = 0;
    for i in v.iter() {
        i.serialize_into(&mut buffer[cnt..cnt + F::SIZE]);
        cnt += F::SIZE;
    }
    buffer
}

#[cfg(test)]
mod tests {
    use ark_ec::pairing::Pairing;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    use super::{bn_254::Bn254F, Field, PairingField};

    #[test]
    fn serialize() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let f = Bn254F::random(&mut rng);
            let mut buffer = [0u8; 64];
            f.serialize_into(&mut buffer);
            let g = Bn254F::deserialize_from(&buffer);
            assert_eq!(f, g);
        }
    }

    fn pairing<F: PairingField>() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let g1 = F::G1::rand(&mut rng);
            let g2 = F::G2::rand(&mut rng);
            let x = F::random(&mut rng);
            assert_eq!(
                F::E::pairing(F::g1_mul(g1, x), g2),
                F::E::pairing(g1, F::g2_mul(g2, x))
            );
        }
    }

    #[test]
    fn pairing_test() {
        pairing::<Bn254F>();
    }
}
