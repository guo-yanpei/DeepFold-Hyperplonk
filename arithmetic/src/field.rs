use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use rand::RngCore;

pub mod goldilocks64;

pub trait Field:
    Copy
    + Clone
    + Debug
    + Default
    + PartialEq
    + From<u32>
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
    const INV_2: Self;
    type BaseField: Field;

    fn zero() -> Self;
    fn is_zero() -> bool;
    fn one() -> Self;
    fn random(rng: impl RngCore) -> Self;
    fn square(&self) -> Self {
        self.clone() * self.clone()
    }
    fn double(&self) -> Self {
        self.clone() + self.clone()
    }
    fn exp(&self, exponent: usize) -> Self;
    fn inv(&self) -> Option<Self>;
    fn add_base_elem(&self, rhs: &Self::BaseField) -> Self;
    fn add_assign_base_elem(&mut self, rhs: &Self::BaseField);
    fn mul_base_elem(&self, rhs: &Self::BaseField) -> Self;
    fn mul_assign_base_elem(&mut self, rhs: &Self::BaseField);
    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self;
    fn serialize_into(&self, buffer: &mut [u8]);
    fn deserialize_from(buffer: &[u8]) -> Self;
}

pub trait FftField: Field {
    const LOG_ORDER: u32;
    const ROOT_OF_UNITY: Self;
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
