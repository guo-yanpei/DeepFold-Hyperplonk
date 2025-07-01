use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ff::{biginteger::BigInt, BigInteger, Field as F, One, PrimeField, UniformRand, Zero};

use super::{Field, PairingField};

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DynamicField {
    modulus: u64,
    v: u64,
}

impl DynamicField {
    pub fn gen_sig(modulus: u64) -> Self {
        Self {
            v: 0,
            modulus,
        }
    }

    pub fn from_with_modulus(a: u64, modulus: u64) -> Self {
        Self {
            v: a,
            modulus,
        }
    }

    pub fn inv_with_modulus(&self, modulus: u64) -> Option<Self> {
        if self.v == 0 {
            return None; // 零没有逆元
        }
        // MODULUS 必须是素数
        Some(self.exp((modulus - 2) as usize))
    }

    pub fn get_modulus(&self) -> u64 {
        self.modulus
    }

    pub fn one_with_modulus(modulus: u64) -> Self {
        Self {
            v: 1,
            modulus,
        }
    }

    pub fn exp_with_modulus(&self, mut exponent: usize, modulus: u64) -> Self {
        let mut res = Self::one_with_modulus(modulus);
        let mut t = self.clone();
        while exponent != 0 {
            if (exponent & 1) == 1 {
                res *= t;
            }
            t *= t;
            exponent >>= 1;
        }
        res
    }

}

impl std::ops::Neg for DynamicField {
    type Output = Self;
    fn neg(self) -> Self::Output {
        if self.v == 0 {
            self
        } else {
            Self { v: self.modulus - self.v, modulus: self.modulus }
        }
        
    }
}
impl std::ops::Add for DynamicField {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = self.v + rhs.v;
        if sum >= self.modulus {
            sum -= self.modulus
        }

        Self {
            v: sum,
            modulus: self.modulus
        }
    }
}

impl std::ops::AddAssign for DynamicField {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs
    }
}

impl std::ops::Sub for DynamicField {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let sub;
        if self.v < rhs.v {
            sub = self.modulus + self.v - rhs.v;
        } else {
            sub = self.v - rhs.v;
        }
        Self {
            v: sub,
            modulus: self.modulus,
        }
    }
}

impl std::ops::SubAssign for DynamicField {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs
    }
}

impl std::ops::Mul for DynamicField {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut prod = (self.v as u128) * (rhs.v as u128);
        prod = prod % self.modulus as u128;
        Self {
            v: prod as u64,
            modulus: self.modulus,
        }
        // Self(self.0 * rhs.0)
    }
}

impl std::ops::MulAssign for DynamicField {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl From<u32> for DynamicField {
    fn from(value: u32) -> Self {
        Self {
            v: value as u64,
            modulus: 0,
        }
    }
}

impl From<u64> for DynamicField {
    fn from(value: u64) -> Self {
        Self {
            v: value,
            modulus: 0,
        }
    }
}

impl Field for DynamicField {
    const NAME: &'static str = "Dynamic Field";
    const SIZE: usize = 64;
    // const INV_2: Self = Self::default();
    type BaseField = Self;

    fn zero() -> Self {
        Self {
            v: 0,
            modulus: 0,
        }
    }

    fn is_zero(&self) -> bool {
        self.v.is_zero()
    }

    fn inv_2() -> Self {
        unimplemented!()
    }

    fn one() -> Self {
        Self {
            v: 0,
            modulus: 0,
        }
    }

    fn double(&self) -> Self {
        *self + *self
    }

    fn square(&self) -> Self {
        *self * *self
    }

    fn random(mut rng: impl rand::RngCore) -> Self {
        Self {
            v: 0,
            modulus: 0,
        }
    }

    fn inv(&self) -> Option<Self> {
        println!("inv modulus: {}", self.modulus);
        if self.v == 0 {
            return None; // 零没有逆元
        }
        // MODULUS 必须是素数
        Some(self.exp_with_modulus((self.modulus - 2) as usize, self.modulus))
    }

    fn exp(&self, mut exponent: usize) -> Self {
        let mut res = Self::one();
        let mut t = self.clone();
        while exponent != 0 {
            if (exponent & 1) == 1 {
                res *= t;
            }
            t *= t;
            exponent >>= 1;
        }
        res
    }

    fn add_base_elem(&self, rhs: Self::BaseField) -> Self {
        self.clone() + rhs
    }

    fn add_assign_base_elem(&mut self, rhs: Self::BaseField) {
        *self += rhs
    }

    fn mul_base_elem(&self, rhs: Self::BaseField) -> Self {
        *self * rhs
    }

    fn mul_assign_base_elem(&mut self, rhs: Self::BaseField) {
        *self *= rhs;
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        unimplemented!()
    }

    fn serialize_into(&self, buffer: &mut [u8]) {
        unimplemented!()
    }

    fn deserialize_from(buffer: &[u8]) -> Self {
        unimplemented!()
    }

    fn get_value(&self) -> u64 {
        self.v
    }
}