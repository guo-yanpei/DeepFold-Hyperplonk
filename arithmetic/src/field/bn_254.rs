use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ff::{biginteger::BigInt, BigInteger, Field as F, One, PrimeField, UniformRand, Zero};

use super::{Field, PairingField};

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Bn254F(Fr);

impl std::ops::Neg for Bn254F {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}
impl std::ops::Add for Bn254F {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::AddAssign for Bn254F {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs
    }
}

impl std::ops::Sub for Bn254F {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl std::ops::SubAssign for Bn254F {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs
    }
}

impl std::ops::Mul for Bn254F {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl std::ops::MulAssign for Bn254F {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl From<u32> for Bn254F {
    fn from(value: u32) -> Self {
        Bn254F(value.into())
    }
}

impl From<u64> for Bn254F {
    fn from(value: u64) -> Self {
        Bn254F(value.into())
    }
}

impl Field for Bn254F {
    const NAME: &'static str = "Bn254 Fr";
    const SIZE: usize = 32;
    // const INV_2: Self = Self::default();
    type BaseField = Self;

    fn zero() -> Self {
        Self(Fr::from(0))
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn inv_2() -> Self {
        unimplemented!()
    }

    fn one() -> Self {
        Self(Fr::one())
    }

    fn double(&self) -> Self {
        Self(self.0 + self.0)
    }

    fn square(&self) -> Self {
        Self(self.0 * self.0)
    }

    fn random(mut rng: impl rand::RngCore) -> Self {
        Self(Fr::rand(&mut rng))
    }

    fn inv(&self) -> Option<Self> {
        self.0.inverse().map(|x| Self(x))
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
        Self(Fr::from_le_bytes_mod_order(bytes))
    }

    fn serialize_into(&self, buffer: &mut [u8]) {
        buffer[..Self::SIZE].copy_from_slice(&self.0.into_bigint().to_bytes_le())
    }

    fn deserialize_from(buffer: &[u8]) -> Self {
        let ptr = buffer.as_ptr() as *const u64;
        let v0 = unsafe { ptr.read_unaligned() } as u64;
        let v1 = unsafe { ptr.add(1).read_unaligned() } as u64;
        let v2 = unsafe { ptr.add(2).read_unaligned() } as u64;
        let v3 = unsafe { ptr.add(3).read_unaligned() } as u64;
        Self(BigInt([v0, v1, v2, v3]).into())
    }
}

impl PairingField for Bn254F {
    type E = Bn254;
    type G1 = G1Projective;
    type G2 = G2Projective;

    fn g1_mul(g1: Self::G1, x: Self) -> Self::G1 {
        g1 * x.0
    }

    fn g2_mul(g2: Self::G2, x: Self) -> Self::G2 {
        g2 * x.0
    }
}
