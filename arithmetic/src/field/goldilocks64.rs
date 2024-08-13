#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Goldilocks64 {
    v: u64,
}
const MOD: u64 = 18446744069414584321u64; // 2**64 - 2**32 + 1
const HIGH: u128 = (1u128 << 127) - (1u128 << 96) + (1u128 << 127);
const MIDDLE: u128 = (1u128 << 96) - (1u128 << 64);
const LOW: u128 = (1u128 << 64) - 1;

impl std::ops::Neg for Goldilocks64 {
    type Output = Goldilocks64;
    fn neg(self) -> Self::Output {
        if self.v == 0 {
            return self.clone();
        }
        Self { v: MOD - self.v }
    }
}

impl std::ops::Add for Goldilocks64 {
    type Output = Goldilocks64;
    fn add(self, rhs: Self) -> Self::Output {
        let mut res = self.v.wrapping_add(rhs.v);
        if res < self.v || res < rhs.v {
            res += 1u64 << 32;
            res -= 1;
        }
        if res >= MOD {
            res -= MOD;
        }
        Goldilocks64 { v: res }
    }
}

impl std::ops::AddAssign for Goldilocks64 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Sub for Goldilocks64 {
    type Output = Goldilocks64;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut res = self.v.wrapping_sub(rhs.v);
        if rhs.v > self.v {
            res = res.wrapping_add(MOD);
        }
        if res >= MOD {
            res -= MOD;
        }
        Goldilocks64 { v: res }
    }
}

impl std::ops::SubAssign for Goldilocks64 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl std::ops::Mul for Goldilocks64 {
    type Output = Goldilocks64;
    fn mul(self, rhs: Self) -> Self::Output {
        let res = self.v as u128 * rhs.v as u128;
        let high = ((res & HIGH) >> 96) as u64;
        let middle = ((res & MIDDLE) >> 64) as u64;
        let low = (res & LOW) as u64;
        let mut low2 = low.wrapping_sub(high);
        if high > low {
            low2 = low2.wrapping_add(MOD);
        }
        let mut product = middle << 32;
        product -= product >> 32;
        let mut ret = low2.wrapping_add(product);
        if ret < product || ret >= MOD {
            ret = ret.wrapping_sub(MOD);
        }
        Goldilocks64 { v: ret }
    }
}

impl std::ops::MulAssign for Goldilocks64 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl From<u32> for Goldilocks64 {
    fn from(value: u32) -> Self {
        Goldilocks64 { v: value as u64 }
    }
}

impl From<u64> for Goldilocks64 {
    fn from(mut value: u64) -> Self {
        if (value >> 63) == 1 {
            value = (1u64 << 63) | (value & ((1u64 << 32) - 1))
        }
        Goldilocks64 { v: value }
    }
}

use super::{FftField, Field};

impl Field for Goldilocks64 {
    const NAME: &'static str = "Goldilocks64";
    const SIZE: usize = 8;
    const INV_2: Self = Goldilocks64 { v: (MOD + 1) / 2 };
    type BaseField = Goldilocks64;

    fn zero() -> Self {
        Goldilocks64 { v: 0 }
    }

    fn is_zero(&self) -> bool {
        self.v == 0
    }

    fn one() -> Self {
        Goldilocks64 { v: 1 }
    }

    fn double(&self) -> Self {
        self.clone() + self.clone()
    }

    fn square(&self) -> Self {
        self.clone() * self.clone()
    }

    fn random(mut rng: impl rand::RngCore) -> Self {
        rng.next_u64().into()
    }

    fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.exp(MOD as usize - 2))
    }

    fn exp(&self, mut exponent: usize) -> Self {
        let mut res = Goldilocks64 { v: 1 };
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
        *self += rhs;
    }

    fn mul_base_elem(&self, rhs: Self::BaseField) -> Self {
        *self * rhs
    }

    fn mul_assign_base_elem(&mut self, rhs: Self::BaseField) {
        *self *= rhs;
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let ptr = bytes.as_ptr() as *const u64;
        let v = unsafe { ptr.read_unaligned() } as u64;
        v.into()
    }

    fn serialize_into(&self, buffer: &mut [u8]) {
        buffer[..Self::SIZE].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&self.v as *const u64 as *const u8, Self::SIZE)
        })
    }

    fn deserialize_from(buffer: &[u8]) -> Self {
        let ptr = buffer.as_ptr() as *const u64;
        let v = unsafe { ptr.read_unaligned() };
        assert!(v < MOD);
        Goldilocks64 { v }
    }
}

impl FftField for Goldilocks64 {
    const LOG_ORDER: u32 = 32;
    const ROOT_OF_UNITY: Self = Goldilocks64 {
        v: 2741030659394132017u64,
    };
    type FftBaseField = Goldilocks64;
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Goldilocks64Ext {
    v: [Goldilocks64; 2],
}

impl std::ops::Neg for Goldilocks64Ext {
    type Output = Goldilocks64Ext;
    fn neg(self) -> Self::Output {
        Self {
            v: [-self.v[0], -self.v[1]],
        }
    }
}

impl std::ops::Add for Goldilocks64Ext {
    type Output = Goldilocks64Ext;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            v: [self.v[0] + rhs.v[0], self.v[1] + rhs.v[1]],
        }
    }
}

impl std::ops::AddAssign for Goldilocks64Ext {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::Sub for Goldilocks64Ext {
    type Output = Goldilocks64Ext;
    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            v: [self.v[0] - rhs.v[0], self.v[1] - rhs.v[1]],
        }
    }
}

impl std::ops::SubAssign for Goldilocks64Ext {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl std::ops::Mul for Goldilocks64Ext {
    type Output = Goldilocks64Ext;
    fn mul(self, rhs: Self) -> Self::Output {
        let a = self.v[1];
        let b = self.v[0];
        let c = rhs.v[1];
        let d = rhs.v[0];
        Goldilocks64Ext {
            v: [b * d + a * c * 7u32.into(), b * c + a * d],
        }
    }
}

impl std::ops::MulAssign for Goldilocks64Ext {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl From<u32> for Goldilocks64Ext {
    fn from(value: u32) -> Self {
        Goldilocks64Ext {
            v: [value.into(), Goldilocks64::zero()],
        }
    }
}

impl From<Goldilocks64> for Goldilocks64Ext {
    fn from(value: Goldilocks64) -> Self {
        Goldilocks64Ext {
            v: [value, Goldilocks64::zero()],
        }
    }
}

impl From<u64> for Goldilocks64Ext {
    fn from(value: u64) -> Self {
        Goldilocks64Ext {
            v: [value.into(), Goldilocks64::zero()],
        }
    }
}

impl Field for Goldilocks64Ext {
    const NAME: &'static str = "Goldilocks64Ext";
    const SIZE: usize = 16;
    const INV_2: Self = Goldilocks64Ext {
        v: [Goldilocks64 { v: (MOD + 1) / 2 }, Goldilocks64 { v: 0 }],
    };
    type BaseField = Goldilocks64;

    fn zero() -> Self {
        Goldilocks64Ext {
            v: [Goldilocks64::zero(), Goldilocks64::zero()],
        }
    }

    fn is_zero(&self) -> bool {
        self.v[0].is_zero() && self.v[1].is_zero()
    }

    fn one() -> Self {
        Goldilocks64Ext {
            v: [Goldilocks64::one(), Goldilocks64::zero()],
        }
    }

    fn double(&self) -> Self {
        self.clone() + self.clone()
    }

    fn square(&self) -> Self {
        self.clone() * self.clone()
    }

    fn random(mut rng: impl rand::RngCore) -> Self {
        Goldilocks64Ext {
            v: [rng.next_u64().into(), rng.next_u64().into()],
        }
    }

    fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(
            self.exp(MOD as usize - 1).exp(MOD as usize - 1)
                * self.exp(MOD as usize - 1)
                * self.exp(MOD as usize - 2),
        )
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
        Goldilocks64Ext {
            v: [self.v[0] + rhs, self.v[1]],
        }
    }

    fn add_assign_base_elem(&mut self, rhs: Self::BaseField) {
        self.v[0] += rhs;
    }

    fn mul_base_elem(&self, rhs: Self::BaseField) -> Self {
        Goldilocks64Ext {
            v: [self.v[0] * rhs, self.v[1] * rhs],
        }
    }

    fn mul_assign_base_elem(&mut self, rhs: Self::BaseField) {
        self.v[0] *= rhs;
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let ptr = bytes.as_ptr() as *const u64;
        let v0 = unsafe { ptr.read_unaligned() } as u64;
        let ptr = bytes[8..].as_ptr() as *const u64;
        let v1 = unsafe { ptr.read_unaligned() } as u64;
        Goldilocks64Ext {
            v: [v0.into(), v1.into()],
        }
    }

    fn serialize_into(&self, buffer: &mut [u8]) {
        buffer[..Self::SIZE].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&self.v as *const Goldilocks64 as *const u8, Self::SIZE)
        })
    }

    fn deserialize_from(buffer: &[u8]) -> Self {
        let ptr = buffer.as_ptr() as *const u64;
        let v0 = unsafe { ptr.read_unaligned() };
        assert!(v0 < MOD);
        let ptr = buffer[8..].as_ptr() as *const u64;
        let v1 = unsafe { ptr.read_unaligned() };
        assert!(v1 < MOD);
        Goldilocks64Ext {
            v: [Goldilocks64 { v: v0 }, Goldilocks64 { v: v1 }],
        }
    }
}

impl FftField for Goldilocks64Ext {
    const LOG_ORDER: u32 = 32;
    const ROOT_OF_UNITY: Self = Goldilocks64Ext {
        v: [
            Goldilocks64 {
                v: 2741030659394132017,
            },
            Goldilocks64 { v: 0 },
        ],
    };
    type FftBaseField = Goldilocks64;
}
