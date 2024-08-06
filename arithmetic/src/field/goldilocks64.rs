#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Goldilocks64 {
    v: u64,
}
static MOD: u64 = 18446744069414584321u64; // 2**64 - 2**32 + 1
static HIGH: u128 = (1u128 << 127) - (1u128 << 96) + (1u128 << 127);
static MIDDLE: u128 = (1u128 << 96) - (1u128 << 64);
static LOW: u128 = (1u128 << 64) - 1;

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

use super::{FftField, Field};
use rand::Rng;

impl Field for Goldilocks64 {
    const NAME: &'static str = "Goldilocks64";
    const SIZE: usize = 8;
    const INV_2: Self = Goldilocks64 { v: (MOD + 1) / 2 };

    fn is_zero(&self) -> bool {
        self.v == 0
    }
}

impl FftField for Goldilocks64 {
    const LOG_ORDER: u32 = 32;
    const ROOT_OF_UNITY: Self = Goldilocks64 {
        v: 2741030659394132017u64,
    };
}
