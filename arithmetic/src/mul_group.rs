use std::rc::Rc;

use crate::field::FftField;

#[derive(Debug, Clone)]
pub struct Radix2Group<F: FftField> {
    log_order: u32,
    omega: F,
    elements: Rc<Vec<F>>,
}

impl<F: FftField> Radix2Group<F> {
    pub fn new(log_order: u32) -> Self {
        let omega = F::ROOT_OF_UNITY.exp(1usize << (F::LOG_ORDER - log_order));
        let elements = std::iter::successors(Some(F::one()), |&last| Some(last * omega))
            .take(1 << log_order)
            .collect();
        Radix2Group {
            log_order,
            omega,
            elements: Rc::new(elements),
        }
    }

    pub fn size(&self) -> usize {
        1 << self.log_order
    }

    pub fn element_at(&self, index: usize) -> F {
        self.elements[index]
    }

    pub fn element_inv_at(&self, index: usize) -> F {
        if index == 0 {
            F::one()
        } else {
            self.elements[self.size() - index]
        }
    }

    pub fn exp(&self, index: usize) -> Radix2Group<F> {
        assert_eq!(index & (index - 1), 0);
        Radix2Group::new(self.log_order - index.ilog2())
    }

    fn batch_bit_reverse(log_n: usize) -> Vec<usize> {
        let n = 1 << log_n;
        let mut res = (0..n).into_iter().map(|_| 0).collect::<Vec<usize>>();
        for i in 0..n {
            res[i] = (res[i >> 1] >> 1) | ((i & 1) << (log_n - 1));
        }
        res
    }

    fn _fft(coeff: &mut Vec<F>, omega: F) {
        let n = coeff.len();
        let log_n = n.ilog2() as usize;
        let rank = Self::batch_bit_reverse(log_n);
        for i in 0..n {
            if i < rank[i] {
                (coeff[i], coeff[rank[i]]) = (coeff[rank[i]], coeff[i]);
            }
        }
        let mut log_m = 0usize;
        for _i in 0..log_n {
            let w_m = omega.exp(n >> (log_m + 1));
            let m = 1 << log_m;
            for j in (0..n).step_by(m * 2) {
                let mut w = F::from(1);
                for k in 0..m {
                    let t = w * coeff[j + k + m];
                    coeff[j + k + m] = coeff[j + k] - t;
                    coeff[j + k] += t;
                    w *= w_m;
                }
            }
            log_m += 1;
        }
    }

    pub fn fft(&self, coeff: Vec<F::BaseField>) -> Vec<F> {
        let mut coeff = coeff.into_iter().map(|x| F::from(x)).collect::<Vec<_>>();
        let padding_zero = self.size() - coeff.len();
        for _ in 0..padding_zero {
            coeff.push(F::zero());
        }
        Self::_fft(&mut coeff, self.omega);
        coeff
    }

    pub fn ifft(&self, mut evals: Vec<F>) -> Vec<F> {
        assert_eq!(self.size(), evals.len());
        Self::_fft(&mut evals, self.omega.exp((1 << self.size()) - 1));
        let t = F::from(self.size() as u32).inv().unwrap();
        evals.iter_mut().for_each(|x| *x *= t);
        evals
    }
}

#[cfg(test)]
mod tests {

    use crate::field::{goldilocks64::Goldilocks64, Field};

    use super::*;
    #[test]
    fn fft_and_ifft() {
        let mut a = vec![];
        let mut b = vec![];
        let mut rng = rand::thread_rng();
        for _i in 0..16 {
            a.push(Goldilocks64::random(&mut rng));
            b.push(Goldilocks64::random(&mut rng));
        }
        for _i in 16..32 {
            a.push(Goldilocks64::zero());
            b.push(Goldilocks64::zero());
        }
        let mul_group = Radix2Group::new(5);
        let mut fft_a = mul_group.fft(a.clone());
        let fft_b = mul_group.fft(b.clone());
        for i in 0..fft_a.len() {
            fft_a[i] *= fft_b[i];
        }
        let fft_a_times_b = mul_group.ifft(fft_a);
        let mut a_times_b = vec![];
        for _i in 0..32 {
            a_times_b.push(Goldilocks64::zero());
        }
        for i in 0..16usize {
            for j in 0..16usize {
                a_times_b[i + j] += a[i] * b[j];
            }
        }
        assert_eq!(fft_a_times_b, a_times_b);
        let b = mul_group.fft(a.clone());
        let c = mul_group.ifft(b);
        assert_eq!(a, c);
    }

    #[test]
    fn elements() {
        let coset = Radix2Group::<Goldilocks64>::new(5);
        assert_eq!(coset.element_at(0), Goldilocks64::one());
        assert_eq!(coset.element_inv_at(0), Goldilocks64::one());
        let omega = coset.omega;
        for i in 0..30 {
            assert_eq!(coset.element_at(i) * omega, coset.element_at(i + 1));
            assert_eq!(
                coset.element_inv_at(i) * omega.inv().unwrap(),
                coset.element_inv_at(i + 1)
            );
        }
    }

    #[test]
    fn exp() {
        let coset = Radix2Group::<Goldilocks64>::new(5);
        let coset_square = coset.exp(2);
        for (idx, i) in coset_square.elements.iter().enumerate() {
            assert_eq!(*i, coset.element_at(idx).exp(2));
            assert_eq!(*i, coset.element_at(idx + coset_square.size()).exp(2));
        }
    }
}
