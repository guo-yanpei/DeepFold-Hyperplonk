use crate::field::Field;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Definition for an MLE, with an associated type F.
pub struct MultiLinearPoly<F: Field> {
    pub evals: Vec<F>,
}

impl<F: Field> MultiLinearPoly<F> {
    pub fn new(evals: Vec<F>) -> MultiLinearPoly<F> {
        MultiLinearPoly { evals }
    }

    pub fn new_eq(r: &Vec<F>) -> MultiLinearPoly<F> {
        let mut evals = vec![F::one()];
        for &b in r.iter().rev() {
            evals = evals
                .iter()
                .flat_map(|&prod| [prod * (F::one() - b), prod * b])
                .collect();
        }
        MultiLinearPoly { evals }
    }

    pub fn eval_eq(r: &Vec<F>, point: &Vec<F>) -> F {
        assert_eq!(r.len(), point.len());
        let mut res = F::one();
        for i in 0..r.len() {
            let tmp = point[i] * r[i];
            res *= tmp + tmp - point[i] - r[i] + F::one();
        }
        res
    }

    pub fn new_identical(var_num: usize, offset: F) -> MultiLinearPoly<F> {
        MultiLinearPoly {
            evals: (0..(1 << var_num)).map(|x| F::from(x) + offset).collect(),
        }
    }

    pub fn eval_identical(point: &Vec<F>, offset: F) -> F {
        let mut res = offset + point[0];
        let mut t = F::BaseField::one();
        for i in 1..point.len() {
            t += t;
            res += point[i].mul_base_elem(t);
        }
        res
    }

    pub fn eval_multilinear<FEXT: Field<BaseField = F>>(evals: &Vec<F>, point: &[FEXT]) -> FEXT {
        let mut scratch = vec![];
        let mut cur_eval_size = 1 << (point.len() - 1);
        assert_eq!(cur_eval_size << 1, evals.len());
        for i in 0..cur_eval_size {
            scratch.push(
                point[0]
                    .mul_base_elem(evals[i * 2 + 1] - evals[i * 2])
                    .add_base_elem(evals[i * 2]),
            );
        }
        for r in point[1..].iter() {
            cur_eval_size >>= 1;
            for i in 0..cur_eval_size {
                scratch[i] = scratch[i * 2] + (scratch[i * 2 + 1] - scratch[i * 2]) * (*r);
            }
        }
        scratch[0]
    }

    pub fn eval_multilinear_ext(evals: &Vec<F>, point: &[F]) -> F {
        let mut scratch = evals.to_vec();
        let mut cur_eval_size = evals.len() >> 1;
        assert_eq!(1 << point.len(), evals.len());
        for r in point.iter() {
            for i in 0..cur_eval_size {
                scratch[i] = scratch[i * 2] + (scratch[i * 2 + 1] - scratch[i * 2]) * (*r);
            }
            cur_eval_size >>= 1;
        }
        scratch[0]
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::field::{bn_254::Bn254F, Field};

    use super::MultiLinearPoly;

    #[test]
    fn eq() {
        let mut rng = thread_rng();
        let r = (0..12).map(|_| Bn254F::random(&mut rng)).collect();
        let eq_r = MultiLinearPoly::new_eq(&r);
        let point = (0..12).map(|_| Bn254F::random(&mut rng)).collect();
        assert_eq!(
            MultiLinearPoly::eval_eq(&r, &point),
            MultiLinearPoly::eval_multilinear(&eq_r.evals, &point)
        );
        let identical = MultiLinearPoly::new_identical(12, Bn254F::zero());
        let r = (0..12).map(|_| Bn254F::random(&mut rng)).collect();
        assert_eq!(
            MultiLinearPoly::eval_identical(&r, Bn254F::zero()),
            MultiLinearPoly::eval_multilinear_ext(&identical.evals, &r)
        );
    }
}
