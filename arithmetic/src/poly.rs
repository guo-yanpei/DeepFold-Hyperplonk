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

    pub fn new_eq(r: Vec<F>) -> MultiLinearPoly<F> {
        let mut evals = vec![F::one()];
        for &b in r.iter().rev() {
            evals = evals
                .iter()
                .flat_map(|&prod| [prod * (F::one() - b), prod * b])
                .collect();
        }
        MultiLinearPoly { evals }
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

    pub fn eval_multilinear_ext(
        evals: &Vec<F>,
        point: &[F],
    ) -> F {
        let mut scratch = evals.to_vec();
        let mut cur_eval_size = evals.len() >> 1;
        for r in point.iter() {
            for i in 0..cur_eval_size {
                scratch[i] = scratch[i * 2] + (scratch[i * 2 + 1] - scratch[i * 2]) * (*r);
            }
            cur_eval_size >>= 1;
        }
        scratch[0]
    }
}
