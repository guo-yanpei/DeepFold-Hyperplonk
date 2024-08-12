use arithmetic::{field::Field, poly::MultiLinearPoly};
use util::fiat_shamir::{Proof, Transcript};

use crate::sumcheck::Sumcheck;

pub struct ProdCheck;

impl ProdCheck {
    pub fn prove<F: Field>(evals: Vec<F>, transcript: &mut Transcript) -> Vec<F> {
        assert_eq!(evals.len() & (evals.len() - 1), 0);
        let var_num = evals.len().ilog2() as usize;
        let mut products = vec![evals];
        for i in 1..var_num {
            let last_prod = &products[i - 1];
            let mut evals = vec![];
            let m = 1 << (var_num - i);
            for j in 0..m {
                evals.push(last_prod[j * 2] * last_prod[j * 2 + 1]);
            }
            products.push(evals);
        }
        transcript.append_f(products[var_num - 1][0]);
        transcript.append_f(products[var_num - 1][1]);
        let mut point = vec![transcript.challenge_f::<F>()];
        for i in (0..var_num - 1).rev() {
            let eq = MultiLinearPoly::new_eq(&point);
            let mut evals_0 = vec![];
            let mut evals_1 = vec![];
            for j in 0..products[i].len() {
                if j % 2 == 0 {
                    evals_0.push(products[i][j]);
                } else {
                    evals_1.push(products[i][j]);
                }
            }
            let (mut new_point, v) =
                Sumcheck::prove([evals_0, evals_1, eq.evals], 3, transcript, |v: [F; 3]| {
                    [v[0] * v[1] * v[2]]
                });
            transcript.append_f(v[0]);
            transcript.append_f(v[1]);
            let r = transcript.challenge_f();
            point = vec![r];
            point.append(&mut new_point);
        }
        point
    }

    pub fn verify<F: Field>(
        var_num: usize,
        transcript: &mut Transcript,
        proof: &mut Proof,
    ) -> (F, Vec<F>, F) {
        let mut v0: F = proof.get_next_and_step();
        let mut v1: F = proof.get_next_and_step();
        let prod = v0 * v1;
        transcript.append_f(v0);
        transcript.append_f(v1);
        let mut point = vec![transcript.challenge_f::<F>()];
        let mut y = v0 + (v1 - v0) * point[0];
        for i in 1..var_num {
            let (mut new_point, new_y) = Sumcheck::verify([y], 3, i, transcript, proof);
            v0 = proof.get_next_and_step();
            v1 = proof.get_next_and_step();
            assert_eq!(
                v0 * v1 * MultiLinearPoly::eval_eq(&new_point, &point),
                new_y[0]
            );
            transcript.append_f(v0);
            transcript.append_f(v1);
            let r = transcript.challenge_f();
            point = vec![r];
            point.append(&mut new_point);
            y = v0 + (v1 - v0) * r;
        }
        (prod, point, y)
    }
}

#[cfg(test)]
mod tests {
    use arithmetic::{
        field::{goldilocks64::Goldilocks64Ext, Field},
        poly::MultiLinearPoly,
    };
    use rand::thread_rng;
    use util::fiat_shamir::Transcript;

    use super::ProdCheck;

    #[test]
    fn prod_check() {
        let mut transcript = Transcript::new();
        let mut rng = thread_rng();
        let evals = (0..4096)
            .map(|_| Goldilocks64Ext::random(&mut rng))
            .collect::<Vec<_>>();
        let prod = evals
            .iter()
            .fold(Goldilocks64Ext::one(), |acc, x| acc * x.clone());
        let point = ProdCheck::prove(evals.clone(), &mut transcript);
        let mut proof = transcript.proof;

        let mut transcript = Transcript::new();
        let (res, new_point, y) = ProdCheck::verify(12, &mut transcript, &mut proof);
        assert_eq!(res, prod);
        assert_eq!(point, new_point);
        assert_eq!(MultiLinearPoly::eval_multilinear_ext(&evals, &point), y);
    }
}
