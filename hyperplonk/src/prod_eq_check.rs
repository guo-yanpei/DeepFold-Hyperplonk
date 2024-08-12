use arithmetic::{field::Field, poly::MultiLinearPoly};
use util::fiat_shamir::{Proof, Transcript};

use crate::sumcheck::Sumcheck;

pub struct ProdEqCheck;

impl ProdEqCheck {
    pub fn prove<F: Field>(evals: [Vec<F>; 2], transcript: &mut Transcript) -> Vec<F> {
        let var_num = evals[0].len().ilog2() as usize;
        let mut products = evals.map(|x| vec![x]);
        for i in 0..2 {
            for j in 1..var_num {
                let last_prod = &products[i][j - 1];
                let mut evals = vec![];
                let m = 1 << (var_num - j);
                for k in 0..m {
                    evals.push(last_prod[k * 2] * last_prod[k * 2 + 1]);
                }
                products[i].push(evals);
            }
            transcript.append_f(products[i][var_num - 1][0]);
            transcript.append_f(products[i][var_num - 1][1]);
        }
        let mut point = vec![transcript.challenge_f::<F>()];
        for i in (0..var_num - 1).rev() {
            let eq = MultiLinearPoly::new_eq(&point);
            let mut evals_00 = vec![];
            let mut evals_01 = vec![];
            for j in products[0][i].iter().enumerate() {
                if j.0 % 2 == 0 {
                    evals_00.push(*j.1);
                } else {
                    evals_01.push(*j.1);
                }
            }
            let mut evals_10 = vec![];
            let mut evals_11 = vec![];
            for j in products[1][i].iter().enumerate() {
                if j.0 % 2 == 0 {
                    evals_10.push(*j.1);
                } else {
                    evals_11.push(*j.1);
                }
            }

            let (mut new_point, v) = Sumcheck::prove(
                [evals_00, evals_01, evals_10, evals_11, eq.evals],
                3,
                transcript,
                |v: [F; 5]| [v[0] * v[1] * v[4], v[2] * v[3] * v[4]],
            );
            for j in 0..4 {
                transcript.append_f(v[j]);
            }
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
    ) -> (Vec<F>, [F; 2]) {
        let mut v0: F = proof.get_next_and_step();
        let mut v1: F = proof.get_next_and_step();
        let mut v2: F = proof.get_next_and_step();
        let mut v3: F = proof.get_next_and_step();
        assert_eq!(v0 * v1, v2 * v3);
        transcript.append_f(v0);
        transcript.append_f(v1);
        transcript.append_f(v2);
        transcript.append_f(v3);
        let mut point = vec![transcript.challenge_f::<F>()];
        let mut y = [v0 + (v1 - v0) * point[0], v2 + (v3 - v2) * point[0]];
        for i in 1..var_num {
            let (mut new_point, new_y) = Sumcheck::verify(y, 3, i, transcript, proof);
            v0 = proof.get_next_and_step();
            v1 = proof.get_next_and_step();
            assert_eq!(
                v0 * v1 * MultiLinearPoly::eval_eq(&new_point, &point),
                new_y[0]
            );
            transcript.append_f(v0);
            transcript.append_f(v1);
            v2 = proof.get_next_and_step();
            v3 = proof.get_next_and_step();
            assert_eq!(
                v2 * v3 * MultiLinearPoly::eval_eq(&new_point, &point),
                new_y[1]
            );
            transcript.append_f(v2);
            transcript.append_f(v3);
            let r = transcript.challenge_f();
            point = vec![r];
            point.append(&mut new_point);
            y = [v0 + (v1 - v0) * r, v2 + (v3 - v2) * r];
        }
        (point, y)
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

    use super::ProdEqCheck;

    #[test]
    fn prod_check() {
        let mut transcript = Transcript::new();
        let mut rng = thread_rng();
        let evals = (0..4096)
            .map(|_| Goldilocks64Ext::random(&mut rng))
            .collect::<Vec<_>>();
        let evals_rev = evals.clone().into_iter().rev().collect::<Vec<_>>();
        let point = ProdEqCheck::prove([evals.clone(), evals_rev.clone()], &mut transcript);
        let mut proof = transcript.proof;

        let mut transcript = Transcript::new();
        let (new_point, y) = ProdEqCheck::verify(12, &mut transcript, &mut proof);
        assert_eq!(MultiLinearPoly::eval_multilinear_ext(&evals, &point), y[0]);
        assert_eq!(
            MultiLinearPoly::eval_multilinear_ext(&evals_rev, &new_point),
            y[1]
        );
    }
}
