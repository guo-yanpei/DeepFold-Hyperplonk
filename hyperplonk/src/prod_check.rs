use arithmetic::{field::Field, poly::MultiLinearPoly};
use util::fiat_shamir::{Proof, Transcript};

use crate::sumcheck::Sumcheck;

pub struct ProdCheck;

impl ProdCheck {
    fn prove<F: Field>(evals: Vec<F>, transcript: &mut Transcript) -> Vec<F> {
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
            let (mut new_point, v) = Sumcheck::prove([evals_0, evals_1, eq.evals], 3, transcript, |v: [F; 3]| {
                v[0] * v[1] * v[2]
            });
            transcript.append_f(v[0]);
            transcript.append_f(v[1]);
            let r = transcript.challenge_f();
            point = vec![r];
            point.append(&mut new_point);
        }
        point
    }

    fn verify<F: Field>(mut y: F, var_num: usize, transcript: &mut Transcript, proof: &mut Proof) {}
}
