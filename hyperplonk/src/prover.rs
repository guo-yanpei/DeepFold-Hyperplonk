use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{CommitmentSerde, PolyCommitProver};
use util::fiat_shamir::{Proof, Transcript};

use crate::{prod_check::ProdCheck, sumcheck::Sumcheck};

pub struct ProverKey<F: Field, PC: PolyCommitProver<F>> {
    pub selector: MultiLinearPoly<F::BaseField>,
    pub selector_commitments: PC,
    pub permutation: [MultiLinearPoly<F::BaseField>; 3],
    pub permutation_commitments: [PC; 3],
}

pub struct Prover<F: Field, PC: PolyCommitProver<F>> {
    pub prover_key: ProverKey<F, PC>,
}

impl<F: Field, PC: PolyCommitProver<F>> Prover<F, PC> {
    pub fn prove(&self, pp: &PC::Param, witness: [Vec<F::BaseField>; 3]) -> Proof {
        let mut transcript = Transcript::new();
        let pc_provers = witness.clone().map(|x| PC::new(pp, &x));

        for i in 0..3 {
            let commit = pc_provers[i].commit();
            let mut buffer = vec![0u8; commit.size()];
            commit.serialize_into(&mut buffer);
            transcript.append_u8_slice(&buffer, commit.size());
        }

        let bookkeeping = witness
            .clone()
            .map(|x| x.into_iter().map(|i| F::from(i)).collect::<Vec<_>>());

        let r = (0..12)
            .map(|_| transcript.challenge_f::<F>())
            .collect::<Vec<_>>();
        let eq_r = MultiLinearPoly::new_eq(&r);
        let (sumcheck_point, v) = Sumcheck::prove(
            [
                self.prover_key
                    .selector
                    .evals
                    .iter()
                    .map(|x| F::from(*x))
                    .collect(),
                bookkeeping[0].clone(),
                bookkeeping[1].clone(),
                bookkeeping[2].clone(),
                eq_r.evals.clone(),
            ],
            4,
            &mut transcript,
            |v: [F; 5]| v[4] * ((F::one() - v[0]) * (v[1] + v[2]) + v[0] * v[1] * v[2] + v[3]),
        );

        transcript.append_f(v[0]);
        transcript.append_f(v[1]);
        transcript.append_f(v[2]);
        transcript.append_f(v[3]);

        let r_1: F = transcript.challenge_f();
        let r_2: F = transcript.challenge_f();

        let identical = [
            MultiLinearPoly::new_identical(12, F::BaseField::zero()),
            MultiLinearPoly::new_identical(12, F::BaseField::from(1 << 29)),
            MultiLinearPoly::new_identical(12, F::BaseField::from(1 << 30)),
        ];

        let evals = bookkeeping[0]
            .iter()
            .zip(identical[0].evals.iter())
            .chain(bookkeeping[1].iter().zip(identical[1].evals.iter()))
            .map(|(&x, &y)| r_1 + x + r_2.mul_base_elem(y))
            .collect();
        let prod_point1 = ProdCheck::prove(evals, &mut transcript);
        let evals = bookkeeping[2]
            .iter()
            .zip(identical[2].evals.iter())
            .map(|(&x, &y)| r_1 + x + r_2.mul_base_elem(y))
            .collect();
        let prod_point2 = ProdCheck::prove(evals, &mut transcript);

        let evals = bookkeeping[0]
            .iter()
            .zip(self.prover_key.permutation[0].evals.iter())
            .chain(
                bookkeeping[1]
                    .iter()
                    .zip(self.prover_key.permutation[1].evals.iter()),
            )
            .map(|(&x, &y)| r_1 + x + r_2.mul_base_elem(y))
            .collect();
        let prod_point3 = ProdCheck::prove(evals, &mut transcript);
        let evals = bookkeeping[2]
            .iter()
            .zip(self.prover_key.permutation[2].evals.iter())
            .map(|(&x, &y)| r_1 + x + r_2.mul_base_elem(y))
            .collect();
        let prod_point4 = ProdCheck::prove(evals, &mut transcript);

        transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
            &bookkeeping[0],
            &prod_point1[..12],
        ));
        transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
            &bookkeeping[1],
            &prod_point1[..12],
        ));
        transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
            &bookkeeping[2],
            &prod_point2,
        ));
        transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
            &bookkeeping[0],
            &prod_point3[..12],
        ));
        transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
            &bookkeeping[1],
            &prod_point3[..12],
        ));
        transcript.append_f(MultiLinearPoly::eval_multilinear(
            &self.prover_key.permutation[0].evals,
            &prod_point3[..12],
        ));
        transcript.append_f(MultiLinearPoly::eval_multilinear(
            &self.prover_key.permutation[1].evals,
            &prod_point3[..12],
        ));
        transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
            &bookkeeping[2],
            &prod_point4,
        ));
        transcript.append_f(MultiLinearPoly::eval_multilinear(
            &self.prover_key.permutation[2].evals,
            &prod_point4,
        ));

        transcript.proof
    }
}
