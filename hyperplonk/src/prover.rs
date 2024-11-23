use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{CommitmentSerde, PolyCommitProver};
use util::fiat_shamir::{Proof, Transcript};

use crate::{prod_eq_check::ProdEqCheck, sumcheck::Sumcheck};

pub struct ProverKey<F: Field, PC: PolyCommitProver<F>> {
    pub selector: MultiLinearPoly<F::BaseField>,
    pub commitments: PC,
    pub permutation: [MultiLinearPoly<F::BaseField>; 3],
}

pub struct Prover<F: Field, PC: PolyCommitProver<F>> {
    pub prover_key: ProverKey<F, PC>,
}

impl<F: Field, PC: PolyCommitProver<F>> Prover<F, PC> {
    pub fn prove(&self, pp: &PC::Param, nv: usize, witness: [Vec<F::BaseField>; 3]) -> Proof {
        let mut transcript = Transcript::new();
        let witness_pc = PC::new(pp, &witness);

        let commit = witness_pc.commit();
        let mut buffer = vec![0u8; PC::Commitment::size(nv, 3)];
        commit.serialize_into(&mut buffer);
        transcript.append_u8_slice(&buffer, PC::Commitment::size(nv, 3));

        let bookkeeping = witness
            .clone()
            .map(|x| x.into_iter().map(|i| F::from(i)).collect::<Vec<_>>());


        let r = (0..nv)
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
            |v: [F; 5]| [v[4] * ((F::one() - v[0]) * (v[1] + v[2]) + v[0] * v[1] * v[2] + v[3])],
        );

        for i in 0..4 {
            transcript.append_f(v[i]);
        }
        let witness_flatten = bookkeeping[0]
            .clone()
            .into_iter()
            .chain(bookkeeping[1].clone().into_iter())
            .chain(bookkeeping[2].clone().into_iter())
            .chain((0..(1 << nv)).into_iter().map(|_| F::zero()))
            .collect::<Vec<_>>();
        let identical = MultiLinearPoly::new_identical(nv, F::BaseField::zero())
            .evals
            .into_iter()
            .chain(
                MultiLinearPoly::new_identical(nv, F::BaseField::from(1 << 29))
                    .evals
                    .into_iter(),
            )
            .chain(
                MultiLinearPoly::new_identical(nv, F::BaseField::from(1 << 30))
                    .evals
                    .into_iter(),
            )
            .chain((0..(1 << nv)).into_iter().map(|_| F::BaseField::zero()))
            .collect::<Vec<_>>();
        let permutation = self.prover_key.permutation[0]
            .clone()
            .evals
            .into_iter()
            .chain(self.prover_key.permutation[1].clone().evals.into_iter())
            .chain(self.prover_key.permutation[2].clone().evals.into_iter())
            .chain((0..(1 << nv)).into_iter().map(|_| F::BaseField::zero()))
            .collect::<Vec<_>>();

        let r = [0; 2].map(|_| transcript.challenge_f::<F>());

        let evals1 = witness_flatten
            .iter()
            .zip(identical.iter())
            .map(|(&x, &y)| r[0] + x + r[1].mul_base_elem(y))
            .collect::<Vec<_>>();
        let evals2 = witness_flatten
            .iter()
            .zip(permutation.iter())
            .map(|(&x, &y)| r[0] + x + r[1].mul_base_elem(y))
            .collect::<Vec<_>>();
        let prod_point = ProdEqCheck::prove([evals1, evals2], &mut transcript);

        for i in 0..3 {
            transcript.append_f(MultiLinearPoly::eval_multilinear(
                &witness[i],
                &prod_point[..nv],
            ));
        }
        for i in 0..3 {
            transcript.append_f(MultiLinearPoly::eval_multilinear(
                &self.prover_key.permutation[i].evals,
                &prod_point[..nv],
            ));
        }

        let r: F = transcript.challenge_f();
        let r2 = r * r;
        let r3 = r2 * r;
        let r4 = r3 * r;
        let r5 = r4 * r;
        let (point, _) = Sumcheck::prove(
            [
                self.prover_key
                    .selector
                    .evals
                    .iter()
                    .zip(witness[0].iter())
                    .zip(witness[1].iter())
                    .zip(witness[2].iter())
                    .map(|(((&x1, &x2), &x3), &x4)| {
                        F::from(x1)
                            + r.mul_base_elem(x2)
                            + r2.mul_base_elem(x3)
                            + r3.mul_base_elem(x4)
                    })
                    .collect(),
                self.prover_key.permutation[0]
                    .evals
                    .iter()
                    .zip(self.prover_key.permutation[1].evals.iter())
                    .zip(self.prover_key.permutation[2].evals.iter())
                    .zip(witness[0].iter())
                    .zip(witness[1].iter())
                    .zip(witness[2].iter())
                    .map(|(((((&x1, &x2), &x3), &x4), &x5), &x6)| {
                        F::from(x1)
                            + r.mul_base_elem(x2)
                            + r2.mul_base_elem(x3)
                            + r3.mul_base_elem(x4)
                            + r4.mul_base_elem(x5)
                            + r5.mul_base_elem(x6)
                    })
                    .collect(),
                MultiLinearPoly::new_eq(&sumcheck_point).evals,
                MultiLinearPoly::new_eq(&prod_point[..nv].to_vec()).evals,
            ],
            2,
            &mut transcript,
            |v: [F; 4]| [v[0] * v[2], v[1] * v[3]],
        );

        transcript.append_f(MultiLinearPoly::eval_multilinear(
            &self.prover_key.selector.evals,
            &point,
        ));
        for i in 0..3 {
            transcript.append_f(MultiLinearPoly::eval_multilinear(
                &self.prover_key.permutation[i].evals,
                &point,
            ));
        }
        for i in 0..3 {
            transcript.append_f(MultiLinearPoly::eval_multilinear(&witness[i], &point));
        }

        PC::open(
            pp,
            vec![&self.prover_key.commitments, &witness_pc],
            point,
            &mut transcript,
        );

        transcript.proof
    }
}
