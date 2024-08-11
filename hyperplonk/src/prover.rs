use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{CommitmentSerde, PolyCommitProver};
use util::fiat_shamir::{Proof, Transcript};

use crate::sumcheck::Sumcheck;

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
        let (point, v) = Sumcheck::prove(
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
        


        transcript.proof
    }
}
