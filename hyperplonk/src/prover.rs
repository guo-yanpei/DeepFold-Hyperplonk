use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{CommitmentSerde, PolyCommitProver};
use util::fiat_shamir::{Proof, Transcript};

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
        let pc_provers = witness.map(|x| PC::new(pp, &x));

        for i in 0..3 {
            let commit = pc_provers[i].commit();
            let mut buffer = vec![0u8; commit.size()];
            commit.serialize_into(&mut buffer);
            transcript.append_u8_slice(&buffer, commit.size());
        }

        let eq_r = (0..12)
            .map(|_| transcript.challenge_f::<F>())
            .collect::<Vec<_>>();
        transcript.proof
    }
}
