use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::PolyCommitProver;
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
        let x: F = transcript.challenge_f();
        transcript.proof
    }
}
