use std::marker::PhantomData;

use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{PolyCommitProver, PolyCommitVerifier};

use crate::{prover::ProverKey, verifier::VerifierKey};

// the circuit gate is (1 - s(X)) * (a(X) + b(X)) + s(X) * a(X) * b(X) + c(X) = 0
// the first m elements in a(X) are public inputs
pub struct Circuit<F: Field> {
    pub permutation: [Vec<F::BaseField>; 3],
    pub selector: Vec<F::BaseField>,
}

impl<F: Field> Circuit<F> {
    pub fn setup<
        PcProver: PolyCommitProver<F>,
        PcVerifier: PolyCommitVerifier<F, Commitment = PcProver::Commitment>,
    >(
        &self,
        pp: &PcProver::Param,
        vp: &PcVerifier::Param,
    ) -> (ProverKey<F, PcProver>, VerifierKey<F, PcVerifier>) {
        let pc_prover = PcProver::new(
            pp,
            &[
                self.selector.clone(),
                self.permutation[0].clone(),
                self.permutation[1].clone(),
                self.permutation[2].clone(),
            ],
        );
        (
            ProverKey {
                selector: MultiLinearPoly::new(self.selector.clone()),
                commitments: pc_prover.clone(),
                permutation: self.permutation.clone().map(|x| MultiLinearPoly::new(x)),
            },
            VerifierKey {
                commitment: PcVerifier::new(vp, pc_prover.commit(), 4),
                _data: PhantomData::default(),
            },
        )
    }
}
