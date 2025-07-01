use std::marker::PhantomData;

use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::{PolyCommitProver, PolyCommitVerifier};
use seal_fhe::{BFVEncoder, Context, EncryptionParameters, Plaintext};

use crate::{prover::ProverKey, verifier::VerifierKey};

type F = Plaintext;

// the circuit gate is (1 - s(X)) * (a(X) + b(X)) + s(X) * a(X) * b(X) + c(X) = 0
// the first m elements in a(X) are public inputs
pub struct Circuit {
    pub permutation: [Vec<F>; 3],
    pub selector: Vec<F>,
}

impl<'a> Circuit {
    pub fn setup<
        PcProver: PolyCommitProver,
        PcVerifier: PolyCommitVerifier<Commitment = PcProver::Commitment>,
    >(
        &self,
        pp: &PcProver::Param,
        vp: &PcVerifier::Param,
        params: &'a EncryptionParameters,
        ctx: &'a Context,
    ) -> (ProverKey<'a, PcProver>, VerifierKey<PcVerifier>) {
        let pc_prover = PcProver::new(
            pp,
            &[
                self.selector.clone(),
                self.permutation[0].clone(),
                self.permutation[1].clone(),
                self.permutation[2].clone(),
            ],
        );

        let encoder = BFVEncoder::new(ctx, params).unwrap();
        (
            ProverKey {
                selector: MultiLinearPoly::new(self.selector.clone(), &params, &ctx),
                commitments: pc_prover.clone(),
                permutation: self.permutation.clone().map(|x| MultiLinearPoly::new(x, &params, &ctx)),
            },
            VerifierKey {
                commitment: PcVerifier::new(vp, pc_prover.commit(), 4),
            },
        )
    }
}
