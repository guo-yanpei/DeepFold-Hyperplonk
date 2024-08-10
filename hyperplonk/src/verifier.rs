use std::marker::PhantomData;

use arithmetic::field::Field;
use poly_commit::PolyCommitVerifier;
use util::fiat_shamir::Proof;

use crate::circuit::Circuit;

pub struct VerifierKey<F: Field, PC: PolyCommitVerifier<F>> {
    pub selector_commitment: PC,
    pub permutation_commitments: [PC; 3],
    pub _data: PhantomData<F>,
}

impl<F: Field, PC: PolyCommitVerifier<F>> VerifierKey<F, PC> {
    fn new(circuit: Circuit<F>) -> Self {
        unimplemented!()
    }
}

pub struct Verifier<F: Field, PC: PolyCommitVerifier<F>> {
    pub verifier_key: VerifierKey<F, PC>,
}

impl<F: Field, PC: PolyCommitVerifier<F>> Verifier<F, PC> {
    pub fn verify(&self, proof: Proof) -> bool {
        unimplemented!()
    }
}
