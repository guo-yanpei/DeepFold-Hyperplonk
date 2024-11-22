use std::marker::PhantomData;

use arithmetic::{field::Field, poly::MultiLinearPoly};
use util::fiat_shamir::{Proof, Transcript};

use crate::{CommitmentSerde, PolyCommitProver, PolyCommitVerifier};

#[derive(Debug, Clone, Default)]
pub struct NilCommitment<F: Field>(PhantomData<F>);

impl<F: Field> CommitmentSerde for NilCommitment<F> {
    fn size(nv: usize, np: usize) -> usize {
        0
    }

    fn serialize_into(&self, buffer: &mut [u8]) {}

    fn deserialize_from(proof: &mut Proof, var_num: usize, poly_num: usize) -> Self {
        NilCommitment::default()
    }
}

#[derive(Debug, Clone)]
pub struct NilPcProver<F: Field> {
    evals: Vec<Vec<F::BaseField>>,
}

impl<F: Field> PolyCommitProver<F> for NilPcProver<F> {
    type Param = ();
    type Commitment = NilCommitment<F>;

    fn new(_pp: &(), evals: &[Vec<F::BaseField>]) -> Self {
        NilPcProver {
            evals: evals.iter().map(|x| x.clone()).collect(),
        }
    }

    fn commit(&self) -> Self::Commitment {
        NilCommitment::default()
    }

    fn open(
        _pp: &Self::Param,
        provers: Vec<&Self>,
        mut point: Vec<F>,
        transcript: &mut Transcript,
    ) {
    }
}

#[derive(Debug, Clone)]
pub struct NilPcVerifier<F: Field> {
    commit: NilCommitment<F>,
}

impl<F: Field> PolyCommitVerifier<F> for NilPcVerifier<F> {
    type Param = ();
    type Commitment = NilCommitment<F>;

    fn new(_pp: &Self::Param, commit: Self::Commitment, poly_num: usize) -> Self {
        NilPcVerifier { commit }
    }

    fn verify(
        _pp: &Self::Param,
        verifiers: Vec<&Self>,
        point: Vec<F>,
        mut evals: Vec<Vec<F>>,
        transcript: &mut Transcript,
        proof: &mut Proof,
    ) -> bool {
        true
    }
}
