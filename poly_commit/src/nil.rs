use std::marker::PhantomData;

use arithmetic::{field::Field, poly::MultiLinearPoly};
use seal_fhe::Plaintext;
use util::fiat_shamir::{Proof, Transcript};

use crate::{CommitmentSerde, PolyCommitProver, PolyCommitVerifier};

#[derive(Debug, Clone, Default)]
pub struct NilCommitment(PhantomData<F>);

type F = Plaintext;

impl CommitmentSerde for NilCommitment {
    fn size(nv: usize, np: usize) -> usize {
        0
    }

    fn serialize_into(&self, buffer: &mut [u8]) {}

    fn deserialize_from(proof: &mut Proof, var_num: usize, poly_num: usize) -> Self {
        NilCommitment::default()
    }
}

#[derive(Debug, Clone)]
pub struct NilPcProver {
    evals: Vec<Vec<F>>,
}

impl PolyCommitProver for NilPcProver {
    type Param = ();
    type Commitment = NilCommitment;

    fn new(_pp: &(), evals: &[Vec<F>]) -> Self {
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
pub struct NilPcVerifier {
    commit: NilCommitment,
}

impl PolyCommitVerifier for NilPcVerifier {
    type Param = ();
    type Commitment = NilCommitment;

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
