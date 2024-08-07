use arithmetic::{field::Field, poly::MultiLinearPoly};
use util::fiat_shamir::{Proof, Transcript};

use crate::{CommitmentSerde, PolyCommitProver, PolyCommitVerifier};

#[derive(Debug, Clone, Default)]
pub struct RawCommitment<F: Field> {
    pub poly_evals: Vec<F::BaseField>,
}

impl<F: Field> CommitmentSerde for RawCommitment<F> {
    fn size(&self) -> usize {
        self.poly_evals.len() * F::SIZE
    }
    fn serialize_into(&self, buffer: &mut [u8]) {
        self.poly_evals.iter().enumerate().for_each(|(i, v)| {
            v.serialize_into(&mut buffer[i * F::BaseField::SIZE..(i + 1) * F::BaseField::SIZE])
        });
    }
    fn deserialize_from(buffer: &[u8], var_num: usize) -> Self {
        let mut poly_evals = Vec::new();
        for i in 0..(1 << var_num) {
            poly_evals.push(F::BaseField::deserialize_from(
                &buffer[i * F::BaseField::SIZE..(i + 1) * F::BaseField::SIZE],
            ));
        }
        RawCommitment { poly_evals }
    }
}

pub struct ShufflePcProver<F: Field> {
    evals: Vec<F::BaseField>,
}

impl<F: Field> PolyCommitProver<F> for ShufflePcProver<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;

    fn new(_pp: &(), evals: &Vec<F::BaseField>) -> Self {
        ShufflePcProver { evals: evals.clone() }
    }

    fn commit(&self) -> Self::Commitment {
        RawCommitment {
            poly_evals: self.evals.clone(),
        }
    }

    fn open(&self, _pp: &(), point: &[F], transcript: &mut Transcript) {
        let mut new_point = point.to_vec();
        new_point[0].add_assign_base_elem(F::BaseField::one());
        transcript.append_f(MultiLinearPoly::eval_multilinear(
            &self.evals,
            &new_point,
        ));
        let r = transcript.challenge_f::<F>();
        let new_len = self.evals.len() / 2;
        let mut poly_evals = vec![];
        for i in 0..new_len {
            poly_evals.push(
                r.mul_base_elem(self.evals[i * 2 + 1] - self.evals[i * 2])
                    .add_base_elem(self.evals[i * 2]),
            );
        }
        for i in 1..point.len() {
            let mut new_point = point[i..].to_vec();
            new_point[0].add_assign_base_elem(F::BaseField::one());
            transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
                &poly_evals,
                &new_point,
            ));
            let r = transcript.challenge_f();
            let new_len = poly_evals.len() / 2;
            for j in 0..new_len {
                poly_evals[j] = poly_evals[j * 2] + (poly_evals[j * 2 + 1] - poly_evals[j * 2]) * r;
            }
            poly_evals.truncate(new_len);
        }
    }
}

pub struct ShufflePcVerifier<F: Field> {
    commit: RawCommitment<F>,
}

impl<F: Field> PolyCommitVerifier<F> for ShufflePcVerifier<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;

    fn new(_pp: &Self::Param, commit: Self::Commitment) -> Self {
        ShufflePcVerifier { commit }
    }

    fn verify(
        &self,
        _pp: &(),
        point: &[F],
        eval: F,
        transcript: &mut Transcript,
        proof: &mut Proof,
    ) -> bool {
        let mut eval = eval;
        let mut new_point = vec![];
        for i in 0..point.len() {
            let next_eval = proof.get_next_and_step::<F>();
            transcript.append_f(next_eval);
            let r = transcript.challenge_f::<F>();

            eval += (r - point[i]) * (next_eval - eval);
            new_point.push(r);
        }
        eval == MultiLinearPoly::eval_multilinear(&self.commit.poly_evals, &new_point)
    }
}
