use arithmetic::{field::Field, poly::MultiLinearPoly};
use util::fiat_shamir::{Proof, Transcript};

use crate::{CommitmentSerde, PolyCommitProver, PolyCommitVerifier};

#[derive(Debug, Clone, Default)]
pub struct RawCommitment<F: Field> {
    pub poly_evals: Vec<Vec<F::BaseField>>,
}

impl<F: Field> CommitmentSerde for RawCommitment<F> {
    fn size(nv: usize, np: usize) -> usize {
        (1 << nv) * np * F::BaseField::SIZE
    }

    fn serialize_into(&self, buffer: &mut [u8]) {
        let poly_len = self.poly_evals[0].len();
        self.poly_evals.iter().enumerate().for_each(|(i, poly)| {
            poly.iter().enumerate().for_each(|(j, v)| {
                v.serialize_into(
                    &mut buffer[(i * poly_len + j) * F::BaseField::SIZE
                        ..(i * poly_len + j + 1) * F::BaseField::SIZE],
                )
            })
        });
    }

    fn deserialize_from(proof: &mut Proof, var_num: usize, poly_num: usize) -> Self {
        let mut poly_evals = Vec::new();
        for _ in 0..poly_num {
            let mut poly = vec![];
            for _ in 0..(1 << var_num) {
                poly.push(proof.get_next_and_step());
            }
            poly_evals.push(poly);
        }
        RawCommitment { poly_evals }
    }
}

#[derive(Debug, Clone)]
pub struct ShufflePcProver<F: Field> {
    evals: Vec<Vec<F::BaseField>>,
}

impl<F: Field> PolyCommitProver<F> for ShufflePcProver<F> {
    type Param = ();
    type Commitment = RawCommitment<F>;

    fn new(_pp: &(), evals: &[Vec<F::BaseField>]) -> Self {
        ShufflePcProver {
            evals: evals.iter().map(|x| x.clone()).collect(),
        }
    }

    fn commit(&self) -> Self::Commitment {
        RawCommitment {
            poly_evals: self.evals.clone(),
        }
    }

    fn open(
        pp: &Self::Param,
        prover_point: Vec<(&Self, Vec<Vec<Vec<F>>>)>,
        transcript: &mut Transcript,
    ) {
        let provers = prover_point.iter().map(|x| x.0).collect::<Vec<_>>();
        let mut points = prover_point.into_iter().map(|x| x.1).collect::<Vec<_>>();
        let commit_num = points.len();
        let nv = points[0][0][0].len();
        for i in 0..commit_num {
            for j in 0..points[i].len() {
                for k in 0..points[i][j].len() {
                    points[i][j][k][0].add_assign_base_elem(F::BaseField::one());
                    transcript.append_f(MultiLinearPoly::eval_multilinear(
                        &provers[i].evals[j],
                        &points[i][j][k],
                    ));
                }
            }
        }
        let r = transcript.challenge_f::<F>();
        let mut new_len = provers[0].evals[0].len() / 2;
        let mut poly_evals = vec![];
        for i in 0..commit_num {
            let mut commit = vec![];
            for j in 0..points[i].len() {
                let mut poly = vec![];
                for k in 0..new_len {
                    poly.push(
                        r.mul_base_elem(
                            provers[i].evals[j][k * 2 + 1] - provers[i].evals[j][k * 2],
                        )
                        .add_base_elem(provers[i].evals[j][k * 2]),
                    );
                }
                commit.push(poly);
            }
            poly_evals.push(commit);
        }

        for s in 1..nv {
            for i in 0..commit_num {
                for j in 0..points[i].len() {
                    for k in 0..points[i][j].len() {
                        points[i][j][k][s].add_assign_base_elem(F::BaseField::one());
                        transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
                            &poly_evals[i][j],
                            &points[i][j][k][s..].to_vec(),
                        ));
                    }
                }
            }
            let r = transcript.challenge_f();
            println!("{} {} {:?}", file!(), line!(), r);
            new_len /= 2;
            for i in 0..commit_num {
                for j in 0..points[i].len() {
                    for k in 0..new_len {
                        poly_evals[i][j][k] = poly_evals[i][j][k * 2]
                            + (poly_evals[i][j][k * 2] - poly_evals[i][j][k * 2]) * r;
                    }
                    poly_evals[i][j].truncate(new_len);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
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
        pp: &Self::Param,
        commit_point: Vec<(&Self, Vec<Vec<Vec<F>>>)>,
        mut evals: Vec<Vec<Vec<F>>>,
        transcript: &mut Transcript,
        proof: &mut Proof,
    ) -> bool {
        let verifiers = commit_point.iter().map(|x| x.0).collect::<Vec<_>>();
        let points = commit_point.into_iter().map(|x| x.1).collect::<Vec<_>>();
        let mut new_point = vec![];
        let nv = points[0][0][0].len();
        for s in 0..nv {
            let mut next_evals = vec![];
            for i in 0..points.len() {
                let mut commit = vec![];
                for j in 0..points[i].len() {
                    let mut poly = vec![];
                    for _ in 0..points[i][j].len() {
                        let e = proof.get_next_and_step::<F>();
                        transcript.append_f(e);
                        poly.push(e);
                    }
                    commit.push(poly);
                }
                next_evals.push(commit);
            }
            let r: F = transcript.challenge_f();
            new_point.push(r);
            for i in 0..points.len() {
                for j in 0..points[i].len() {
                    for k in 0..points[i][j].len() {
                        let e = evals[i][j][k];
                        evals[i][j][k] += (r - points[i][j][k][s]) * (next_evals[i][j][k] - e);
                    }
                }
            }
        }
        println!("{} {} {:?}", file!(), line!(), new_point);

        for i in 0..points.len() {
            for j in 0..points[i].len() {
                for k in 0..points[i][j].len() {
                    assert_eq!(
                        evals[i][j][k],
                        MultiLinearPoly::eval_multilinear(
                            &verifiers[i].commit.poly_evals[j],
                            &new_point
                        )
                    );
                }
            }
        }

        true
    }
}
