use std::{collections::HashMap, marker::PhantomData};

use arithmetic::{
    field::{as_bytes_vec, FftField, Field},
    mul_group::Radix2Group,
    poly::MultiLinearPoly,
};
use util::{
    fiat_shamir::Proof,
    merkle_tree::{MerkleTreeProver, MerkleTreeVerifier, HASH_SIZE},
};

use crate::Transcript;

use super::{CommitmentSerde, PolyCommitProver, PolyCommitVerifier};

#[derive(Debug, Clone, Default)]
pub struct MerkleRoot([u8; HASH_SIZE]);

impl CommitmentSerde for MerkleRoot {
    fn size(nv: usize, np: usize) -> usize {
        HASH_SIZE
    }

    fn serialize_into(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.0);
    }

    fn deserialize_from(proof: &mut Proof, nv: usize, np: usize) -> Self {
        let mut root = proof.get_next_hash();
        Self(root)
    }
}

#[derive(Debug, Clone)]
pub struct DeepFoldParam<F: FftField> {
    pub mult_subgroups: Vec<Radix2Group<F::FftBaseField>>,
    pub variable_num: usize,
    pub query_num: usize,
}

#[derive(Clone)]
pub struct QueryResult<F: Field> {
    pub proof_bytes: Vec<u8>,
    pub proof_values: HashMap<usize, F>,
}

impl<F: Field> QueryResult<F> {
    pub fn verify_merkle_tree(
        &self,
        leaf_indices: &Vec<usize>,
        leaf_size: usize,
        merkle_verifier: &MerkleTreeVerifier,
    ) -> bool {
        let len = merkle_verifier.leave_number;
        let leaves: Vec<Vec<u8>> = leaf_indices
            .iter()
            .map(|i| {
                as_bytes_vec(
                    &(0..leaf_size)
                        .map(|j| self.proof_values.get(&(i + j * len)).unwrap().clone())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let res = merkle_verifier.verify(self.proof_bytes.clone(), leaf_indices, &leaves);
        assert!(res);
        res
    }
}

#[derive(Clone)]
pub struct InterpolateValue<F: Field> {
    pub value: Vec<F>,
    leaf_size: usize,
    merkle_tree: MerkleTreeProver,
}

impl<F: FftField> InterpolateValue<F> {
    pub fn new(value: Vec<F>, leaf_size: usize) -> Self {
        let len = value.len() / leaf_size;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| {
                    as_bytes_vec::<F>(
                        &(0..leaf_size)
                            .map(|j| value[len * j + i])
                            .collect::<Vec<_>>(),
                    )
                })
                .collect(),
        );
        Self {
            value,
            leaf_size,
            merkle_tree,
        }
    }

    pub fn leave_num(&self) -> usize {
        self.merkle_tree.leave_num()
    }

    pub fn commit(&self) -> [u8; HASH_SIZE] {
        self.merkle_tree.commit()
    }

    pub fn query(&self, leaf_indices: &Vec<usize>) -> (Vec<u8>, Vec<F>) {
        let len = self.merkle_tree.leave_num();
        assert_eq!(len * self.leaf_size, self.value.len());
        let proof_values = (0..self.leaf_size)
            .flat_map(|i| {
                leaf_indices
                    .iter()
                    .map(|j| self.value[j.clone() + i * len])
                    .collect::<Vec<_>>()
            })
            .collect();
        let proof_bytes = self.merkle_tree.open(&leaf_indices);
        (proof_bytes, proof_values)
    }
}

#[derive(Clone)]
pub struct DeepFoldProver<F: FftField> {
    pub interpolation: InterpolateValue<F::FftBaseField>,
    poly: Vec<Vec<F::BaseField>>,
}

impl<F: FftField> DeepFoldProver<F> {
    fn evaluate_next_domain(
        last_interpolation: &Vec<F>,
        pp: &DeepFoldParam<F>,
        round: usize,
        challenge: F,
    ) -> Vec<F> {
        let mut res = vec![];
        let len = pp.mult_subgroups[round].size();
        let subgroup = &pp.mult_subgroups[round];
        for i in 0..(len / 2) {
            let x = last_interpolation[i];
            let nx = last_interpolation[i + len / 2];
            let sum = x + nx;
            let new_v = sum + challenge * ((x - nx) * F::from(subgroup.element_inv_at(i)) - sum);
            res.push(new_v.mul_base_elem(<F as Field>::BaseField::inv_2()));
        }
        res
    }
}

impl<F: FftField> PolyCommitProver<F> for DeepFoldProver<F> {
    type Param = DeepFoldParam<F>;
    type Commitment = MerkleRoot;

    fn new(pp: &Self::Param, poly: &[Vec<F::BaseField>]) -> Self {
        let values = poly
            .iter()
            .flat_map(|x| pp.mult_subgroups[0].fft(x.clone()))
            .collect::<Vec<_>>();
        DeepFoldProver {
            interpolation: InterpolateValue::new(values, 2 * poly.len()),
            poly: poly.iter().map(|x| x.clone()).collect(),
        }
    }

    fn commit(&self) -> Self::Commitment {
        MerkleRoot(self.interpolation.commit())
    }

    fn open(pp: &Self::Param, provers: Vec<&Self>, point: Vec<F>, transcript: &mut Transcript) {
        let mut interpolations: Vec<InterpolateValue<F>> = vec![];
        let r: F = transcript.challenge_f();
        let mut poly_evals = provers[0].poly[0]
            .iter()
            .map(|x| F::from(*x))
            .collect::<Vec<_>>();
        for i in 0..provers.len() {
            let start = if i == 0 { 1 } else { 0 };
            for j in start..provers[i].poly.len() {
                for k in 0..poly_evals.len() {
                    poly_evals[k] *= r;
                    poly_evals[k].add_assign_base_elem(provers[i].poly[j][k]);
                }
            }
        }
        let len = pp.mult_subgroups[0].size();
        let mut poly_interpolations = (0..len).map(|_| F::zero()).collect::<Vec<_>>();
        for i in 0..provers.len() {
            for j in 0..len {
                for k in 0..provers[i].poly.len() {
                    poly_interpolations[j] *= r;
                    poly_interpolations[j] += F::from(provers[i].interpolation.value[j + len * k]);
                }
            }
        }
        for i in 0..pp.variable_num {
            let mut new_point = point[i..].to_vec();
            new_point[0].add_assign_base_elem(F::BaseField::one());
            transcript.append_f(MultiLinearPoly::eval_multilinear_ext(
                &poly_evals,
                &new_point,
            ));
            let challenge: F = transcript.challenge_f();
            let new_len = poly_evals.len() / 2;
            for j in 0..new_len {
                poly_evals[j] =
                    poly_evals[j * 2] + (poly_evals[j * 2 + 1] - poly_evals[j * 2]) * challenge;
            }
            poly_evals.truncate(new_len);
            let next_evaluation = Self::evaluate_next_domain(
                if i == 0 {
                    &poly_interpolations
                } else {
                    &interpolations[i - 1].value
                },
                pp,
                i,
                challenge,
            );
            if i < pp.variable_num - 1 {
                let new_interpolation = InterpolateValue::new(next_evaluation, 2);
                transcript.append_u8_slice(&new_interpolation.commit(), HASH_SIZE);
                interpolations.push(new_interpolation);
            } else {
                transcript.append_f(next_evaluation[0]);
            }
        }
        let mut leaf_indices = transcript.challenge_usizes(pp.query_num);
        for i in 0..pp.variable_num {
            let len = pp.mult_subgroups[i].size();
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();
            if i == 0 {
                let query = provers
                    .iter()
                    .map(|j| j.interpolation.query(&leaf_indices))
                    .collect::<Vec<_>>();
                for q in query {
                    transcript.append_u8_slice(&q.0, q.0.len());
                    for j in q.1 {
                        transcript.append_f(j);
                    }
                }
            } else {
                let query = interpolations[i - 1].query(&leaf_indices);
                transcript.append_u8_slice(&query.0, query.0.len());
                for j in query.1 {
                    transcript.append_f(j);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct DeepFoldVerifier<F: FftField> {
    commit: MerkleTreeVerifier,
    poly_num: usize,
    _data: PhantomData<F>,
}

impl<F: FftField> PolyCommitVerifier<F> for DeepFoldVerifier<F> {
    type Param = DeepFoldParam<F>;
    type Commitment = MerkleRoot;

    fn new(pp: &Self::Param, commit: Self::Commitment, poly_num: usize) -> Self {
        DeepFoldVerifier {
            commit: MerkleTreeVerifier::new(pp.mult_subgroups[0].size() / 2, commit.0),
            poly_num,
            _data: PhantomData::default(),
        }
    }

    fn verify(
        pp: &Self::Param,
        verifiers: Vec<&Self>,
        point: Vec<F>,
        evals: Vec<Vec<F>>,
        transcript: &mut Transcript,
        proof: &mut Proof,
    ) -> bool {
        let r = transcript.challenge_f();
        let mut eval = F::zero();
        for i in evals {
            for j in i {
                eval *= r;
                eval += j;
            }
        }
        let mut challenges = vec![];
        let mut commits = vec![];
        for i in 0..point.len() {
            let next_eval = proof.get_next_and_step::<F>();
            transcript.append_f(next_eval);
            let challenge = transcript.challenge_f::<F>();

            eval += (challenge - point[i]) * (next_eval - eval);
            challenges.push(challenge);
            if i < pp.variable_num - 1 {
                let merkle_root = proof.get_next_hash();
                transcript.append_u8_slice(&merkle_root, HASH_SIZE);
                commits.push(MerkleTreeVerifier::new(
                    pp.mult_subgroups[i + 1].size() / 2,
                    merkle_root,
                ));
            } else {
                let final_value = proof.get_next_and_step::<F>();
                transcript.append_f(final_value);
                if final_value != eval {
                    return false;
                }
            }
        }

        let mut leaf_indices = transcript.challenge_usizes(pp.query_num);
        let mut indices = leaf_indices.clone();
        let mut query_results = vec![];
        for i in 0..pp.variable_num {
            let len = pp.mult_subgroups[i].size();
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            if i == 0 {
                let mut poly_values = vec![];
                for j in 0..verifiers.len() {
                    let proof_bytes =
                        proof.get_next_slice(verifiers[j].commit.proof_length(&leaf_indices));
                    let proof_values = (0..leaf_indices.len() * 2 * verifiers[j].poly_num)
                        .map(|_| proof.get_next_and_step::<F::FftBaseField>())
                        .collect::<Vec<_>>();
                    transcript.append_u8_slice(&proof_bytes, proof_bytes.len());
                    for k in &proof_values {
                        transcript.append_f(*k);
                    }
                    poly_values.append(
                        &mut (0..verifiers[j].poly_num)
                            .map(|k| {
                                (&proof_values
                                    [k * leaf_indices.len() * 2..(k + 1) * leaf_indices.len() * 2])
                                    .to_vec()
                            })
                            .collect::<Vec<_>>(),
                    );
                    let query = QueryResult {
                        proof_bytes,
                        proof_values: proof_values
                            .into_iter()
                            .enumerate()
                            .map(|(idx, x)| {
                                (
                                    leaf_indices[idx % leaf_indices.len()]
                                        + (len / 2) * (idx / leaf_indices.len()),
                                    x,
                                )
                            })
                            .collect(),
                    };
                    assert!(query.verify_merkle_tree(
                        &leaf_indices,
                        2 * verifiers[j].poly_num,
                        &verifiers[j].commit
                    ));
                }
                let poly_values = (0..leaf_indices.len() * 2)
                    .into_iter()
                    .map(|j| {
                        let mut x = F::zero();
                        for k in 0..poly_values.len() {
                            x *= r;
                            x += F::from(poly_values[k][j]);
                        }
                        x
                    })
                    .collect::<Vec<_>>();

                query_results.push(QueryResult {
                    proof_bytes: vec![],
                    proof_values: leaf_indices
                        .iter()
                        .map(|&x| x)
                        .chain(leaf_indices.iter().map(|&x| x + len / 2))
                        .zip(poly_values)
                        .collect(),
                })
            } else {
                let proof_bytes = proof.get_next_slice(commits[i - 1].proof_length(&leaf_indices));
                let proof_values = (0..leaf_indices.len() * 2)
                    .map(|_| proof.get_next_and_step::<F>())
                    .collect::<Vec<_>>();
                transcript.append_u8_slice(&proof_bytes, proof_bytes.len());
                for j in &proof_values {
                    transcript.append_f(*j);
                }
                let query = QueryResult {
                    proof_bytes,
                    proof_values: leaf_indices
                        .iter()
                        .map(|&x| x)
                        .chain(leaf_indices.iter().map(|x| x + len / 2))
                        .zip(proof_values.into_iter())
                        .collect(),
                };
                query.verify_merkle_tree(&leaf_indices, 2, &commits[i - 1]);
                query_results.push(query);
            }
        }
        drop(leaf_indices);
        for i in 0..pp.variable_num {
            let len = pp.mult_subgroups[i].size();
            indices = indices.iter_mut().map(|v| *v % (len >> 1)).collect();
            indices.sort();
            indices.dedup();

            for j in indices.iter() {
                let x = query_results[i].proof_values.get(&j).unwrap().clone();
                let nx = query_results[i]
                    .proof_values
                    .get(&(j + len / 2))
                    .unwrap()
                    .clone();
                let sum = x + nx;
                let new_v = sum
                    + challenges[i]
                        * ((x - nx) * F::from(pp.mult_subgroups[i].element_inv_at(*j)) - sum);
                if i < pp.variable_num - 1 {
                    if new_v != query_results[i + 1].proof_values[j].double() {
                        println!("{} {}", file!(), line!());
                        return false;
                    }
                } else {
                    if new_v.mul_base_elem(<F as Field>::BaseField::inv_2()) != eval {
                        return false;
                    }
                }
            }
        }
        true
    }
}
