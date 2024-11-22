use std::time::Instant;

use arithmetic::{
    field::{
        goldilocks64::{Goldilocks64, Goldilocks64Ext},
        Field,
    },
    mul_group::Radix2Group,
    poly::MultiLinearPoly,
};
use poly_commit::{
    deepfold::{DeepFoldParam, DeepFoldProver, DeepFoldVerifier, MerkleRoot},
    CommitmentSerde, PolyCommitProver, PolyCommitVerifier,
};
use rand::thread_rng;
use util::fiat_shamir::Transcript;

fn main() {
    let mut rng = thread_rng();
    let nv = 21;
    let batch = 3;
    let code_rate = 1;
    let poly = (0..(1 << nv))
        .map(|_| Goldilocks64::random(&mut rng))
        .collect::<Vec<_>>();
    let point = (0..nv)
        .map(|_| Goldilocks64Ext::random(&mut rng))
        .collect::<Vec<_>>();
    let mut polies = vec![];
    for i in 0..(1 << batch) {
        polies.push(poly[i * (1 << (nv - batch))..(i + 1) * (1 << (nv - batch))].to_vec());
    }
    let evals = polies
        .iter()
        .map(|x| MultiLinearPoly::eval_multilinear(x, &point[0..nv - batch].to_vec()))
        .collect::<Vec<_>>();
    let mut mult_subgroups = vec![Radix2Group::<Goldilocks64>::new(
        (nv - batch + code_rate) as u32,
    )];
    for i in 1..nv - batch {
        mult_subgroups.push(mult_subgroups[i - 1].exp(2));
    }
    let pp = DeepFoldParam::<Goldilocks64Ext> {
        mult_subgroups,
        variable_num: nv - batch,
        query_num: 100 / code_rate,
    };
    let start = Instant::now();
    let prover = DeepFoldProver::new(&pp, &polies);
    let commitment = prover.commit();
    let mut buffer = vec![0u8; MerkleRoot::size(nv - batch, 1 << batch)];
    commitment.serialize_into(&mut buffer);
    let mut transcript = Transcript::new();
    transcript.append_u8_slice(&buffer, MerkleRoot::size(nv - batch, 1 << batch));
    for i in 0..(1 << batch) {
        transcript.append_f(evals[i]);
    }
    DeepFoldProver::open(
        &pp,
        vec![&prover],
        point[0..nv - batch].to_vec(),
        &mut transcript,
    );
    println!(
        "prover: {} ms, size: {} B",
        start.elapsed().as_millis(),
        transcript.proof.bytes.len()
    );
    let mut proof = transcript.proof;

    let commitment = MerkleRoot::deserialize_from(&mut proof, nv - batch, 1 << batch);
    let mut transcript = Transcript::new();
    let mut buffer = vec![0u8; MerkleRoot::size(nv - batch, 1 << batch)];
    commitment.serialize_into(&mut buffer);
    transcript.append_u8_slice(&buffer, MerkleRoot::size(nv - batch, 1 << batch));
    let verifier = DeepFoldVerifier::new(&pp, commitment, 1 << batch);
    let eval = vec![(0..(1 << batch))
        .map(|_| proof.get_next_and_step::<Goldilocks64Ext>())
        .collect::<Vec<_>>()];
    for i in 0..(1 << batch) {
        transcript.append_f(eval[0][i]);
    }
    assert!(DeepFoldVerifier::verify(
        &pp,
        vec![&verifier],
        point[0..nv - batch].to_vec(),
        eval,
        &mut transcript,
        &mut proof
    ));
}
