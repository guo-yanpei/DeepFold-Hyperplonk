use std::time::Instant;

use arithmetic::{
    field::{
        goldilocks64::{Goldilocks64, Goldilocks64Ext},
        Field,
    },
    mul_group::Radix2Group,
};
use csv::Writer;
use poly_commit::deepfold::{DeepFoldParam, DeepFoldProver, DeepFoldVerifier};
use rand::thread_rng;

use hyperplonk::{circuit::Circuit, prover::Prover, verifier::Verifier};

fn main() {
    let mut wtr = Writer::from_path("deepfold_snark.csv").unwrap();
    wtr.write_record(["nv", "prover_time", "proof_size", "verifier_time"])
        .unwrap();
    let (prover_time, proof_size, verifier_time) = bench_mock_circuit(20, 1);
    wtr.write_record([20, prover_time, proof_size, verifier_time].map(|x| x.to_string()))
        .unwrap();
}

fn bench_mock_circuit(nv: u32, repetition: usize) -> (usize, usize, usize) {
    let num_gates = 1u32 << nv;
    let mock_circuit = Circuit::<Goldilocks64Ext> {
        permutation: [
            (0..num_gates).map(|x| x.into()).collect(),
            (0..num_gates).map(|x| (x + (1 << 29)).into()).collect(),
            (0..num_gates).map(|x| (x + (1 << 30)).into()).collect(),
        ], // identical permutation
        selector: (0..num_gates).map(|x| (x & 1).into()).collect(),
    };

    let mut mult_subgroups = vec![Radix2Group::<Goldilocks64>::new(nv + 2)];
    for i in 1..nv as usize {
        mult_subgroups.push(mult_subgroups[i - 1].exp(2));
    }
    let pp = DeepFoldParam::<Goldilocks64Ext> {
        mult_subgroups,
        variable_num: nv as usize,
        query_num: 45,
    };
    let (pk, vk) = mock_circuit.setup::<DeepFoldProver<_>, DeepFoldVerifier<_>>(&pp, &pp);
    let prover = Prover { prover_key: pk };
    let verifier = Verifier { verifier_key: vk };
    let a = (0..num_gates)
        .map(|_| Goldilocks64::random(&mut thread_rng()))
        .collect::<Vec<_>>();
    let b = (0..num_gates)
        .map(|_| Goldilocks64::random(&mut thread_rng()))
        .collect::<Vec<_>>();
    let c = (0..num_gates)
        .map(|i| {
            let i = i as usize;
            let s = mock_circuit.selector[i];
            -((Goldilocks64::one() - s) * (a[i] + b[i]) + s * a[i] * b[i])
        })
        .collect::<Vec<_>>();
    let start = Instant::now();
    for _ in 0..repetition - 1 {
        let _proof = prover.prove(&pp, nv as usize, [a.clone(), b.clone(), c.clone()]);
    }
    let proof = prover.prove(&pp, nv as usize, [a, b, c]);
    let prover_time = start.elapsed().as_micros() as usize / repetition;
    let proof_size = proof.bytes.len();

    let start = Instant::now();
    assert!(verifier.verify(&pp, nv as usize, proof));
    let verifier_time = start.elapsed().as_micros() as usize;

    (prover_time, proof_size, verifier_time)
}
