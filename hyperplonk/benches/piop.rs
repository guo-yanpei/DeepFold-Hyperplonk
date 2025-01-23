use std::time::Instant;

use arithmetic::field::{bn_254::Bn254F, Field};
use csv::Writer;
use poly_commit::nil::{NilPcProver, NilPcVerifier};
use rand::thread_rng;

use hyperplonk::{circuit::Circuit, prover::Prover, verifier::Verifier};

fn main() {
    let nv = 15usize;
    bench_mock_circuit::<Bn254F>(nv, 1);
    let mut wtr = Writer::from_path("piop.csv").unwrap();
    wtr.write_record(["nv", "prover_time", "proof_size", "verifier_time"])
        .unwrap();
    let (prover_time, proof_size, verifier_time) = bench_mock_circuit::<Bn254F>(nv, 1);
    wtr.write_record([nv, prover_time, proof_size, verifier_time].map(|x| x.to_string()))
        .unwrap();
}

fn bench_mock_circuit<F: Field>(nv: usize, repetition: usize) -> (usize, usize, usize) {
    let num_gates = 1u32 << nv;
    let mock_circuit = Circuit::<F> {
        permutation: [
            (0..num_gates).map(|x| x.into()).collect(),
            (0..num_gates).map(|x| (x + (1 << 29)).into()).collect(),
            (0..num_gates).map(|x| (x + (1 << 30)).into()).collect(),
        ], // identical permutation
        selector: (0..num_gates).map(|x| (x & 1).into()).collect(),
    };

    let (pk, vk) = mock_circuit.setup::<NilPcProver<_>, NilPcVerifier<_>>(&(), &());
    let prover = Prover { prover_key: pk };
    let verifier = Verifier { verifier_key: vk };
    let a = (0..num_gates)
        .map(|_| F::BaseField::random(&mut thread_rng()))
        .collect::<Vec<_>>();
    let b = (0..num_gates)
        .map(|_| F::BaseField::random(&mut thread_rng()))
        .collect::<Vec<_>>();
    let c = (0..num_gates)
        .map(|i| {
            let i = i as usize;
            let s = mock_circuit.selector[i];
            -((F::BaseField::one() - s) * (a[i] + b[i]) + s * a[i] * b[i])
        })
        .collect::<Vec<_>>();
    let start = Instant::now();
    for _ in 0..repetition - 1 {
        let _proof = prover.prove(&(), nv as usize, [a.clone(), b.clone(), c.clone()]);
    }
    let proof = prover.prove(&(), nv as usize, [a.clone(), b.clone(), c.clone()]);
    let prover_time = start.elapsed().as_micros() as usize / repetition;
    let proof_size = proof.bytes.len();

    let start = Instant::now();
    assert!(verifier.verify(&(), nv as usize, proof));
    let verifier_time = start.elapsed().as_micros() as usize;

    (prover_time, proof_size, verifier_time)
}
