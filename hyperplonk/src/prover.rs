use arithmetic::{field::Field, poly::MultiLinearPoly};
use poly_commit::PolyCommitProver;
use util::fiat_shamir::Proof;

use crate::{circuit::Circuit, witness::WitnessColumn};

struct ProverKey<F: Field, PC: PolyCommitProver<F>> {
    pub selector: MultiLinearPoly<F::BaseField>,
    pub selector_commitments: PC,
    pub permutation: [MultiLinearPoly<F::BaseField>; 3],
    pub permutation_commitments: [PC; 3],
}

impl<F: Field, PC: PolyCommitProver<F>> ProverKey<F, PC> {
    fn new(circuit: Circuit<F>) -> Self {
        unimplemented!()
    }
}

struct Prover<F: Field, PC: PolyCommitProver<F>> {
    pub prover_key: ProverKey<F, PC>,
}

impl<F: Field, PC: PolyCommitProver<F>> Prover<F, PC> {
    fn prover(&self, witness: Vec<WitnessColumn<F>>) -> Proof {
        unimplemented!()
    }
}
