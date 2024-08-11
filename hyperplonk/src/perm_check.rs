use arithmetic::field::Field;
use util::fiat_shamir::{Proof, Transcript};

struct PermCheck{}

impl PermCheck {
    fn prove<F: Field>(input1: [Vec<F>; 2], input2: [Vec<F>; 2], transcript: &mut Transcript) {
        let r = (0..2).map(|_| transcript.challenge_f::<F>()).collect::<Vec<_>>();
        
    }

    fn verify(transcript: &mut Transcript, proof: &mut Proof) {

    }
}
