use arithmetic::field::Field;

use crate::selector::SelectorColumn;

// the circuit gate is (1 - s(X)) * (a(X) + b(X)) + s(X) * a(X) * b(X) - c(X) = 0
// the first m elements in a(X) are public inputs
pub struct Circuit<F: Field> {
    // pub witness: [WitnessColumn<F::BaseField>; 3],
    pub permutation: [Vec<F::BaseField>; 3],
    pub selector: SelectorColumn<F::BaseField>,
}
