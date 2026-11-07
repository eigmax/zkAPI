//! Poseidon over the BN254 scalar field as arkworks' `PoseidonSponge` computes it for upstream's
//! parameters: width 3 (capacity 1, rate 2), 8 full and 57 partial rounds, alpha 5.

use crate::constants::{POSEIDON_ARK, POSEIDON_MDS};
use crate::fr::F;

const FULL_ROUNDS_HALF: usize = 4;
const PARTIAL_ROUNDS: usize = 57;
const PARTIAL: core::ops::Range<usize> = FULL_ROUNDS_HALF..FULL_ROUNDS_HALF + PARTIAL_ROUNDS;

/// The permutation: per round, add the round constants, apply the S-box (to every lane in a
/// full round, to lane 0 in a partial round), then multiply by the MDS matrix.
pub fn permute(state: &mut [F; 3]) {
    for (round, constants) in POSEIDON_ARK.iter().enumerate() {
        for (value, constant) in state.iter_mut().zip(constants) {
            *value = *value + *constant;
        }
        if PARTIAL.contains(&round) {
            state[0] = state[0].pow5();
        } else {
            for value in state.iter_mut() {
                *value = value.pow5();
            }
        }
        let input = *state;
        for (value, mds) in state.iter_mut().zip(&POSEIDON_MDS) {
            *value = input[0] * mds[0] + input[1] * mds[1] + input[2] * mds[2];
        }
    }
}

/// The sponge hash of `inputs` and one squeezed element: absorb into the rate lanes, permuting
/// whenever both are full and more input follows, then permute and read lane 1.
pub fn hash(inputs: &[F]) -> F {
    let mut state = [F::ZERO; 3];
    let mut next = 0;
    for input in inputs {
        if next == 2 {
            permute(&mut state);
            next = 0;
        }
        state[1 + next] = state[1 + next] + *input;
        next += 1;
    }
    permute(&mut state);
    state[1]
}

/// One permutation of `(capacity, left, right)`, read at lane 1.
pub fn compress(capacity: F, left: F, right: F) -> F {
    let mut state = [capacity, left, right];
    permute(&mut state);
    state[1]
}
