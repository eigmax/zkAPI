//! Proves a zkAPI v2 withdrawal statement: checks W1–W14 and commits the 16 statement words.

#![no_main]
zkm_zkvm::entrypoint!(main);

use zkapi_ziren_statement::{check_withdrawal, public_values, track, WithdrawalInput};

pub fn main() {
    let input: WithdrawalInput = track("read-input", zkm_zkvm::io::read::<WithdrawalInput>);
    if let Err(rejected) = track("check", || check_withdrawal(&input.statement, &input.witness)) {
        panic!("withdrawal statement fails {}", rejected.0);
    }
    zkm_zkvm::io::commit_slice(&public_values(&input.statement));
}
