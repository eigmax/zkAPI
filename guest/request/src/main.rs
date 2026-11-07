//! Proves a zkAPI v2 request statement: checks Q1–Q10 and commits the 12 statement words.

#![no_main]
zkm_zkvm::entrypoint!(main);

use zkapi_ziren_statement::{check_request, public_values, track, RequestInput};

pub fn main() {
    let input: RequestInput = track("read-input", zkm_zkvm::io::read::<RequestInput>);
    if let Err(rejected) = track("check", || check_request(&input.statement, &input.witness)) {
        panic!("request statement fails {}", rejected.0);
    }
    zkm_zkvm::io::commit_slice(&public_values(&input.statement));
}
