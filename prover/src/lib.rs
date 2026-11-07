//! Ziren proofs of zkAPI v2 request and withdrawal statements.
//!
//! The guests check the statement (Q1–Q10 or W1–W14) and commit its words, so a proof's
//! public values are the statement as `abi.encodePacked` `uint256` words. A verifier checks
//! the Groth16 proof against those words and the guest's verifying-key hash.

use anyhow::{anyhow, Result};
use zkapi_ziren_statement::{public_values, Input, Word};
use zkm_sdk::{include_elf, ZKMStdin};

pub const REQUEST_ELF: &[u8] = include_elf!("zkapi-request");
pub const WITHDRAWAL_ELF: &[u8] = include_elf!("zkapi-withdrawal");

pub fn elf(input: &Input) -> &'static [u8] {
    match input {
        Input::Request(_) => REQUEST_ELF,
        Input::Withdrawal(_) => WITHDRAWAL_ELF,
    }
}

pub fn stdin(input: &Input) -> ZKMStdin {
    let mut stdin = ZKMStdin::new();
    match input {
        Input::Request(input) => stdin.write(input),
        Input::Withdrawal(input) => stdin.write(input),
    }
    stdin
}

/// Verifies a Groth16 proof (`ZKMProofWithPublicValues::bytes`) of `statement` under the
/// guest whose verifying-key hash is `vkey_hash`, as a server would.
pub fn verify_groth16(proof: &[u8], statement: &[Word], vkey_hash: &str) -> Result<()> {
    zkm_verifier::Groth16Verifier::verify(
        proof,
        &public_values(statement),
        vkey_hash,
        &zkm_verifier::GROTH16_VK_BYTES,
    )
    .map_err(|error| anyhow!("Groth16 verification failed: {error:?}"))
}
