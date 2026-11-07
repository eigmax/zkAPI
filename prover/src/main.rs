//! `zkapi-ziren execute <input>`: run the guest, check its public values, print the cycles.
//! `zkapi-ziren prove <input> <proof>`: prove to Groth16, verify, and save the proof.
//! `zkapi-ziren serve`: prove each `<input> <proof>` line read from stdin in one process, so the
//! proving keys and the Groth16 circuit are loaded once, not per proof.
//! `zkapi-ziren vkeys`: print both guests' verifying-key hashes.
//!
//! `<input>` is a bincode `zkapi_ziren_statement::Input`.

use std::{collections::HashMap, io::BufRead, time::Instant};

use anyhow::{bail, Context, Result};
use zkapi_ziren::{elf, stdin, verify_groth16, REQUEST_ELF, WITHDRAWAL_ELF};
use zkapi_ziren_statement::{public_values, Input};
use zkm_sdk::{HashableKey, ProverClient, ZKMProvingKey, ZKMVerifyingKey};

type Keys = HashMap<&'static str, (ZKMProvingKey, ZKMVerifyingKey)>;

fn program(input: &Input) -> &'static str {
    match input {
        Input::Request(_) => "request",
        Input::Withdrawal(_) => "withdrawal",
    }
}

/// Proves `input_path` to Groth16, verifies the proof as a server would, and saves it to `out`.
fn prove_one(client: &ProverClient, keys: &mut Keys, input_path: &str, out: &str) -> Result<String> {
    let input = read_input(input_path)?;
    let started = Instant::now();
    let (pk, vk) = keys
        .entry(program(&input))
        .or_insert_with(|| client.setup(elf(&input)));
    let setup = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let proof = client.prove(pk, stdin(&input)).groth16().run()?;
    let proving = started.elapsed().as_secs_f64();
    client.verify(&proof, vk)?;
    let bytes = proof.bytes()?;
    verify_groth16(&bytes, input.statement(), &vk.bytes32())?;
    proof.save(out)?;
    Ok(format!(
        "vkey {} setup {:.1} s groth16 {:.1} s proof {} bytes public values {} bytes",
        vk.bytes32(),
        setup,
        proving,
        bytes.len(),
        proof.public_values.as_slice().len()
    ))
}

fn read_input(path: &str) -> Result<Input> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let input: Input = bincode::deserialize(&bytes).context("decoding the input")?;
    if let Err(rejected) = input.check() {
        bail!("the statement fails {} natively", rejected.0);
    }
    Ok(input)
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let client = ProverClient::new();
    match args.get(1).map(String::as_str) {
        Some("execute") => {
            let input = read_input(args.get(2).context("input path")?)?;
            let started = Instant::now();
            let (values, report) = client.execute(elf(&input), &stdin(&input)).run()?;
            if values.as_slice() != public_values(input.statement()).as_slice() {
                bail!("the guest committed other public values");
            }
            let total = report.total_instruction_count();
            println!(
                "cycles {} execute {:.2} s",
                total,
                started.elapsed().as_secs_f64()
            );
            let mut scopes = report.cycle_tracker.iter().collect::<Vec<_>>();
            scopes.sort_by(|a, b| b.1.cmp(a.1));
            for (name, cycles) in scopes {
                println!(
                    "  {name:<22} {cycles:>12} {:>6.2}%",
                    100.0 * *cycles as f64 / total as f64
                );
            }
            if std::env::var("ZKAPI_PROFILE").as_deref() == Ok("1") {
                println!("{report}");
            }
        }
        Some("prove") => {
            let input = args.get(2).context("input path")?;
            let out = args.get(3).context("proof path")?;
            println!("{}", prove_one(&client, &mut Keys::new(), input, out)?);
        }
        Some("serve") => {
            let mut keys = Keys::new();
            for line in std::io::stdin().lock().lines() {
                let line = line?;
                let mut fields = line.split_whitespace();
                let (Some(input), Some(out)) = (fields.next(), fields.next()) else {
                    continue;
                };
                let started = Instant::now();
                match prove_one(&client, &mut keys, input, out) {
                    Ok(summary) => println!(
                        "ok {input} wall {:.1} s {summary}",
                        started.elapsed().as_secs_f64()
                    ),
                    Err(error) => println!("error {input} {error:#}"),
                }
            }
        }
        Some("vkeys") => {
            for (name, program) in [("request", REQUEST_ELF), ("withdrawal", WITHDRAWAL_ELF)] {
                let (_, vk) = client.setup(program);
                println!("{name} {}", vk.bytes32());
            }
        }
        _ => bail!("usage: zkapi-ziren execute <input> | prove <input> <proof> | serve | vkeys"),
    }
    Ok(())
}
