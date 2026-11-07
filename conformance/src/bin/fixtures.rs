//! Writes valid prover inputs, built with upstream's own helpers, to a directory:
//! `request-signed.bin`, `request-genesis.bin`, `withdrawal-escape.bin`,
//! `withdrawal-close.bin` and `withdrawal-ownership.bin` (bincode of `Input`).

use std::path::PathBuf;

use zkapi_ziren_conformance::*;
use zkapi_ziren_statement::Input;

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "out".into()));
    std::fs::create_dir_all(&dir).expect("output directory");
    let inputs = [
        ("request-signed", Input::Request(request_input(&request_fixture(1, true)))),
        ("request-genesis", Input::Request(request_input(&request_fixture(3, false)))),
        ("withdrawal-escape", Input::Withdrawal(withdrawal_input(&withdrawal_fixture(4, 0, true)))),
        ("withdrawal-close", Input::Withdrawal(withdrawal_input(&withdrawal_fixture(5, 1, true)))),
        ("withdrawal-ownership", Input::Withdrawal(withdrawal_input(&withdrawal_fixture(6, 2, true)))),
    ];
    for (name, input) in inputs {
        input.check().unwrap_or_else(|rejected| panic!("{name}: {rejected:?}"));
        let path = dir.join(format!("{name}.bin"));
        std::fs::write(&path, bincode::serialize(&input).expect("encode")).expect("write");
        println!("{}", path.display());
    }
}
