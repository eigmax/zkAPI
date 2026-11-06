//! Executes the TLS-check guest on each recorded session and prints its
//! cycles per phase and its precompile calls. Execution only: no proof.
//!
//! Usage: `host <capture.bin>...`

use zkm_core_executor::{Executor, Program, ZKMContext};
use zkm_pcs::ZKMCoreOpts;

const ELF: &[u8] = include_bytes!(env!("ZKM_ELF_tls-guest"));

const ORDER: &[&str] = &[
    "records",
    "x25519",
    "transcript_hash",
    "key_schedule",
    "hs_decrypt",
    "x509_parse",
    "chain_names",
    "chain_sig_0",
    "chain_sig_1",
    "chain_sig_2",
    "chain_sig_3",
    "cert_verify",
    "finished",
    "app_decrypt_request",
    "app_decrypt_response",
    "app_hash",
    "selective_decrypt",
];

fn main() {
    let program = Program::from(ELF).expect("guest ELF");
    for path in std::env::args().skip(1) {
        let capture: tlsv::Capture = bincode::deserialize(&std::fs::read(&path).expect("read capture")).expect("capture");
        let mut rt = Executor::with_context(program.clone(), ZKMCoreOpts::default(), ZKMContext::default());
        rt.write_stdin(&capture);
        rt.run_fast().expect("guest execution");
        let summary: tlsv::Summary = bincode::deserialize(&rt.state.public_values_stream).expect("summary");
        let report = &rt.report;

        println!("== {} ({path})", summary.server_name);
        for c in &summary.chain {
            println!("   {c}");
        }
        println!(
            "   CertificateVerify {:#06x}; certs {} B, handshake records {} B, request {} B, response {} B",
            summary.cert_verify_scheme, summary.cert_bytes, summary.hs_record_bytes, summary.request_bytes, summary.response_bytes
        );
        let total = *report.cycle_tracker.get("total").unwrap_or(&0);
        println!("   {:<22} {:>12} {:>7}", "phase", "cycles", "share");
        for name in ORDER {
            if let Some(&cycles) = report.cycle_tracker.get(*name) {
                println!("   {:<22} {:>12} {:>6.1}%", name, cycles, 100.0 * cycles as f64 / total.max(1) as f64);
            }
        }
        println!("   {:<22} {:>12}", "total (check)", total);
        println!("   {:<22} {:>12}", "whole program", report.total_instruction_count());
        let mut calls: Vec<_> = report.syscall_counts.iter().filter(|(_, &n)| n > 0).collect();
        calls.sort_by(|a, b| b.1.cmp(a.1));
        let calls: Vec<String> = calls.iter().map(|(k, n)| format!("{k:?}={n}")).collect();
        println!("   syscalls: {}", calls.join(", "));
        println!("   selective plaintext: {:?}", String::from_utf8_lossy(&summary.selective_plaintext));
    }
}
