//! Checks one recorded TLS 1.3 session and commits what it established.
#![no_main]
zkm_zkvm::entrypoint!(main);

/// Reports each phase to the executor's cycle tracker.
struct CycleTracker;

impl tlsv::Tracker for CycleTracker {
    fn start(&mut self, phase: &str) {
        println!("cycle-tracker-report-start: {phase}");
    }
    fn end(&mut self, phase: &str) {
        println!("cycle-tracker-report-end: {phase}");
    }
}

pub fn main() {
    let capture: tlsv::Capture = zkm_zkvm::io::read();
    println!("cycle-tracker-report-start: total");
    let summary = tlsv::check(&capture, &mut CycleTracker).expect("session check failed");
    println!("cycle-tracker-report-end: total");
    zkm_zkvm::io::commit(&summary);
}
