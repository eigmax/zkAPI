//! The Ziren statements accept exactly what upstream's Groth16 circuits accept: on valid
//! fixtures of every shape, and on each fixture with one value changed.

use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as ScalarField};
use ark_ff::{One, UniformRand, Zero};
use zkapi_proof::groth16::{RequestCircuit, StateSigningKey, WithdrawalCircuit};
use zkapi_ziren_conformance::*;
use zkapi_ziren_statement::{check_request, check_withdrawal, Rejected};

type RequestMutation = (&'static str, fn(&mut RequestCircuit));
type WithdrawalMutation = (&'static str, fn(&mut WithdrawalCircuit));

/// The point of order two, (0, -1): on the curve, outside the prime-order subgroup.
fn order_two() -> EdwardsAffine {
    EdwardsAffine::new_unchecked(Fr::zero(), -Fr::one())
}

fn other_point(seed: u64) -> EdwardsAffine {
    let mut rng = rng(seed);
    StateSigningKey::generate(&mut rng).public
}

fn ziren_request(circuit: &RequestCircuit) -> Result<(), Rejected> {
    let input = request_input(circuit);
    check_request(&input.statement, &input.witness)
}

fn ziren_withdrawal(circuit: &WithdrawalCircuit) -> Result<(), Rejected> {
    let input = withdrawal_input(circuit);
    check_withdrawal(&input.statement, &input.witness)
}

const REQUEST_MUTATIONS: &[RequestMutation] = &[
    ("secret zero", |c| c.witness.secret = Fr::zero()),
    ("secret", |c| c.witness.secret += Fr::one()),
    ("balance", |c| c.witness.current_balance += 1),
    ("solvency bound above balance", |c| {
        c.public.solvency_bound = c.witness.current_balance + 1
    }),
    ("solvency bound equal to balance", |c| {
        c.public.solvency_bound = c.witness.current_balance
    }),
    ("request time after expiry", |c| c.public.request_time = c.witness.expiry + 1),
    ("request time at expiry", |c| c.public.request_time = c.witness.expiry),
    ("deposit below balance", |c| {
        c.witness.deposit_amount = c.witness.current_balance - 1
    }),
    ("expiry", |c| c.witness.expiry += 1),
    ("sibling", |c| c.witness.merkle_siblings[5] += Fr::one()),
    ("note id", |c| c.witness.note_id ^= 1),
    ("active root", |c| c.public.active_root += Fr::one()),
    ("anchor", |c| c.witness.current_anchor += Fr::one()),
    ("previous anchor", |c| c.witness.prev_anchor += Fr::one()),
    ("anchor one", |c| c.witness.current_anchor = Fr::one()),
    ("signature s", |c| {
        c.witness.state_signature.s += ScalarField::one()
    }),
    ("signature r", |c| {
        c.witness.state_signature.r = EdwardsProjective::generator().into_affine()
    }),
    ("signature r off the subgroup", |c| {
        c.witness.state_signature.r = (c.witness.state_signature.r.into_group()
            + order_two().into_group())
        .into_affine()
    }),
    ("signing key", |c| c.public.state_signing_key = other_point(9)),
    ("signing key plus order two", |c| {
        c.public.state_signing_key = (c.public.state_signing_key.into_group()
            + order_two().into_group())
        .into_affine()
    }),
    ("blinding", |c| c.witness.current_blinding += ScalarField::one()),
    ("rerandomization", |c| {
        c.witness.rerandomization += ScalarField::one()
    }),
    ("anonymous commitment", |c| {
        c.public.anonymous_commitment = other_point(10)
    }),
    ("request nullifier", |c| c.public.request_nullifier += Fr::one()),
    ("request context", |c| c.witness.request_context += Fr::one()),
    ("authorization tag", |c| c.public.authorization_tag += Fr::one()),
    ("protocol version", |c| c.public.protocol_version += 1),
    ("chain id", |c| c.public.chain_id += 1),
    ("contract", |c| c.public.contract_address += Fr::one()),
];

const WITHDRAWAL_MUTATIONS: &[WithdrawalMutation] = &[
    ("secret zero", |c| c.witness.secret = Fr::zero()),
    ("secret", |c| c.witness.secret += Fr::one()),
    ("note id", |c| c.witness.note_id ^= 1),
    ("deposit", |c| c.witness.deposit_amount += 1),
    ("expiry", |c| c.witness.expiry += 1),
    ("note fields", |c| c.public.note_fields += Fr::one()),
    ("note leaf", |c| c.public.note_leaf += Fr::one()),
    ("state balance", |c| c.witness.state_balance += 1),
    ("final balance", |c| c.public.final_balance += 1),
    ("final balance down", |c| c.public.final_balance -= 1),
    ("conceded", |c| c.public.conceded += 1),
    ("deposit below balance", |c| {
        c.witness.deposit_amount = c.witness.state_balance - 1
    }),
    ("anchor", |c| c.witness.current_anchor += Fr::one()),
    ("anchor one", |c| c.witness.current_anchor = Fr::one()),
    ("blinding", |c| c.witness.state_blinding += ScalarField::one()),
    ("state signature s", |c| {
        c.witness.state_signature.s += ScalarField::one()
    }),
    ("state signing key", |c| c.public.state_signing_key = other_point(11)),
    ("state signing key plus order two", |c| {
        c.public.state_signing_key = (c.public.state_signing_key.into_group()
            + order_two().into_group())
        .into_affine()
    }),
    ("clearance signature s", |c| {
        c.witness.clearance_signature.s += ScalarField::one()
    }),
    ("clearance signing key", |c| {
        c.public.clearance_signing_key = other_point(12)
    }),
    ("withdrawal nullifier", |c| {
        c.public.withdrawal_nullifier += Fr::one()
    }),
    ("next nullifier", |c| c.public.next_nullifier += Fr::one()),
    ("next nullifier zero", |c| c.public.next_nullifier = Fr::zero()),
    ("kind 0", |c| c.public.kind = 0),
    ("kind 1", |c| c.public.kind = 1),
    ("kind 2", |c| c.public.kind = 2),
    ("kind 3", |c| c.public.kind = 3),
    ("destination zero", |c| c.public.destination = Fr::zero()),
    ("destination 160 bits", |c| {
        c.public.destination = Fr::from(2u64).pow_by_u64(160) - Fr::one()
    }),
    ("destination 161 bits", |c| {
        c.public.destination = Fr::from(2u64).pow_by_u64(160)
    }),
    ("protocol version", |c| c.public.protocol_version += 1),
    ("chain id", |c| c.public.chain_id += 1),
    ("contract", |c| c.public.contract_address += Fr::one()),
];

trait PowByU64 {
    fn pow_by_u64(self, exponent: u64) -> Self;
}

impl PowByU64 for Fr {
    fn pow_by_u64(self, exponent: u64) -> Self {
        ark_ff::Field::pow(&self, [exponent])
    }
}

fn request_fixtures() -> Vec<(&'static str, RequestCircuit)> {
    vec![
        ("signed", request_fixture(1, true)),
        ("signed, second seed", request_fixture(2, true)),
        ("genesis", request_fixture(3, false)),
    ]
}

fn withdrawal_fixtures() -> Vec<(&'static str, WithdrawalCircuit)> {
    vec![
        ("escape", withdrawal_fixture(4, 0, true)),
        ("mutual close", withdrawal_fixture(5, 1, true)),
        ("ownership", withdrawal_fixture(6, 2, true)),
        ("escape from genesis", withdrawal_fixture(7, 0, false)),
        ("mutual close from genesis", withdrawal_fixture(8, 1, false)),
    ]
}

#[test]
fn valid_requests_are_accepted_by_both() {
    for (name, circuit) in request_fixtures() {
        assert!(satisfied_request(&circuit), "{name}: upstream refuses");
        assert_eq!(ziren_request(&circuit), Ok(()), "{name}");
    }
}

#[test]
fn valid_withdrawals_are_accepted_by_both() {
    for (name, circuit) in withdrawal_fixtures() {
        assert!(satisfied_withdrawal(&circuit), "{name}: upstream refuses");
        assert_eq!(ziren_withdrawal(&circuit), Ok(()), "{name}");
    }
}

#[test]
fn request_verdicts_agree_under_every_mutation() {
    let mut refused = 0;
    let mut total = 0;
    for (fixture, base) in request_fixtures() {
        for (mutation, apply) in REQUEST_MUTATIONS {
            let mut circuit = base.clone();
            apply(&mut circuit);
            let upstream = satisfied_request(&circuit);
            let ziren = ziren_request(&circuit);
            assert_eq!(
                upstream,
                ziren.is_ok(),
                "{fixture} / {mutation}: upstream {upstream}, ziren {ziren:?}"
            );
            total += 1;
            refused += usize::from(!upstream);
        }
    }
    println!("request: {refused} of {total} mutations refused by both, the rest accepted by both");
    assert!(refused > total / 2);
}

#[test]
fn withdrawal_verdicts_agree_under_every_mutation() {
    let mut refused = 0;
    let mut total = 0;
    for (fixture, base) in withdrawal_fixtures() {
        for (mutation, apply) in WITHDRAWAL_MUTATIONS {
            let mut circuit = base.clone();
            apply(&mut circuit);
            let upstream = satisfied_withdrawal(&circuit);
            let ziren = ziren_withdrawal(&circuit);
            assert_eq!(
                upstream,
                ziren.is_ok(),
                "{fixture} / {mutation}: upstream {upstream}, ziren {ziren:?}"
            );
            total += 1;
            refused += usize::from(!upstream);
        }
    }
    println!(
        "withdrawal: {refused} of {total} mutations refused by both, the rest accepted by both"
    );
    assert!(refused > total / 2);
}

#[test]
fn random_requests_agree() {
    let mut rng = rng(99);
    for round in 0..20u64 {
        let mut circuit = request_fixture(100 + round, round % 3 != 0);
        let (mutation, apply) = REQUEST_MUTATIONS[(u64::rand(&mut rng) % REQUEST_MUTATIONS.len() as u64) as usize];
        apply(&mut circuit);
        assert_eq!(
            satisfied_request(&circuit),
            ziren_request(&circuit).is_ok(),
            "round {round} / {mutation}"
        );
    }
}

#[test]
fn encodings_the_circuit_cannot_take_are_refused() {
    let base = request_input(&request_fixture(1, true));
    let mut input = base.clone();
    input.statement[3] = [0xff; 32];
    assert_eq!(
        check_request(&input.statement, &input.witness),
        Err(Rejected("input 3"))
    );
    let mut input = base.clone();
    input.statement[6][23] = 1;
    assert_eq!(
        check_request(&input.statement, &input.witness),
        Err(Rejected("Q2"))
    );
    let mut input = base.clone();
    input.witness.blinding[0] = 0x08;
    assert_eq!(
        check_request(&input.statement, &input.witness),
        Err(Rejected("witness"))
    );
    let mut input = base;
    input.witness.state_signature.r_x[31] ^= 1;
    assert_eq!(
        check_request(&input.statement, &input.witness),
        Err(Rejected("Q7"))
    );
}
