//! The two statements of zkAPI v2 (circuit `zkapi-v2-concession-v2`), checked natively.
//!
//! A Ziren guest runs [`check_request`] or [`check_withdrawal`] on a statement and its
//! witness, and commits the statement's words ([`public_values`]). The checks accept exactly
//! the pairs that satisfy upstream's Groth16 circuits (`zkapi-proof/src/groth16.rs`); the
//! `conformance` crate tests this against those circuits. Labels Q1–Q10 and W1–W14 are the
//! circuits' constraint groups.
//!
//! The checks follow the circuits' gadgets, not only the native helpers:
//!
//! * a public point is checked to be on the curve, not to be in the prime-order subgroup;
//! * a signature's `R` is given as `R' = R · cofactor⁻¹`, must be on the curve even when the
//!   signature is not checked (genesis, or a withdrawal that is not a mutual close), and is
//!   used as `cofactor · R'`, which lies in the prime-order subgroup;
//! * signature scalars and blindings are any 251-bit integers;
//! * the Schnorr challenge multiplies the public key as the full 254-bit hash, unreduced;
//! * the note leaf multiplies its generator as its canonical 254-bit value.
//!
//! The arithmetic runs on [`fr::F`] (Poseidon in [`poseidon`], Baby-JubJub in [`curve`]), whose
//! multiplication is Ziren's `uint256_mulmod` precompile in the guest; the parameters are the
//! constants in [`constants`], which the tests check against their derivations.

#[rustfmt::skip]
mod constants;
pub mod curve;
pub mod fr;
pub mod poseidon;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig};
use ark_ff::{BigInteger, BigInteger256, Field, One, PrimeField};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use curve::{Affine, Point};
use fr::F;

/// A statement word or a field-element witness: 32 bytes, big-endian.
pub type Word = [u8; 32];

pub const REQUEST_WORDS: usize = 12;
pub const WITHDRAWAL_WORDS: usize = 16;
pub const MERKLE_DEPTH: usize = 32;
/// Bits of a signature scalar or blinding witness (the Baby-JubJub scalar field's size).
pub const SCALAR_BITS: u32 = 251;
/// Bits of a withdrawal destination (W12).
pub const DESTINATION_BITS: u32 = 160;

const DOMAIN_REG: &[u8] = b"zkapi.v2.reg";
const DOMAIN_LEAF: &[u8] = b"zkapi.v2c.leaf";
const DOMAIN_NODE: &[u8] = b"zkapi.v2.node";
const DOMAIN_NULLIFIER: &[u8] = b"zkapi.v2c.null";
const DOMAIN_ANCHOR: &[u8] = b"zkapi.v2c.anchor";
const DOMAIN_AUTHORIZATION: &[u8] = b"zkapi.v2.auth";
const DOMAIN_STATE: &[u8] = b"zkapi.v2.state";
const DOMAIN_CLEARANCE: &[u8] = b"zkapi.v2.clear";
const DOMAIN_SIGNATURE: &[u8] = b"zkapi.v2.sig";
/// The label upstream derives the blinding generator `H` from.
pub const BLINDING_LABEL: &[u8] = b"zkapi.v2.balance.blinding.generator";
/// The label upstream derives the note-binding generator `J` from.
pub const NOTE_LABEL: &[u8] = b"zkapi.v2.note-binding.generator.v1";

/// Why a statement was refused: the circuit constraint group it fails (`"Q5"`, `"W13"`),
/// `"input N"` for a statement word the circuit cannot take, or `"witness"` for a witness
/// encoding no circuit witness has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejected(pub &'static str);

/// A Schnorr signature witness. `r_x`, `r_y` are `R' = R · cofactor⁻¹`; `s` is below 2^251.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub r_x: Word,
    pub r_y: Word,
    pub s: Word,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestWitness {
    pub secret: Word,
    pub request_context: Word,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub merkle_siblings: [Word; MERKLE_DEPTH],
    pub balance: u128,
    pub blinding: Word,
    pub rerandomization: Word,
    pub anchor: Word,
    pub prev_anchor: Word,
    pub state_signature: Signature,
}

/// The guest's input for a request proof: the 12 statement words, in upstream's order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestInput {
    pub statement: [Word; REQUEST_WORDS],
    pub witness: RequestWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalWitness {
    pub secret: Word,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub balance: u128,
    pub blinding: Word,
    pub anchor: Word,
    pub state_signature: Signature,
    pub clearance_signature: Signature,
}

/// The guest's input for a withdrawal proof: the 16 statement words, in upstream's order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalInput {
    pub statement: [Word; WITHDRAWAL_WORDS],
    pub witness: WithdrawalWitness,
}

/// Either statement with its witness: the prover's input file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Input {
    Request(RequestInput),
    Withdrawal(WithdrawalInput),
}

impl Input {
    pub fn statement(&self) -> &[Word] {
        match self {
            Input::Request(input) => &input.statement,
            Input::Withdrawal(input) => &input.statement,
        }
    }

    pub fn check(&self) -> Result<(), Rejected> {
        match self {
            Input::Request(input) => check_request(&input.statement, &input.witness),
            Input::Withdrawal(input) => check_withdrawal(&input.statement, &input.witness),
        }
    }
}

/// The proof's public values: the statement words, concatenated. This is
/// `abi.encodePacked` of the statement as `uint256` words.
pub fn public_values(statement: &[Word]) -> Vec<u8> {
    statement.concat()
}

pub fn word(value: &Fr) -> Word {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

pub fn integer_word(value: &BigInteger256) -> Word {
    let mut out = [0u8; 32];
    for (index, limb) in value.0.iter().enumerate() {
        out[24 - 8 * index..32 - 8 * index].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn integer(word: &Word) -> BigInteger256 {
    let mut limbs = [0u64; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = 24 - 8 * index;
        *limb = u64::from_be_bytes(word[start..start + 8].try_into().expect("8 bytes"));
    }
    BigInteger256::new(limbs)
}

/// A canonical field element (below the BN254 scalar modulus).
fn felt(word: &Word) -> Option<F> {
    F::from_be_bytes(word)
}

/// An integer below 2^bits, for bits ≤ 128.
fn bounded(word: &Word, bits: u32) -> Option<u128> {
    let value = integer(word);
    let high = (value.0[2] | value.0[3]) != 0;
    let low = (value.0[1] as u128) << 64 | value.0[0] as u128;
    if high || (bits < 128 && low >> bits != 0) {
        return None;
    }
    Some(low)
}

/// A 251-bit scalar witness.
fn scalar(word: &Word) -> Result<BigInteger256, Rejected> {
    let value = integer(word);
    if value.0[3] >> (SCALAR_BITS - 192) != 0 {
        return Err(Rejected("witness"));
    }
    Ok(value)
}

fn input(statement: &[Word], index: usize, label: &'static str) -> Result<F, Rejected> {
    felt(&statement[index]).ok_or(Rejected(label))
}

fn witness_felt(word: &Word) -> Result<F, Rejected> {
    felt(word).ok_or(Rejected("witness"))
}

/// Runs `f` inside the Ziren cycle-tracker scope `name` when built with the `profile` feature;
/// the executor's report then carries the scope's cycles, summed over its calls.
#[cfg_attr(not(feature = "profile"), allow(unused_variables))]
pub fn track<T>(name: &str, f: impl FnOnce() -> T) -> T {
    #[cfg(feature = "profile")]
    println!("cycle-tracker-report-start: {name}");
    let out = f();
    #[cfg(feature = "profile")]
    println!("cycle-tracker-report-end: {name}");
    out
}

/// Derives the Poseidon parameters as upstream does (`find_poseidon_ark_and_mds`, 8 full and 57
/// partial rounds, rate 2, alpha 5).
pub fn derive_poseidon_config() -> PoseidonConfig<Fr> {
    let full_rounds = 8;
    let partial_rounds = 57;
    let rate = 2;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds,
        partial_rounds,
        0,
    );
    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        5,
        mds,
        ark,
        rate,
        1,
    )
}

/// Derives a generator from `label` as upstream does: keccak-to-curve with a counter, then the
/// cofactor cleared.
pub fn derive_generator(label: &[u8]) -> EdwardsAffine {
    for counter in 0u32..u32::MAX {
        let mut digest = Keccak256::new();
        digest.update(label);
        digest.update(counter.to_be_bytes());
        let x = Fr::from_be_bytes_mod_order(&digest.finalize());
        let x_squared = x.square();
        let numerator = Fr::one() - x_squared;
        let denominator = Fr::one() - (EdwardsConfig::COEFF_D * x_squared);
        let Some(denominator_inverse) = denominator.inverse() else {
            continue;
        };
        let Some(mut y) = (numerator * denominator_inverse).sqrt() else {
            continue;
        };
        if y.into_bigint().is_odd() {
            y = -y;
        }
        let point = EdwardsAffine::new_unchecked(x, y)
            .mul_bigint(EdwardsConfig::COFACTOR)
            .into_affine();
        if !point.is_zero() && point.is_in_correct_subgroup_assuming_on_curve() {
            return point;
        }
    }
    unreachable!("hash-to-curve counter exhausted")
}

fn domain(label: &[u8]) -> F {
    F::from_short_be_bytes(label)
}

/// The Poseidon sponge hash of a fixed-arity input.
pub fn hash(inputs: &[F]) -> F {
    track("poseidon-hash", || poseidon::hash(inputs))
}

/// One permutation of `(capacity, left, right)`, its first rate lane.
pub fn compress(capacity: F, left: F, right: F) -> F {
    track("poseidon-hash", || {
        poseidon::compress(capacity, left, right)
    })
}

pub fn registration(secret: F) -> F {
    hash(&[domain(DOMAIN_REG), secret, F::ZERO])
}

/// `F = n·2^192 + D·2^64 + e`.
pub fn note_fields(note_id: u32, deposit_amount: u128, expiry: u64) -> F {
    let mut bytes = [0u8; 32];
    bytes[4..8].copy_from_slice(&note_id.to_be_bytes());
    bytes[8..24].copy_from_slice(&deposit_amount.to_be_bytes());
    bytes[24..32].copy_from_slice(&expiry.to_be_bytes());
    felt(&bytes).expect("below 2^224")
}

pub fn note_leaf(secret: F, fields: F) -> F {
    compress(domain(DOMAIN_LEAF), registration(secret), fields)
}

pub fn merkle_node(left: F, right: F) -> F {
    compress(domain(DOMAIN_NODE), left, right)
}

pub fn merkle_root(note_id: u32, leaf: F, siblings: &[F]) -> F {
    track("merkle-root", || {
        let mut current = leaf;
        for (level, sibling) in siblings.iter().enumerate() {
            current = if (note_id >> level) & 1 == 0 {
                merkle_node(current, *sibling)
            } else {
                merkle_node(*sibling, current)
            };
        }
        current
    })
}

pub fn nullifier(secret: F, note_id: u32, anchor: F) -> F {
    hash(&[
        domain(DOMAIN_NULLIFIER),
        secret,
        F::from_u64(note_id.into()),
        anchor,
    ])
}

pub fn next_anchor(nullifier: F) -> F {
    hash(&[domain(DOMAIN_ANCHOR), nullifier])
}

pub fn authorization_tag(nullifier: F, request_context: F) -> F {
    hash(&[domain(DOMAIN_AUTHORIZATION), nullifier, request_context])
}

fn state_message(
    protocol_version: F,
    chain_id: F,
    contract: F,
    commitment: &Affine,
    anchor: F,
) -> F {
    hash(&[
        domain(DOMAIN_STATE),
        protocol_version,
        chain_id,
        contract,
        commitment.x,
        commitment.y,
        anchor,
    ])
}

fn clearance_message(protocol_version: F, chain_id: F, contract: F, nullifier: F) -> F {
    hash(&[
        domain(DOMAIN_CLEARANCE),
        protocol_version,
        chain_id,
        contract,
        nullifier,
    ])
}

fn ark_point(point: &Affine) -> EdwardsAffine {
    EdwardsAffine::new_unchecked(point.x.to_ark(), point.y.to_ark())
}

/// The Baby-JubJub generator `G`, arkworks' `EdwardsConfig::GENERATOR`.
pub fn generator() -> EdwardsAffine {
    ark_point(&constants::GENERATOR)
}

/// The blinding generator `H`, upstream's `balance_blinding_generator`.
pub fn blinding_generator() -> EdwardsAffine {
    ark_point(&constants::BLINDING_GENERATOR)
}

/// The note-binding generator `J`, upstream's `note_binding_generator`.
pub fn note_generator() -> EdwardsAffine {
    ark_point(&constants::NOTE_GENERATOR)
}

/// `C = B·G + r·H + L·J`, with `r` any 251-bit integer and `L` by its canonical value.
pub fn commitment(balance: u128, blinding: &BigInteger256, leaf: F) -> Point {
    track("commitment", || {
        let balance = BigInteger256::new([balance as u64, (balance >> 64) as u64, 0, 0]);
        Point::from(constants::GENERATOR)
            .mul(&balance)
            .add(&Point::from(constants::BLINDING_GENERATOR).mul(blinding))
            .add(&Point::from(constants::NOTE_GENERATOR).mul(&leaf.integer()))
    })
}

struct Schnorr {
    r_prime: Affine,
    s: BigInteger256,
}

/// Decodes a signature witness as the circuit allocates it: `R'` on the curve (else the
/// constraint group `label` fails, whether or not the signature is checked); a check uses
/// `R = 8·R'`.
fn schnorr(signature: &Signature, label: &'static str) -> Result<Schnorr, Rejected> {
    let r_prime = Affine::on_curve(witness_felt(&signature.r_x)?, witness_felt(&signature.r_y)?)
        .ok_or(Rejected(label))?;
    Ok(Schnorr {
        r_prime,
        s: scalar(&signature.s)?,
    })
}

impl Schnorr {
    /// `s·G == R + c·PK`, with `c` the full challenge hash.
    fn verifies(&self, public_key: &Affine, message: F) -> bool {
        let r = track("signature-cofactor", || {
            Point::from(self.r_prime).mul_by_cofactor().to_affine()
        });
        let challenge = hash(&[domain(DOMAIN_SIGNATURE), r.x, r.y, message]);
        track("schnorr-scalar-muls", || {
            Point::from(constants::GENERATOR)
                .mul(&self.s)
                .equals(&Point::from(r).add(&Point::from(*public_key).mul(&challenge.integer())))
        })
    }
}

/// The request statement, Q1–Q10.
pub fn check_request(
    statement: &[Word; REQUEST_WORDS],
    witness: &RequestWitness,
) -> Result<(), Rejected> {
    let protocol_version = input(statement, 0, "input 0")?;
    let chain_id = input(statement, 1, "input 1")?;
    let contract = input(statement, 2, "input 2")?;
    let active_root = input(statement, 3, "input 3")?;
    let state_key = Affine::on_curve(
        input(statement, 4, "input 4")?,
        input(statement, 5, "input 5")?,
    )
    .ok_or(Rejected("input 4"))?;
    let request_time = bounded(&statement[6], 64).ok_or(Rejected("Q2"))? as u64;
    let solvency_bound = bounded(&statement[7], 128).ok_or(Rejected("Q3"))?;
    let request_nullifier = input(statement, 8, "input 8")?;
    let authorization = input(statement, 9, "input 9")?;
    let anonymous = Affine::on_curve(
        input(statement, 10, "input 10")?,
        input(statement, 11, "input 11")?,
    )
    .ok_or(Rejected("input 10"))?;

    let secret = witness_felt(&witness.secret)?;
    let request_context = witness_felt(&witness.request_context)?;
    let anchor = witness_felt(&witness.anchor)?;
    let prev_anchor = witness_felt(&witness.prev_anchor)?;
    let siblings = witness
        .merkle_siblings
        .iter()
        .map(witness_felt)
        .collect::<Result<Vec<_>, _>>()?;
    let blinding = scalar(&witness.blinding)?;
    let rerandomization = scalar(&witness.rerandomization)?;
    let signature = schnorr(&witness.state_signature, "Q7")?;

    if secret.is_zero() {
        return Err(Rejected("Q1"));
    }
    if witness.expiry < request_time {
        return Err(Rejected("Q2"));
    }
    if witness.balance < solvency_bound {
        return Err(Rejected("Q3"));
    }
    if witness.deposit_amount < witness.balance {
        return Err(Rejected("Q4"));
    }
    let fields = note_fields(witness.note_id, witness.deposit_amount, witness.expiry);
    let leaf = note_leaf(secret, fields);
    if merkle_root(witness.note_id, leaf, &siblings) != active_root {
        return Err(Rejected("Q5"));
    }
    let genesis = anchor == F::ONE;
    if genesis && witness.balance != witness.deposit_amount {
        return Err(Rejected("Q6"));
    }
    if !genesis && anchor != next_anchor(nullifier(secret, witness.note_id, prev_anchor)) {
        return Err(Rejected("Q6a"));
    }
    let current = commitment(witness.balance, &blinding, leaf);
    if !genesis {
        let message = state_message(
            protocol_version,
            chain_id,
            contract,
            &current.to_affine(),
            anchor,
        );
        if !signature.verifies(&state_key, message) {
            return Err(Rejected("Q7"));
        }
    }
    let rerandomized = track("rerandomize", || {
        current.add(&Point::from(constants::BLINDING_GENERATOR).mul(&rerandomization))
    });
    if !rerandomized.equals_affine(&anonymous) {
        return Err(Rejected("Q8"));
    }
    if nullifier(secret, witness.note_id, anchor) != request_nullifier {
        return Err(Rejected("Q9"));
    }
    if authorization_tag(request_nullifier, request_context) != authorization {
        return Err(Rejected("Q10"));
    }
    Ok(())
}

/// The withdrawal statement, W1–W14.
pub fn check_withdrawal(
    statement: &[Word; WITHDRAWAL_WORDS],
    witness: &WithdrawalWitness,
) -> Result<(), Rejected> {
    let protocol_version = input(statement, 0, "input 0")?;
    let chain_id = input(statement, 1, "input 1")?;
    let contract = input(statement, 2, "input 2")?;
    let note_leaf_input = input(statement, 3, "input 3")?;
    let state_key = Affine::on_curve(
        input(statement, 4, "input 4")?,
        input(statement, 5, "input 5")?,
    )
    .ok_or(Rejected("input 4"))?;
    let clearance_key = Affine::on_curve(
        input(statement, 6, "input 6")?,
        input(statement, 7, "input 7")?,
    )
    .ok_or(Rejected("input 6"))?;
    let fields_input = input(statement, 8, "input 8")?;
    let final_balance = bounded(&statement[9], 128).ok_or(Rejected("W3"))?;
    let destination = input(statement, 10, "input 10")?;
    let withdrawal_nullifier = input(statement, 11, "input 11")?;
    let kind = input(statement, 12, "input 12")?;
    let next_nullifier = input(statement, 13, "input 13")?;
    let conceded = bounded(&statement[14], 128).ok_or(Rejected("W3"))?;
    bounded(&statement[15], 64).ok_or(Rejected("W14"))?;

    let secret = witness_felt(&witness.secret)?;
    let anchor = witness_felt(&witness.anchor)?;
    let blinding = scalar(&witness.blinding)?;
    let state_signature = schnorr(&witness.state_signature, "W7")?;
    let clearance_signature = schnorr(&witness.clearance_signature, "W13")?;

    if secret.is_zero() {
        return Err(Rejected("W1"));
    }
    if note_fields(witness.note_id, witness.deposit_amount, witness.expiry) != fields_input {
        return Err(Rejected("W2"));
    }
    if final_balance.checked_add(conceded) != Some(witness.balance) {
        return Err(Rejected("W3"));
    }
    if witness.deposit_amount < witness.balance {
        return Err(Rejected("W4"));
    }
    let leaf = note_leaf(secret, fields_input);
    if leaf != note_leaf_input {
        return Err(Rejected("W5"));
    }
    let genesis = anchor == F::ONE;
    if genesis && witness.balance != witness.deposit_amount {
        return Err(Rejected("W6"));
    }
    if !genesis {
        let state = commitment(witness.balance, &blinding, leaf);
        let message = state_message(
            protocol_version,
            chain_id,
            contract,
            &state.to_affine(),
            anchor,
        );
        if !state_signature.verifies(&state_key, message) {
            return Err(Rejected("W7"));
        }
    }
    if nullifier(secret, witness.note_id, anchor) != withdrawal_nullifier {
        return Err(Rejected("W8"));
    }
    let (is_close, is_ownership) = if kind == F::ZERO {
        (false, false)
    } else if kind == F::ONE {
        (true, false)
    } else if kind == F::from_u64(2) {
        (false, true)
    } else {
        return Err(Rejected("W9"));
    };
    let is_escape = !is_close && !is_ownership;
    let expected_next = if is_escape {
        nullifier(secret, witness.note_id, next_anchor(withdrawal_nullifier))
    } else {
        F::ZERO
    };
    if next_nullifier != expected_next {
        return Err(Rejected("W10"));
    }
    if !is_escape && conceded != 0 {
        return Err(Rejected("W11"));
    }
    if destination.num_bits() > DESTINATION_BITS || (is_ownership && !destination.is_zero()) {
        return Err(Rejected("W12"));
    }
    if is_close {
        let clear = clearance_message(protocol_version, chain_id, contract, withdrawal_nullifier);
        if !clearance_signature.verifies(&clearance_key, clear) {
            return Err(Rejected("W13"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ed_on_bn254::EdwardsProjective;
    use ark_ff::{AdditiveGroup, UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};

    fn rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    fn edge_values() -> Vec<Fr> {
        vec![
            Fr::zero(),
            Fr::one(),
            -Fr::one(),
            -Fr::from(2u64),
            Fr::from(u64::MAX),
        ]
    }

    #[test]
    fn constants_match_their_derivation() {
        assert_eq!(F(fr::MODULUS).integer(), Fr::MODULUS);
        let derived = derive_poseidon_config();
        assert_eq!((derived.full_rounds, derived.partial_rounds), (8, 57));
        assert_eq!((derived.alpha, derived.rate, derived.capacity), (5, 2, 1));
        assert_eq!(derived.ark.len(), constants::POSEIDON_ARK.len());
        for (row, hardcoded) in derived.ark.iter().zip(constants::POSEIDON_ARK.iter()) {
            assert_eq!(
                row.iter().map(F::from_ark).collect::<Vec<_>>(),
                hardcoded.to_vec()
            );
        }
        assert_eq!(derived.mds.len(), constants::POSEIDON_MDS.len());
        for (row, hardcoded) in derived.mds.iter().zip(constants::POSEIDON_MDS.iter()) {
            assert_eq!(
                row.iter().map(F::from_ark).collect::<Vec<_>>(),
                hardcoded.to_vec()
            );
        }
        assert_eq!(blinding_generator(), derive_generator(BLINDING_LABEL));
        assert_eq!(note_generator(), derive_generator(NOTE_LABEL));
        assert_eq!(generator(), EdwardsConfig::GENERATOR);
        assert_eq!(constants::EDWARDS_D, F::from_ark(&EdwardsConfig::COEFF_D));
    }

    #[test]
    fn field_arithmetic_matches_arkworks() {
        let mut rng = rng();
        let mut values = edge_values();
        values.extend((0..200).map(|_| Fr::rand(&mut rng)));
        for (i, a) in values.iter().enumerate() {
            let b = values[(i * 7 + 3) % values.len()];
            let (fa, fb) = (F::from_ark(a), F::from_ark(&b));
            assert_eq!(fa.to_ark(), *a);
            assert_eq!((fa + fb).to_ark(), *a + b);
            assert_eq!((fa - fb).to_ark(), *a - b);
            assert_eq!((fa * fb).to_ark(), *a * b);
            assert_eq!(fa.pow5().to_ark(), a.pow([5u64]));
            assert_eq!(fa.inverse().to_ark(), a.inverse().unwrap_or(Fr::zero()));
            assert_eq!(fa.num_bits(), a.into_bigint().num_bits());
            assert_eq!(felt(&word(a)), Some(fa));
        }
        assert_eq!(F::from_limbs(fr::MODULUS), None);
        assert_eq!(felt(&[0xff; 32]), None);
    }

    #[test]
    fn poseidon_matches_the_arkworks_sponge() {
        let config = derive_poseidon_config();
        let mut rng = rng();
        for arity in 1..=8 {
            for _ in 0..4 {
                let inputs = (0..arity).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
                let mut sponge = PoseidonSponge::new(&config);
                sponge.absorb(&inputs);
                let expected = sponge.squeeze_native_field_elements(1)[0];
                let ours = poseidon::hash(&inputs.iter().map(F::from_ark).collect::<Vec<_>>());
                assert_eq!(ours.to_ark(), expected, "arity {arity}");
            }
        }
        let (capacity, left, right) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
        let mut sponge = PoseidonSponge::new(&config);
        sponge.state[0] = capacity;
        sponge.absorb(&vec![left, right]);
        let expected = sponge.squeeze_native_field_elements(1)[0];
        let ours = poseidon::compress(
            F::from_ark(&capacity),
            F::from_ark(&left),
            F::from_ark(&right),
        );
        assert_eq!(ours.to_ark(), expected);
    }

    fn ours(point: &EdwardsAffine) -> Affine {
        Affine::on_curve(F::from_ark(&point.x), F::from_ark(&point.y)).expect("on the curve")
    }

    fn same(point: &Point, expected: &EdwardsProjective) -> bool {
        let expected = expected.into_affine();
        point.equals_affine(&ours(&expected)) && point.to_affine() == ours(&expected)
    }

    #[test]
    fn curve_arithmetic_matches_arkworks() {
        let mut rng = rng();
        let order_two = EdwardsAffine::new_unchecked(Fr::zero(), -Fr::one());
        assert!(order_two.is_on_curve());
        let mut points = vec![EdwardsAffine::zero(), order_two, EdwardsConfig::GENERATOR];
        for _ in 0..12 {
            let point = (EdwardsProjective::generator() * ark_ed_on_bn254::Fr::rand(&mut rng))
                .into_affine();
            points.push(point);
            points.push((point.into_group() + order_two.into_group()).into_affine());
        }
        for (i, a) in points.iter().enumerate() {
            let b = points[(i * 5 + 1) % points.len()];
            let (pa, pb) = (Point::from(ours(a)), Point::from(ours(&b)));
            assert!(same(&pa.add(&pb), &(a.into_group() + b.into_group())));
            assert!(same(&pa.double(), &a.into_group().double()));
            assert!(same(
                &pa.mul_by_cofactor(),
                &a.mul_by_cofactor().into_group()
            ));
            let mut limbs = [0u64; 4];
            for limb in limbs.iter_mut() {
                *limb = rng.gen();
            }
            limbs[3] >>= rng.gen_range(0..64);
            let scalar = BigInteger256::new(limbs);
            assert!(same(&pa.mul(&scalar), &a.mul_bigint(scalar)));
            assert!(same(
                &pa.mul(&BigInteger256::zero()),
                &EdwardsProjective::zero()
            ));
            assert_eq!(pa.equals(&pb), a == &b);
        }
        for _ in 0..50 {
            let (x, y) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            let expected = EdwardsAffine::new_unchecked(x, y).is_on_curve();
            assert_eq!(
                Affine::on_curve(F::from_ark(&x), F::from_ark(&y)).is_some(),
                expected
            );
        }
    }

    fn hex(value: &str) -> F {
        let bytes = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        felt(&bytes.try_into().unwrap()).unwrap()
    }

    /// Upstream's specification vectors (`zkapi-core/src/v2.rs`).
    #[test]
    fn hashes_match_the_specification_vectors() {
        let registration = registration(F::from_u64(42));
        assert_eq!(
            registration,
            hex("26538304fc53474b13823162f0b9667c1538c7360828d3a1a2e8ffa019a2f8cc")
        );
        let fields = note_fields(7, 5_000_000, 4_000_000_000);
        assert_eq!(
            fields,
            hex("0000000000000007000000000000000000000000004c4b4000000000ee6b2800")
        );
        assert_eq!(
            compress(domain(DOMAIN_LEAF), registration, fields),
            hex("1698e82280376fc3506cb7ebf7278db1764d0183aea5fd4d3b475c644b61395f")
        );
        assert_eq!(
            merkle_node(F::from_u64(1), F::from_u64(2)),
            hex("178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1")
        );
    }

    #[test]
    fn words_round_trip() {
        let value = hex("1698e82280376fc3506cb7ebf7278db1764d0183aea5fd4d3b475c644b61395f");
        assert_eq!(felt(&word(&value.to_ark())), Some(value));
        assert_eq!(integer(&integer_word(&value.integer())), value.integer());
        assert_eq!(
            bounded(&word(&Fr::from(u64::MAX)), 64),
            Some(u64::MAX as u128)
        );
        assert_eq!(bounded(&word(&(Fr::from(u64::MAX) + Fr::one())), 64), None);
        let mut top = [0u8; 32];
        top[0] = 0x04;
        assert!(scalar(&top).is_ok());
        top[0] = 0x08;
        assert!(scalar(&top).is_err());
    }
}
