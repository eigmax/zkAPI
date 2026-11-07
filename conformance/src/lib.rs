//! Upstream zkAPI fixtures, and their conversion to the Ziren statements' encoding.
//!
//! [`satisfied_request`] and [`satisfied_withdrawal`] run upstream's own Groth16 circuits
//! (`zkapi_proof::groth16`) over a statement and witness, so a test can compare their verdict
//! with [`zkapi_ziren_statement::check_request`] and `check_withdrawal`.

use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, Fr as ScalarField};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisMode};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use zkapi_proof::groth16::{
    authorization_tag, balance_commitment, clearance_message, merkle_root, next_anchor,
    note_fields, note_leaf, nullifier, registration_commitment, rerandomize_commitment,
    state_message, successor_nullifier, synthesize, RequestCircuit, RequestPublic,
    RequestWitness, StateSignature, StateSigningKey, WithdrawalCircuit, WithdrawalPublic,
    WithdrawalWitness, REQUEST_MERKLE_DEPTH,
};
use zkapi_ziren_statement as ziren;

pub const PROTOCOL_VERSION: u16 = 2;
pub const CHAIN_ID: u64 = 11_155_111;

pub fn contract() -> Fr {
    Fr::from(0xdead_u64)
}

pub fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// The placeholder signature of a state that is not signed, as upstream's wallet sends it.
pub fn empty_signature() -> StateSignature {
    StateSignature {
        r: EdwardsAffine::zero(),
        s: ScalarField::from(0u64),
    }
}

/// A note in a tree whose other leaves are random.
pub struct Note {
    pub secret: Fr,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub siblings: [Fr; REQUEST_MERKLE_DEPTH],
}

impl Note {
    pub fn new(rng: &mut StdRng, note_id: u32) -> Self {
        let mut siblings = [Fr::zero(); REQUEST_MERKLE_DEPTH];
        for sibling in siblings.iter_mut() {
            *sibling = Fr::rand(rng);
        }
        Self {
            secret: Fr::rand(rng),
            note_id,
            deposit_amount: 5_000_000,
            expiry: 4_000_000_000,
            siblings,
        }
    }

    pub fn leaf(&self) -> Fr {
        note_leaf(
            self.note_id,
            registration_commitment(self.secret),
            self.deposit_amount,
            self.expiry,
        )
    }

    pub fn root(&self) -> Fr {
        merkle_root(self.note_id, self.leaf(), &self.siblings)
    }
}

/// A request at a signed state (`signed`) or at genesis.
pub fn request_fixture(seed: u64, signed: bool) -> RequestCircuit {
    let mut rng = rng(seed);
    let note = Note::new(&mut rng, 0x5a5a_1234);
    let leaf = note.leaf();
    let signer = StateSigningKey::generate(&mut rng);
    let (balance, blinding, anchor, prev_anchor) = if signed {
        let prev_anchor = next_anchor(nullifier(note.secret, note.note_id, Fr::from(1u64)));
        let anchor = next_anchor(nullifier(note.secret, note.note_id, prev_anchor));
        (4_900_000, ScalarField::rand(&mut rng), anchor, prev_anchor)
    } else {
        (note.deposit_amount, ScalarField::rand(&mut rng), Fr::from(1u64), Fr::zero())
    };
    let commitment = balance_commitment(balance, blinding, leaf).into_affine();
    let signature = if signed {
        let message = state_message(PROTOCOL_VERSION, CHAIN_ID, contract(), commitment, anchor);
        signer.sign(message, &mut rng)
    } else {
        empty_signature()
    };
    let rerandomization = ScalarField::rand(&mut rng);
    let anonymous = rerandomize_commitment(commitment.into_group(), rerandomization).into_affine();
    let request_context = Fr::rand(&mut rng);
    let request_nullifier = nullifier(note.secret, note.note_id, anchor);
    RequestCircuit {
        public: RequestPublic {
            protocol_version: PROTOCOL_VERSION,
            chain_id: CHAIN_ID,
            contract_address: contract(),
            active_root: note.root(),
            state_signing_key: signer.public,
            request_time: 3_000_000_000,
            solvency_bound: 1_000_000,
            request_nullifier,
            authorization_tag: authorization_tag(request_nullifier, request_context),
            anonymous_commitment: anonymous,
        },
        witness: RequestWitness {
            secret: note.secret,
            request_context,
            note_id: note.note_id,
            deposit_amount: note.deposit_amount,
            expiry: note.expiry,
            merkle_siblings: note.siblings,
            current_balance: balance,
            current_blinding: blinding,
            rerandomization,
            current_anchor: anchor,
            prev_anchor,
            state_signature: signature,
        },
    }
}

/// A withdrawal of `kind` (0 escape, 1 mutual close, 2 ownership proof) from a signed state,
/// or from genesis.
pub fn withdrawal_fixture(seed: u64, kind: u8, signed: bool) -> WithdrawalCircuit {
    let mut rng = rng(seed);
    let note = Note::new(&mut rng, 77);
    let leaf = note.leaf();
    let state_signer = StateSigningKey::generate(&mut rng);
    let clearance_signer = StateSigningKey::generate(&mut rng);
    let (balance, anchor) = if signed {
        (
            4_900_000,
            next_anchor(nullifier(note.secret, note.note_id, Fr::from(1u64))),
        )
    } else {
        (note.deposit_amount, Fr::from(1u64))
    };
    let blinding = ScalarField::rand(&mut rng);
    let commitment = balance_commitment(balance, blinding, leaf).into_affine();
    let state_signature = if signed {
        state_signer.sign(
            state_message(PROTOCOL_VERSION, CHAIN_ID, contract(), commitment, anchor),
            &mut rng,
        )
    } else {
        empty_signature()
    };
    let withdrawal_nullifier = nullifier(note.secret, note.note_id, anchor);
    let clearance_signature = if kind == 1 {
        clearance_signer.sign(
            clearance_message(PROTOCOL_VERSION, CHAIN_ID, contract(), withdrawal_nullifier),
            &mut rng,
        )
    } else {
        empty_signature()
    };
    let conceded = if kind == 0 { 250_000 } else { 0 };
    WithdrawalCircuit {
        public: WithdrawalPublic {
            protocol_version: PROTOCOL_VERSION,
            chain_id: CHAIN_ID,
            contract_address: contract(),
            note_leaf: leaf,
            state_signing_key: state_signer.public,
            clearance_signing_key: clearance_signer.public,
            note_fields: note_fields(note.note_id, note.deposit_amount, note.expiry),
            final_balance: balance - conceded,
            destination: if kind == 2 {
                Fr::zero()
            } else {
                Fr::from(0xbeef_u64)
            },
            withdrawal_nullifier,
            kind,
            next_nullifier: if kind == 0 {
                successor_nullifier(note.secret, note.note_id, anchor)
            } else {
                Fr::zero()
            },
            conceded,
            valid_until: 3_000_010_800,
        },
        witness: WithdrawalWitness {
            secret: note.secret,
            note_id: note.note_id,
            deposit_amount: note.deposit_amount,
            expiry: note.expiry,
            state_balance: balance,
            state_blinding: blinding,
            current_anchor: anchor,
            state_signature,
            clearance_signature,
        },
    }
}

fn statement<const N: usize>(fields: Vec<Fr>) -> [ziren::Word; N] {
    let words = fields.iter().map(ziren::word).collect::<Vec<_>>();
    words.try_into().expect("statement length")
}

fn scalar_word(value: &ScalarField) -> ziren::Word {
    ziren::integer_word(&value.into_bigint())
}

/// The witness of a signature as the guest takes it: `R' = R · cofactor⁻¹`.
pub fn signature(signature: &StateSignature) -> ziren::Signature {
    let r_prime = signature.r.mul_by_cofactor_inv();
    ziren::Signature {
        r_x: ziren::word(&r_prime.x),
        r_y: ziren::word(&r_prime.y),
        s: scalar_word(&signature.s),
    }
}

pub fn request_input(circuit: &RequestCircuit) -> ziren::RequestInput {
    let witness = &circuit.witness;
    ziren::RequestInput {
        statement: statement(circuit.public.to_field_elements()),
        witness: ziren::RequestWitness {
            secret: ziren::word(&witness.secret),
            request_context: ziren::word(&witness.request_context),
            note_id: witness.note_id,
            deposit_amount: witness.deposit_amount,
            expiry: witness.expiry,
            merkle_siblings: witness.merkle_siblings.map(|sibling| ziren::word(&sibling)),
            balance: witness.current_balance,
            blinding: scalar_word(&witness.current_blinding),
            rerandomization: scalar_word(&witness.rerandomization),
            anchor: ziren::word(&witness.current_anchor),
            prev_anchor: ziren::word(&witness.prev_anchor),
            state_signature: signature(&witness.state_signature),
        },
    }
}

pub fn withdrawal_input(circuit: &WithdrawalCircuit) -> ziren::WithdrawalInput {
    let witness = &circuit.witness;
    ziren::WithdrawalInput {
        statement: statement(circuit.public.to_field_elements()),
        witness: ziren::WithdrawalWitness {
            secret: ziren::word(&witness.secret),
            note_id: witness.note_id,
            deposit_amount: witness.deposit_amount,
            expiry: witness.expiry,
            balance: witness.state_balance,
            blinding: scalar_word(&witness.state_blinding),
            anchor: ziren::word(&witness.current_anchor),
            state_signature: signature(&witness.state_signature),
            clearance_signature: signature(&witness.clearance_signature),
        },
    }
}

fn satisfied(circuit: impl ConstraintSynthesizer<Fr>) -> bool {
    match synthesize(
        circuit,
        SynthesisMode::Prove {
            construct_matrices: true,
        },
    ) {
        Ok(cs) => cs.is_satisfied().unwrap_or(false),
        Err(_) => false,
    }
}

/// Upstream's verdict: does the request circuit accept this statement and witness?
pub fn satisfied_request(circuit: &RequestCircuit) -> bool {
    satisfied(circuit.clone())
}

/// Upstream's verdict: does the withdrawal circuit accept this statement and witness?
pub fn satisfied_withdrawal(circuit: &WithdrawalCircuit) -> bool {
    satisfied(circuit.clone())
}
