//! BN254 scalar-field elements as canonical little-endian `u32` limbs.
//!
//! In a Ziren guest a multiplication is one `uint256_mulmod` precompile call, whose output the
//! chip constrains below the modulus; natively it goes through arkworks. Addition, subtraction
//! and everything built on them run the same code in both, so the native tests cover all but
//! the precompile call.

use core::ops::{Add, Mul, Sub};

use ark_bn254::Fr;
use ark_ff::{BigInteger256, PrimeField};

/// A field element: its canonical value, little-endian `u32` limbs, below [`MODULUS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct F(pub [u32; 8]);

/// The BN254 scalar modulus, little-endian limbs.
pub const MODULUS: [u32; 8] = [
    0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
];

/// `MODULUS - 2`, the inversion exponent.
const MODULUS_MINUS_TWO: [u32; 8] = [
    0xefffffff, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
];

fn add_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let sum = a[i] as u64 + b[i] as u64 + carry;
        out[i] = sum as u32;
        carry = sum >> 32;
    }
    (out, carry != 0)
}

fn sub_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
    let mut out = [0u32; 8];
    let mut borrow = 0i64;
    for i in 0..8 {
        let difference = a[i] as i64 - b[i] as i64 - borrow;
        out[i] = difference as u32;
        borrow = i64::from(difference < 0);
    }
    (out, borrow != 0)
}

fn at_least_modulus(a: &[u32; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] != MODULUS[i] {
            return a[i] > MODULUS[i];
        }
    }
    true
}

impl F {
    pub const ZERO: F = F([0; 8]);
    pub const ONE: F = F([1, 0, 0, 0, 0, 0, 0, 0]);

    pub const fn from_u64(value: u64) -> F {
        F([value as u32, (value >> 32) as u32, 0, 0, 0, 0, 0, 0])
    }

    /// The element whose canonical value is `limbs`, if it is below the modulus.
    pub fn from_limbs(limbs: [u32; 8]) -> Option<F> {
        (!at_least_modulus(&limbs)).then_some(F(limbs))
    }

    /// The element of a 32-byte big-endian word, if the word is below the modulus.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Option<F> {
        let mut limbs = [0u32; 8];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = 28 - 4 * i;
            *limb = u32::from_be_bytes(bytes[start..start + 4].try_into().expect("4 bytes"));
        }
        F::from_limbs(limbs)
    }

    /// The big-endian integer `bytes`, for at most 31 bytes (so below the modulus).
    pub fn from_short_be_bytes(bytes: &[u8]) -> F {
        assert!(bytes.len() < 32, "at most 31 bytes");
        let mut word = [0u8; 32];
        word[32 - bytes.len()..].copy_from_slice(bytes);
        F::from_be_bytes(&word).expect("below 2^248")
    }

    pub fn from_ark(value: &Fr) -> F {
        let limbs = value.into_bigint().0;
        let mut out = [0u32; 8];
        for (i, limb) in limbs.iter().enumerate() {
            out[2 * i] = *limb as u32;
            out[2 * i + 1] = (*limb >> 32) as u32;
        }
        F(out)
    }

    pub fn to_ark(self) -> Fr {
        Fr::from_bigint(self.integer()).expect("canonical")
    }

    /// The canonical value as an integer.
    pub fn integer(self) -> BigInteger256 {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            *limb = self.0[2 * i] as u64 | (self.0[2 * i + 1] as u64) << 32;
        }
        BigInteger256::new(limbs)
    }

    /// Bits of the canonical value.
    pub fn num_bits(self) -> u32 {
        for i in (0..8).rev() {
            if self.0[i] != 0 {
                return 32 * i as u32 + 32 - self.0[i].leading_zeros();
            }
        }
        0
    }

    pub fn is_zero(self) -> bool {
        self == F::ZERO
    }

    pub fn double(self) -> F {
        self + self
    }

    pub fn square(self) -> F {
        self * self
    }

    /// `self^5`, the Poseidon S-box.
    pub fn pow5(self) -> F {
        self.square().square() * self
    }

    /// The inverse, by Fermat (`self^(p-2)`); zero for zero.
    pub fn inverse(self) -> F {
        let mut out = F::ONE;
        for i in (0..256).rev() {
            out = out.square();
            if (MODULUS_MINUS_TWO[i / 32] >> (i % 32)) & 1 == 1 {
                out = out * self;
            }
        }
        out
    }
}

impl Add for F {
    type Output = F;

    fn add(self, other: F) -> F {
        let (sum, carry) = add_raw(&self.0, &other.0);
        if carry || at_least_modulus(&sum) {
            F(sub_raw(&sum, &MODULUS).0)
        } else {
            F(sum)
        }
    }
}

impl Sub for F {
    type Output = F;

    fn sub(self, other: F) -> F {
        let (difference, borrow) = sub_raw(&self.0, &other.0);
        if borrow {
            F(add_raw(&difference, &MODULUS).0)
        } else {
            F(difference)
        }
    }
}

impl Mul for F {
    type Output = F;

    #[cfg(target_os = "zkvm")]
    fn mul(self, other: F) -> F {
        let mut x = self.0;
        let mut y = [0u32; 16];
        y[..8].copy_from_slice(&other.0);
        y[8..].copy_from_slice(&MODULUS);
        zkm_zkvm::syscalls::syscall_uint256_mulmod(&mut x, y.as_ptr() as *const [u32; 8]);
        F(x)
    }

    #[cfg(not(target_os = "zkvm"))]
    fn mul(self, other: F) -> F {
        F::from_ark(&(self.to_ark() * other.to_ark()))
    }
}
