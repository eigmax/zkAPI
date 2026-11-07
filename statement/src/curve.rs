//! Baby-JubJub as arkworks' `ark-ed-on-bn254` models it: `x² + y² = 1 + d·x²·y²` (a = 1) over
//! the BN254 scalar field. Points are kept in extended coordinates `(X, Y, T, Z)`, `x = X/Z`,
//! `y = Y/Z`, `x·y = T/Z`. The formulas (Hisil–Wong–Carter–Dawson 2008) are complete on this
//! curve (a square, d not), so they agree with arkworks' group law on every curve point,
//! including those outside the prime-order subgroup.

use ark_ff::BigInteger256;

use crate::constants::EDWARDS_D;
use crate::fr::F;

/// An affine point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Affine {
    pub x: F,
    pub y: F,
}

impl Affine {
    /// The point `(x, y)` if it is on the curve.
    pub fn on_curve(x: F, y: F) -> Option<Affine> {
        let (xx, yy) = (x.square(), y.square());
        (xx + yy == F::ONE + EDWARDS_D * xx * yy).then_some(Affine { x, y })
    }
}

/// A point in extended coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    x: F,
    y: F,
    t: F,
    z: F,
}

impl From<Affine> for Point {
    fn from(point: Affine) -> Point {
        Point {
            x: point.x,
            y: point.y,
            t: point.x * point.y,
            z: F::ONE,
        }
    }
}

impl Point {
    pub const IDENTITY: Point = Point {
        x: F::ZERO,
        y: F::ONE,
        t: F::ZERO,
        z: F::ONE,
    };

    /// `add-2008-hwcd` with a = 1.
    pub fn add(&self, other: &Point) -> Point {
        let a = self.x * other.x;
        let b = self.y * other.y;
        let c = self.t * EDWARDS_D * other.t;
        let d = self.z * other.z;
        let e = (self.x + self.y) * (other.x + other.y) - a - b;
        let f = d - c;
        let g = d + c;
        let h = b - a;
        Point {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }

    /// `dbl-2008-hwcd` with a = 1.
    pub fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().double();
        let e = (self.x + self.y).square() - a - b;
        let g = a + b;
        let f = g - c;
        let h = a - b;
        Point {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }

    /// `scalar · self`, the scalar taken as a plain integer (not reduced), double-and-add from
    /// its top bit.
    pub fn mul(&self, scalar: &BigInteger256) -> Point {
        let mut out = Point::IDENTITY;
        let mut started = false;
        for i in (0..256).rev() {
            if started {
                out = out.double();
            }
            if (scalar.0[i / 64] >> (i % 64)) & 1 == 1 {
                out = if started { out.add(self) } else { *self };
                started = true;
            }
        }
        out
    }

    /// `8 · self`.
    pub fn mul_by_cofactor(&self) -> Point {
        self.double().double().double()
    }

    pub fn to_affine(&self) -> Affine {
        let z_inverse = self.z.inverse();
        Affine {
            x: self.x * z_inverse,
            y: self.y * z_inverse,
        }
    }

    pub fn equals(&self, other: &Point) -> bool {
        self.x * other.z == other.x * self.z && self.y * other.z == other.y * self.z
    }

    pub fn equals_affine(&self, other: &Affine) -> bool {
        self.x == other.x * self.z && self.y == other.y * self.z
    }
}
