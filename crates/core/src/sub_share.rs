//! Sub-share types, abstractions and utilities.

use crypto_bigint::modular::constant_mod::ResidueParams;
use crypto_bigint::{const_residue, Encoding, U256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto;
use crate::crypto::Secp256k1Order;

/// A "signing share" as defined by the Wamu protocol.
///
/// Ref: <https://wamu.tech/specification#share-splitting-and-reconstruction>.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningShare([u8; 32]);

impl SigningShare {
    /// Generates a new "signing share" as a random 256 bit unsigned integer.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(crypto::random_mod().to_be_bytes())
    }

    /// Returns underlying 32 bytes for "signing share".
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<&[u8]> for SigningShare {
    /// Converts a slice of bytes to a "signing share".
    ///
    /// # Panics
    /// Panics if the input slice is not 32 bytes long.
    fn from(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), 32, "input slice should be 32 bytes long.");
        Self(
            slice.try_into().expect(
                "Should be able to convert Vec<u8> of length 32 (i.e 256 bits) to [u8; 32].",
            ),
        )
    }
}

/// A "sub-share" as defined by the Wamu protocol.
///
/// Ref: <https://wamu.tech/specification#share-splitting-and-reconstruction>.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SubShare {
    x: U256,
    y: U256,
}

impl SubShare {
    /// Initializes a new "sub-share".
    ///
    /// # Panics
    /// Panics if either the `x` or `y` coordinate is not less than the order of the `Secp256k1` curve.
    pub fn new(x: U256, y: U256) -> Self {
        assert!(
            x < Secp256k1Order::MODULUS,
            r#"The `x` coordinate for a "sub-share" must be less than the order of the `Secp256k1` curve."#
        );
        assert!(
            y < Secp256k1Order::MODULUS,
            r#"The `y` coordinate for a "sub-share" must be less than the order of the `Secp256k1` curve."#
        );
        Self { x, y }
    }

    /// Returns the `x` coordinate of the "sub-share".
    pub fn x(&self) -> U256 {
        self.x
    }

    /// Returns the `y` coordinate of the "sub-share".
    pub fn y(&self) -> U256 {
        self.y
    }

    /// Returns the `x` and `y` coordinates of the "sub-share" as an (`x`, `y`) tuple.
    pub fn as_tuple(&self) -> (U256, U256) {
        (self.x, self.y)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubShareInterpolator {
    gradient: U256,
    intercept: U256,
}

impl SubShareInterpolator {
    /// Given 2 "sub-shares" A and B, returns a "sub-share" interpolator.
    ///
    /// i.e a line (a polynomial of degree 1) such that A and B are both points on the line.
    pub fn new(point_a: &SubShare, point_b: &SubShare) -> Self {
        // dy/dx (mod q) is equivalent to dy * i where i is the modular multiplicative inverse of dx such that dx * i  ≡ 1 (mod q).
        // Ref: <http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation>.
        // NOTE: Since q is prime, gcd(dx, q) = 1, so a modular multiplicative inverse always exists and
        // is equivalent to the Bézout's identity coefficient for dx.
        // Ref: <https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity>.
        let x_1 = point_a.x;
        let y_1 = point_a.y;
        let x_2 = point_b.x;
        let y_2 = point_b.y;
        let dy = const_residue!(y_1, Secp256k1Order) - const_residue!(y_2, Secp256k1Order);
        let dx = const_residue!(x_1, Secp256k1Order) - const_residue!(x_2, Secp256k1Order);
        let gradient = dy * dx.invert().0;

        // From y = mx + c (mod q), we compute the intercept c = y - mx (mod q).
        let intercept_mod =
            const_residue!(y_1, Secp256k1Order) - (gradient * const_residue!(x_1, Secp256k1Order));

        Self {
            gradient: gradient.retrieve(),
            intercept: intercept_mod.retrieve(),
        }
    }

    /// Returns "secret share" for given "sub-shares".
    pub fn secret(&self) -> U256 {
        self.intercept
    }

    /// Returns a unique "sub-share" for the index.
    ///
    /// # Panics
    /// Panics if either the "index" is not less than the order of the `Secp256k1` curve or
    /// is equal to zero (because the "sub-share" associated with the zero "index" is the "secret share").
    pub fn sub_share(&self, idx: U256) -> SubShare {
        assert!(
            idx < Secp256k1Order::MODULUS,
            r#"The index for a "sub-share" must be less than the order of the `Secp256k1` curve."#
        );
        assert!(
            idx > U256::ZERO,
            r#"The index for a "sub-share" must not be equal to zero!"#
        );

        // Calculates the y-coordinate of the "sub-share".
        let gradient = self.gradient;
        let intercept = self.intercept;
        let y_coord = (const_residue!(gradient, Secp256k1Order)
            * const_residue!(idx, Secp256k1Order))
            + const_residue!(intercept, Secp256k1Order);

        SubShare {
            x: idx,
            y: y_coord.retrieve(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_share_interpolator_works() {
        // Take line, y = x + 1 (mod q).
        // The "secret share" is 1 i.e at index 0, x = 0 and y = 1.
        let secret_share = U256::ONE;
        let sub_share_0 = SubShare::new(U256::ZERO, secret_share);

        // The "sub-share" at index 1 is (1, 2) i.e when x = 1 and y = 2.
        let sub_share_1 = SubShare::new(U256::ONE, U256::from(2u8));

        // Initializes the "sub-share" interpolator for share splitting with "sub-shares" at index 0 and 1.
        let split_sub_share_interpolator = SubShareInterpolator::new(&sub_share_0, &sub_share_1);

        // The "sub-share" at index 2 is (2, 3),i.e when x = 2, y = 3.
        let sub_share_2 = SubShare::new(U256::from(2u8), U256::from(3u8));

        // Verify that the "sub-share" interpolator returns the right "sub-share" at index 2.
        assert_eq!(
            split_sub_share_interpolator
                .sub_share(U256::from(2u8))
                .as_tuple(),
            sub_share_2.as_tuple()
        );

        // Initializes the "sub-share" interpolator for share reconstruction with "sub-shares" at index 1 and 2.
        let reconstruct_sub_share_interpolator =
            SubShareInterpolator::new(&sub_share_1, &sub_share_2);

        // Verify that the "sub-share" interpolator returns the right "secret share".
        assert_eq!(&reconstruct_sub_share_interpolator.secret(), &secret_share);
    }
}
