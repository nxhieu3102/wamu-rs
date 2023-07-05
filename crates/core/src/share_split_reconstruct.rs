//! Share splitting and reconstruction implementation.
//!
//! Ref: <https://wamu.tech/specification#share-splitting-and-reconstruction>.

use crypto_bigint::{Encoding, U256};

use crate::identity_provider::IdentityProvider;
use crate::sub_share::{SigningShare, SubShare, SubShareInterpolator};

/// Given a "secret share" and an identity provider, returns "signing share" and "sub-share"
/// that can be used to reconstruct the "secret share" given the same identity provider.
///
/// Ref: <https://wamu.tech/specification#share-splitting>.
pub fn split(
    secret_share: U256,
    identity_provider: &impl IdentityProvider,
) -> (SigningShare, SubShare) {
    // Generates "signing share".
    let signing_share = SigningShare::new();

    // Computes "sub-share" a from "signing share".
    let (r, s) = identity_provider.sign_message_share(&signing_share.to_be_bytes());
    let sub_share_a = SubShare::new(U256::from_be_bytes(r), U256::from_be_bytes(s));

    // Initializes the "sub-share" interpolator.
    let sub_share_interpolator = SubShareInterpolator::new(
        // The "secret share" is the constant term, so x = 0.
        &SubShare::new(U256::ZERO, secret_share),
        &sub_share_a,
    );

    // Computes "sub-share" b.
    let sub_share_b = sub_share_interpolator.sub_share(U256::ONE);

    // Returns "signing share" and "sub-share" b.
    (signing_share, sub_share_b)
}

/// Returns "secret share" associated with "signing share", "sub-share" and identity provider.
///
/// Ref: <https://wamu.tech/specification#share-reconstruction>.
pub fn reconstruct(
    signing_share: &SigningShare,
    sub_share_b: &SubShare,
    identity_provider: &impl IdentityProvider,
) -> U256 {
    // Computes "sub-share" a from "signing share".
    let (r, s) = identity_provider.sign_message_share(&signing_share.to_be_bytes());
    let sub_share_a = SubShare::new(U256::from_be_bytes(r), U256::from_be_bytes(s));

    // Initializes the "sub-share" interpolator.
    let sub_share_interpolator = SubShareInterpolator::new(&sub_share_a, sub_share_b);

    // Returns "secret share".
    sub_share_interpolator.secret()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::test_utils::MockECDSAIdentityProvider;

    #[test]
    fn share_splitting_and_reconstruction_works() {
        // Generates secret share.
        let secret_share = crypto::random_mod();

        // Generates identity provider.
        let identity_provider = MockECDSAIdentityProvider::new();

        // Computes "signing share" and "sub-share".
        let (signing_share, sub_share_b) = split(secret_share, &identity_provider);

        // Reconstructs "secret share" from "signing share" and "sub-share".
        let reconstructed_secret_share =
            reconstruct(&signing_share, &sub_share_b, &identity_provider);

        // Verifies reconstructed "secret share".
        assert_eq!(&reconstructed_secret_share, &secret_share);
    }
}
