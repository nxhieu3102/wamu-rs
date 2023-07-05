//! Key generation implementation.
//!
//! Ref: <https://wamu.tech/specification#key-generation>.

use crate::crypto::{Signature, VerifyingKey};
use crate::errors::Error;
use crate::identity_provider::IdentityProvider;
use crate::wrappers;

/// Given random bytes and an identity provider, returns the verifying key and a signature of the random bytes.
pub fn initiate(
    random_bytes: &[u8],
    identity_provider: &impl IdentityProvider,
) -> (VerifyingKey, Signature) {
    wrappers::initiate_request_with_signature(random_bytes, identity_provider)
}

/// Given random bytes, a verifying key for the sending party, a signature of the random bytes and
/// a list of verifying keys for the other parties,
/// returns an ok result for a valid request or an appropriate error result for an invalid request.
pub fn verify(
    random_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature: &Signature,
    verified_parties: &[VerifyingKey],
) -> Result<(), Error> {
    wrappers::verify_request_with_signature(
        random_bytes,
        verifying_key,
        signature,
        verified_parties,
    )
}
